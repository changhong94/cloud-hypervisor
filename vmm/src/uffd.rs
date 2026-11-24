// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal userfaultfd bindings for demand-paged snapshot restore.
//!
//! Prefers `/dev/userfaultfd` (Linux 6.1+) over the `userfaultfd(2)` syscall
//! to create a fault descriptor, falling back to the syscall when the device
//! is unavailable. Then uses `UFFDIO_API` / `UFFDIO_REGISTER` / `UFFDIO_COPY`
//! ioctls to handle page faults from a background thread.
//!
//! Unlike an mmap(MAP_PRIVATE) overlay approach, UFFD does not replace the
//! original memory mapping, so it remains compatible with VFIO device
//! passthrough and shared-memory-backed guest RAM.

use std::fs::{File, OpenOptions};
use std::io::{self, Error, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::{fmt, thread};

use vm_migration::protocol::{MemoryRange, Request, Response, Status};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::migration::transport::SocketStream;
use crate::userfaultfd;

#[repr(C)]
struct UffdioApi {
    pub api: u64,
    pub features: u64,
    pub ioctls: u64,
}

#[repr(C)]
struct UffdioRegister {
    pub range_start: u64,
    pub range_len: u64,
    pub mode: u64,
    pub ioctls: u64,
}

#[repr(C)]
struct UffdioCopy {
    pub dst: u64,
    pub src: u64,
    pub len: u64,
    pub mode: u64,
    pub copy: i64,
}

#[repr(C)]
struct UffdioContinue {
    pub range_start: u64,
    pub range_len: u64,
    pub mode: u64,
    pub mapped: i64,
}

/// Flat representation of `struct uffd_msg` (32 bytes).
///
/// The kernel struct contains an 8-byte header followed by a 24-byte
/// union (`arg`). We only use the `arg.pagefault` variant, so the
/// union is flattened into its pagefault fields here. The trailing
/// 8 bytes (`arg.pagefault.feat` + padding) are unused.
#[repr(C)]
pub(crate) struct UffdMsg {
    pub event: u8,
    _reserved1: u8,
    _reserved2: u16,
    _reserved3: u32,
    pub pf_flags: u64,
    pub pf_address: u64,
    _pad: [u8; 8],
}

const _: () = assert!(size_of::<UffdMsg>() == 32);

/// Try to obtain a userfaultfd via /dev/userfaultfd (Linux 6.1+).
///
/// This bypasses the capability and sysctl checks that gate the syscall,
/// requiring only file permissions on the device node.
fn try_dev_userfaultfd() -> Result<OwnedFd, Error> {
    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/userfaultfd")?;
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: USERFAULTFD_IOC_NEW on a valid /dev/userfaultfd fd returns a new
    // userfaultfd file descriptor.
    let fd = unsafe {
        libc::ioctl(
            dev.as_raw_fd(),
            userfaultfd::USERFAULTFD_IOC_NEW as libc::Ioctl,
            flags,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the ioctl returned a valid fd above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a userfaultfd file descriptor and perform the API handshake.
///
/// Prefers `/dev/userfaultfd` (no capability/sysctl requirements, just file
/// permissions) and falls back to the `userfaultfd(2)` syscall.
pub(crate) fn create(required_features: u64) -> Result<OwnedFd, Error> {
    let fd = match try_dev_userfaultfd() {
        Ok(fd) => fd,
        Err(_) => {
            // SAFETY: `userfaultfd` syscall with O_CLOEXEC | O_NONBLOCK flags.
            let raw =
                unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if raw < 0 {
                return Err(Error::last_os_error());
            }
            // SAFETY: the syscall returned a valid fd above.
            unsafe { OwnedFd::from_raw_fd(raw as RawFd) }
        }
    };

    let mut api = UffdioApi {
        api: userfaultfd::UFFD_API,
        features: required_features,
        ioctls: 0,
    };
    // SAFETY: `api` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_API as libc::Ioctl,
            &mut api,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(fd)
}

/// Register a memory range for missing-page fault handling.
pub(crate) fn register(
    fd: BorrowedFd<'_>,
    addr: u64,
    len: u64,
    uffd_requires_minor_mode: bool,
) -> Result<u64, Error> {
    let mode = if uffd_requires_minor_mode {
        userfaultfd::UFFDIO_REGISTER_MODE_MISSING | userfaultfd::UFFDIO_REGISTER_MODE_MINOR
    } else {
        userfaultfd::UFFDIO_REGISTER_MODE_MISSING
    };

    let mut reg = UffdioRegister {
        range_start: addr,
        range_len: len,
        mode,
        ioctls: 0,
    };
    // SAFETY: `reg` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_REGISTER as libc::Ioctl,
            &mut reg,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(reg.ioctls)
}

/// Resolve a page fault by copying data into the faulted address.
pub(crate) fn copy(fd: BorrowedFd<'_>, dst: u64, src: *const u8, len: u64) -> Result<(), Error> {
    let mut cp = UffdioCopy {
        dst,
        src: src as u64,
        len,
        mode: 0,
        copy: 0,
    };
    loop {
        // SAFETY: `cp` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_COPY as libc::Ioctl,
                &mut cp,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

/// Resolves a minor page fault by installing PTEs for a range.
pub(crate) fn uffd_continue(fd: BorrowedFd<'_>, dst: u64, len: u64) -> Result<(), Error> {
    let mut cont = UffdioContinue {
        range_start: dst,
        range_len: len,
        mode: 0,
        mapped: 0,
    };
    loop {
        // SAFETY: `cont` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_CONTINUE as libc::Ioctl,
                &mut cont,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioPoison {
    range: UffdioRange,
    mode: u64,
    updated: i64,
}

/// A guest memory range registered with userfaultfd, plus where its bytes
/// live for the data source.
pub(crate) struct UffdRange {
    pub host_addr: u64,
    pub length: u64,
    pub source_offset: u64,
    pub page_size: u64,
}

impl UffdRange {
    pub(crate) fn num_pages(&self) -> u64 {
        self.length.div_ceil(self.page_size)
    }

    pub(crate) fn page_addr(&self, page_idx: u64) -> u64 {
        self.host_addr + page_idx * self.page_size
    }

    pub(crate) fn page_source_offset(&self, page_idx: u64) -> u64 {
        self.source_offset + page_idx * self.page_size
    }

    pub(crate) fn page_index_of(&self, addr: u64) -> Option<u64> {
        let page_addr = addr & !(self.page_size - 1);
        (page_addr >= self.host_addr && page_addr < self.host_addr + self.length)
            .then(|| (page_addr - self.host_addr) / self.page_size)
    }
}

/// A userfaultfd and the ranges registered in it, at the addresses they are
/// mapped at in the process owning it.
pub(crate) struct Uffd {
    fd: OwnedFd,
    ranges: Box<[UffdRange]>,
}

impl Uffd {
    pub(crate) fn new(fd: OwnedFd, ranges: Box<[UffdRange]>) -> Result<Self, Error> {
        // SAFETY: `F_GETFL` takes no argument.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: `F_SETFL` takes an integer argument, no pointer.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::last_os_error());
        }
        Ok(Self { fd, ranges })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn ranges(&self) -> &[UffdRange] {
        &self.ranges
    }

    /// Returns the `(range_idx, page_idx)` containing `addr`.
    pub(crate) fn locate(&self, addr: u64) -> Option<(usize, u64)> {
        self.ranges
            .iter()
            .enumerate()
            .find_map(|(range_idx, range)| {
                range
                    .page_index_of(addr)
                    .map(|page_idx| (range_idx, page_idx))
            })
    }
}

/// Provider of guest-memory page contents for a UFFD handler.
pub(crate) trait UffdMemorySource: Send {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error>;

    fn requires_uffd_minor_mode(&self) -> bool;
}

/// Source that reads pages from a local snapshot file.
pub(crate) struct FileUffdMemorySource {
    file: File,
    buf: Vec<u8>,
}

impl FileUffdMemorySource {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            buf: Vec::new(),
        }
    }
}

impl UffdMemorySource for FileUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error> {
        let page_size = range.page_size as usize;
        let page_addr = range.page_addr(page_idx);
        let file_pos = range.page_source_offset(page_idx);

        if self.buf.len() < page_size {
            self.buf.resize(page_size, 0);
        }
        self.file
            .read_exact_at(&mut self.buf[..page_size], file_pos)?;

        match copy(uffd_fd, page_addr, self.buf.as_ptr(), range.page_size) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Installed concurrently. Wake any blocked threads.
                if let Err(e) = wake(uffd_fd, page_addr, range.page_size) {
                    log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn requires_uffd_minor_mode(&self) -> bool {
        false
    }
}

/// Private endpoint prepared by the sandboxer outside VMM seccomp. Only the
/// authenticated manifest selected by the host is accessible through it.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestPageDescriptor {
    socket: String,
    logical_bytes: u64,
    #[serde(default)]
    incremental: bool,
    #[serde(default)]
    baseline: Option<serde_json::Value>,
    #[serde(default)]
    read_window_bytes: u64,
    #[serde(default)]
    local_file_plan: bool,
}
pub(crate) struct ManifestUffdMemorySource {
    local: Option<LocalSnapshotPages>,
    read_window_bytes: u64,
    cache_offset: u64,
    cached_windows: std::collections::VecDeque<(u64, Vec<u8>)>,
    pub(crate) zero_ranges: Vec<(u64, u64)>,
    stream: std::os::unix::net::UnixStream,
    buf: Vec<u8>,
}
impl ManifestUffdMemorySource {
    pub(crate) fn open(path: &std::path::Path, expected_size: u64) -> io::Result<Self> {
        let d: ManifestPageDescriptor =
            serde_json::from_reader(std::io::BufReader::new(File::open(path)?))?;
        if d.read_window_bytes != 0
            && (!(4096..=65536).contains(&d.read_window_bytes) || d.read_window_bytes % 4096 != 0)
        {
            return Err(io::Error::other("Invalid Manifest read window"));
        }
        if d.incremental && d.baseline.is_none() {
            return Err(io::Error::other("Missing incremental memory baseline"));
        }
        if d.logical_bytes != expected_size {
            return Err(io::Error::other("Manifest RAM size mismatch"));
        }
        let mut stream = std::os::unix::net::UnixStream::connect(d.socket)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(35)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(35)))?;
        let mut size = [0; 8];
        stream.read_exact(&mut size)?;
        if u64::from_le_bytes(size) != expected_size {
            return Err(io::Error::other("Manifest source length mismatch"));
        }
        stream.read_exact(&mut size)?;
        let count = u64::from_le_bytes(size);
        if count > 1 << 20 {
            return Err(io::Error::other("Too many Manifest extents"));
        }
        let mut zero_ranges = Vec::new();
        let mut previous_end = 0;
        // Bound read-ahead to the table. The following SCM_RIGHTS byte must
        // remain unread until recvmsg receives its descriptor.
        let mut records = std::io::BufReader::with_capacity(65536, (&mut stream).take(count * 16));
        for _ in 0..count {
            records.read_exact(&mut size)?;
            let start = u64::from_le_bytes(size);
            records.read_exact(&mut size)?;
            let len = u64::from_le_bytes(size);
            if start < previous_end
                || start > expected_size
                || len > expected_size - start
                || len == 0
            {
                return Err(io::Error::other("Invalid Manifest extent"));
            }
            previous_end = start + len;
            zero_ranges.push((start, len));
        }
        drop(records);
        let local = if d.local_file_plan {
            Some(LocalSnapshotPages::receive(
                &mut stream,
                expected_size,
                &zero_ranges,
            )?)
        } else {
            None
        };
        Ok(Self {
            local,
            stream,
            buf: Vec::new(),
            zero_ranges,
            read_window_bytes: d.read_window_bytes,
            cache_offset: 0,
            cached_windows: std::collections::VecDeque::new(),
        })
    }
    /// Map authenticated immutable local extents without copying RAM.
    /// Caller must supply fresh private anonymous windows, before any consumer
    /// runs. Zero extents retain their original zero anonymous mapping.
    /// All alignment checks precede the first MAP_FIXED; mapping errors abort
    /// restore rather than falling back over a partially replaced address space.
    pub(crate) unsafe fn map_local_cow(
        &self,
        windows: &[(u64, u64, u64, i32)],
    ) -> io::Result<Option<Vec<(u64, u64)>>> {
        let Some(local) = &self.local else {
            return Ok(None);
        };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        if local
            .extents
            .iter()
            .any(|&(off, len, _, _)| !off.is_multiple_of(page) || !len.is_multiple_of(page))
        {
            return Ok(None);
        }
        for &(off, len, host, _) in windows {
            if !off.is_multiple_of(page)
                || !len.is_multiple_of(page)
                || !host.is_multiple_of(page)
                || off > local.size
                || len > local.size - off
            {
                return Err(io::Error::other("Invalid private mapping window"));
            }
        }
        // A raw immutable ancestor is often split into thousands of selected
        // ranges by newer pages. Map that ancestor once, then replace every
        // non-ancestor byte (including explicit zeroes) before exposing RAM.
        // Unaligned extents retain the original UFFD path: a seeded file PTE
        // must never hide a missing-page fault that still needs the pager.
        let seed = self.local_cow_seed(windows, page)?;
        let mut mappings = 0usize;
        if let Some((index, physical_base)) = seed {
            for &(off, len, host, reserve) in windows {
                // SAFETY: validated windows are exclusively owned, untouched
                // guest mappings; seed selection checked the complete file span.
                let mapped = unsafe {
                    libc::mmap(
                        host as *mut libc::c_void,
                        len as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_FIXED | reserve,
                        local.files[index].as_raw_fd(),
                        (physical_base + off) as libc::off_t,
                    )
                };
                if mapped == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                mappings += 1;
            }
        }
        for &(off, len, host, reserve) in windows {
            let end = off + len;
            let first = local
                .extents
                .partition_point(|&(start, length, _, _)| start + length <= off);
            for &(start, length, physical, index) in &local.extents[first..] {
                if start >= end {
                    break;
                }
                if !physical.is_multiple_of(page) || seed.is_some_and(|(file, _)| file == index) {
                    continue;
                }
                let lo = off.max(start);
                let hi = end.min(start + length);
                let mapped = unsafe {
                    libc::mmap(
                        (host + lo - off) as *mut libc::c_void,
                        (hi - lo) as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_FIXED | reserve,
                        local.files[index].as_raw_fd(),
                        (physical + lo - start) as libc::off_t,
                    )
                };
                if mapped == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                mappings += 1;
            }
            if seed.is_some() {
                for &(start, length) in &self.zero_ranges {
                    let lo = off.max(start);
                    let hi = end.min(start + length);
                    if lo >= hi {
                        continue;
                    }
                    // SAFETY: replace the seed's stale bytes with fresh zero
                    // anonymous pages, still before KVM/device registration.
                    let mapped = unsafe {
                        libc::mmap(
                            (host + lo - off) as *mut libc::c_void,
                            (hi - lo) as usize,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED | reserve,
                            -1,
                            0,
                        )
                    };
                    if mapped == libc::MAP_FAILED {
                        return Err(io::Error::last_os_error());
                    }
                    mappings += 1;
                }
            }
        }
        eprintln!(
            "LOCAL_COW_PLAN extents={} seed={} mappings={mappings}",
            local.extents.len(),
            seed.is_some()
        );
        Ok(Some(
            local
                .extents
                .iter()
                .filter(|&&(_, _, physical, _)| !physical.is_multiple_of(page))
                .map(|&(off, len, _, _)| (off, len))
                .collect(),
        ))
    }
    // Only affine, page-aligned raw ancestors can seed the address space.
    // Selection is an optimization; all ownership/coverage checks in receive()
    // and all alignment checks above remain mandatory.
    fn local_cow_seed(
        &self,
        windows: &[(u64, u64, u64, i32)],
        page: u64,
    ) -> io::Result<Option<(usize, u64)>> {
        let Some(local) = &self.local else {
            return Ok(None);
        };
        if local.extents.iter().any(|e| !e.2.is_multiple_of(page))
            || self
                .zero_ranges
                .iter()
                .any(|&(o, n)| !o.is_multiple_of(page) || !n.is_multiple_of(page))
        {
            return Ok(None);
        }
        let mut best = None;
        let mut saved = 0usize;
        for (index, file) in local.files.iter().enumerate() {
            let mut delta = None;
            let mut count = 0usize;
            let mut affine = true;
            for &(off, _, physical, file_index) in &local.extents {
                if file_index != index {
                    continue;
                }
                let Some(current) = physical.checked_sub(off) else {
                    affine = false;
                    break;
                };
                if delta.is_some_and(|previous| previous != current) {
                    affine = false;
                    break;
                }
                delta = Some(current);
                count += 1;
            }
            let Some(delta) = delta else {
                continue;
            };
            if !affine || !delta.is_multiple_of(page) {
                continue;
            }
            let size = file.metadata()?.len();
            if windows.iter().any(|&(off, len, _, _)| {
                delta
                    .checked_add(off)
                    .and_then(|p| p.checked_add(len))
                    .is_none_or(|end| end > size)
            }) {
                continue;
            }
            let cost = windows.len() + self.zero_ranges.len();
            if count > cost && count - cost > saved {
                best = Some((index, delta));
                saved = count - cost;
            }
        }
        Ok(best)
    }

    pub(crate) fn shutdown_fd(&self) -> io::Result<OwnedFd> {
        Ok(self.stream.try_clone()?.into())
    }
}
impl Drop for ManifestUffdMemorySource {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
impl ManifestUffdMemorySource {
    fn retain_window(&mut self) {
        if !self.buf.is_empty() && self.buf.len() as u64 <= self.read_window_bytes {
            // Including the current window, at most 32 windows (2 MiB with the maximum window size).
            if self.cached_windows.len() == 31 {
                self.cached_windows.pop_front();
            }
            self.cached_windows
                .push_back((self.cache_offset, std::mem::take(&mut self.buf)));
        } else {
            self.buf.clear();
        }
    }
    // Cache only immutable source bytes, never guest RAM. UFFDIO_COPY still
    // installs just the faulted page and cannot overwrite an already live page.
    fn read_page(&mut self, range: &UffdRange, page_idx: u64) -> io::Result<&[u8]> {
        use std::io::Write;
        if range.page_size > 2 * 1024 * 1024 || page_idx >= range.num_pages() {
            return Err(io::Error::other("Unsupported Manifest page request"));
        }
        let offset = range.page_source_offset(page_idx);
        if let Some(local) = &self.local {
            self.buf.resize(range.page_size as usize, 0);
            local.read(&mut self.buf, offset)?;
            return Ok(&self.buf);
        }
        if offset >= self.cache_offset {
            let start = offset - self.cache_offset;
            if start <= self.buf.len() as u64 && range.page_size <= self.buf.len() as u64 - start {
                return Ok(&self.buf[start as usize..(start + range.page_size) as usize]);
            }
        }
        if let Some(index) = self.cached_windows.iter().position(|(start, bytes)| {
            offset >= *start
                && offset - *start <= bytes.len() as u64
                && range.page_size <= bytes.len() as u64 - (offset - *start)
        }) {
            let (start, bytes) = self.cached_windows.remove(index).unwrap();
            self.retain_window();
            self.cache_offset = start;
            self.buf = bytes;
            let inner = (offset - start) as usize;
            return Ok(&self.buf[inner..inner + range.page_size as usize]);
        }
        self.retain_window();
        let window = range.page_size == 4096 && self.read_window_bytes >= range.page_size;
        let count = if window {
            self.read_window_bytes
                .min(range.length - page_idx * range.page_size)
        } else {
            range.page_size
        };
        let mut request = [0; 16];
        request[..8].copy_from_slice(&offset.to_le_bytes());
        request[8..].copy_from_slice(&(count | if window { 1u64 << 63 } else { 0 }).to_le_bytes());
        self.buf.clear(); // An I/O error must never leave a valid cache entry.
        self.stream.write_all(&request)?;
        let returned = if window {
            let mut length = [0; 8];
            self.stream.read_exact(&mut length)?;
            u64::from_le_bytes(length)
        } else {
            count
        };
        if returned < range.page_size || returned > count || returned % range.page_size != 0 {
            return Err(io::Error::other("Invalid Manifest returned window"));
        }
        let mut data = vec![0; returned as usize];
        self.stream.read_exact(&mut data)?;
        self.buf = data;
        self.cache_offset = offset;
        Ok(&self.buf[..range.page_size as usize])
    }
}

// The fd pins the immutable plaintext snapshot inode. Packed offsets need not
// be mmap-aligned: pread supplies only the faulted page, UFFD installs private
// RAM, and writes remain ordinary guest CoW writes. No RAM fd crosses processes.
struct LocalSnapshotPages {
    files: Vec<File>,
    size: u64,
    extents: Vec<(u64, u64, u64, usize)>,
}
impl LocalSnapshotPages {
    fn receive(
        stream: &mut std::os::unix::net::UnixStream,
        size: u64,
        zeros: &[(u64, u64)],
    ) -> io::Result<Self> {
        let mut marker = [0];
        let (n, file) = stream.recv_with_fd(&mut marker)?;
        let file = file.ok_or_else(|| io::Error::other("Missing local snapshot fd"))?;
        if n != 1 || (marker != [1] && marker != [2]) {
            return Err(io::Error::other("Invalid local snapshot handoff"));
        }
        let multiple = marker == [2];
        let mut files = vec![file];
        if multiple {
            let mut count = [0; 8];
            stream.read_exact(&mut count)?;
            let count = u64::from_le_bytes(count);
            if !(2..=64).contains(&count) {
                return Err(io::Error::other("Invalid local snapshot file count"));
            }
            for _ in 1..count {
                let (n, file) = stream.recv_with_fd(&mut marker)?;
                let file = file.ok_or_else(|| io::Error::other("Missing local snapshot fd"))?;
                if n != 1 || marker != [1] {
                    return Err(io::Error::other("Invalid local snapshot file marker"));
                }
                files.push(file);
            }
        }
        let mut sizes = Vec::new();
        for file in &files {
            // SAFETY: file owns a live descriptor; fcntl only inspects/sets fd flags.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: same owned descriptor; no other owner can close/reuse it here.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let info = file.metadata()?;
            if flags & libc::O_ACCMODE != libc::O_RDONLY || !info.is_file() {
                return Err(io::Error::other(
                    "Local snapshot fd must be a read-only regular file",
                ));
            }
            sizes.push(info.len());
        }
        let mut word = [0; 8];
        stream.read_exact(&mut word)?;
        let count = u64::from_le_bytes(word);
        if count == 0 || count > 1 << 20 {
            return Err(io::Error::other("Invalid local snapshot extent count"));
        }
        let mut extents = Vec::new();
        let mut end = 0;
        let width = if multiple { 32 } else { 24 };
        let mut records = std::io::BufReader::with_capacity(65536, stream.take(count * width));
        for _ in 0..count {
            let mut wire = [0; 24];
            records.read_exact(&mut wire)?;
            let start = u64::from_le_bytes(wire[..8].try_into().unwrap());
            let length = u64::from_le_bytes(wire[8..16].try_into().unwrap());
            let physical = u64::from_le_bytes(wire[16..].try_into().unwrap());
            let index = if multiple {
                records.read_exact(&mut word)?;
                u64::from_le_bytes(word)
            } else {
                0
            };
            if index >= files.len() as u64 {
                return Err(io::Error::other("Invalid local snapshot file index"));
            }
            let file_size = sizes[index as usize];
            if start < end
                || start > size
                || length == 0
                || length > size - start
                || physical > file_size
                || length > file_size - physical
            {
                return Err(io::Error::other("Invalid local snapshot extent"));
            }
            end = start + length;
            extents.push((start, length, physical, index as usize));
        }
        let mut coverage: Vec<_> = extents
            .iter()
            .map(|(o, n, _, _)| (*o, *n))
            .chain(zeros.iter().copied())
            .collect();
        coverage.sort_unstable();
        let mut end = 0;
        for (start, length) in coverage {
            if start != end {
                return Err(io::Error::other(
                    "Local snapshot coverage overlaps or has gaps",
                ));
            }
            end = start + length;
        }
        if end != size {
            return Err(io::Error::other("Incomplete local snapshot coverage"));
        }
        Ok(Self {
            files,
            size,
            extents,
        })
    }
    fn read(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        if offset > self.size || buffer.len() as u64 > self.size - offset {
            return Err(io::Error::other("Local snapshot read outside RAM"));
        }
        buffer.fill(0);
        let end = offset + buffer.len() as u64;
        let first = self
            .extents
            .partition_point(|(start, length, _, _)| start + length <= offset);
        for &(start, length, physical, index) in &self.extents[first..] {
            if start >= end {
                break;
            }
            let lo = start.max(offset);
            let hi = (start + length).min(end);
            self.files[index].read_exact_at(
                &mut buffer[(lo - offset) as usize..(hi - offset) as usize],
                physical + lo - start,
            )?;
        }
        Ok(())
    }
}
impl UffdMemorySource for ManifestUffdMemorySource {
    fn resolve(&mut self, fd: BorrowedFd<'_>, range: &UffdRange, page_idx: u64) -> io::Result<()> {
        let data = self.read_page(range, page_idx)?;
        let addr = range.page_addr(page_idx);
        match copy(fd, addr, data.as_ptr(), range.page_size) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => wake(fd, addr, range.page_size),
            Err(e) => Err(e),
        }
    }
    fn requires_uffd_minor_mode(&self) -> bool {
        false
    }
}

/// Memory source that provides pages content over a socket.
pub(crate) struct SocketUffdMemorySource {
    stream: SocketStream,
    shared_backing: bool,
    buf: Vec<u8>,
}

impl SocketUffdMemorySource {
    pub(crate) fn new(stream: SocketStream, shared_backing: bool) -> Self {
        Self {
            stream,
            shared_backing,
            buf: Vec::new(),
        }
    }

    /// Returns the length of the inline page payload the peer is about to send
    /// (0 when the page was written directly into shared memory).
    fn request_page(&mut self, gpa: u64, len: u64) -> Result<u64, io::Error> {
        Request::page_fault()
            .write_to(&mut self.stream)
            .map_err(io_other)?;
        MemoryRange { gpa, length: len }
            .write_to(&mut self.stream)
            .map_err(io_other)?;

        let resp = Response::read_from(&mut self.stream).map_err(io_other)?;
        match resp.status() {
            Status::Ok => Ok(resp.length()),
            s => Err(io::Error::other(format!(
                "peer returned {s:?} for PageFault at gpa={gpa:#x} len={len}",
            ))),
        }
    }
}

impl UffdMemorySource for SocketUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error> {
        let page_size = range.page_size;
        let page_addr = range.page_addr(page_idx);
        let page_gpa = range.page_source_offset(page_idx);

        let resp_len = self.request_page(page_gpa, page_size)?;

        if self.shared_backing {
            if resp_len != 0 {
                return Err(io::Error::other(format!(
                    "shared-backing PageFault response carried {resp_len} unexpected bytes",
                )));
            }
            match uffd_continue(uffd_fd, page_addr, page_size) {
                Ok(()) => Ok(()),
                // This is fine, someone mapped the page before us.
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            if resp_len != page_size {
                return Err(io::Error::other(format!(
                    "inline PageFault response length {resp_len} != page size {page_size}",
                )));
            }
            let len = page_size as usize;
            if self.buf.len() < len {
                self.buf.resize(len, 0);
            }
            self.stream.read_exact(&mut self.buf[..len])?;
            match copy(uffd_fd, page_addr, self.buf.as_ptr(), page_size) {
                Ok(()) => Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    fn requires_uffd_minor_mode(&self) -> bool {
        self.shared_backing
    }
}

impl Drop for SocketUffdMemorySource {
    fn drop(&mut self) {
        // SAFETY: the fd is valid for the duration of this borrow.
        unsafe { libc::shutdown(self.stream.as_fd().as_raw_fd(), libc::SHUT_RDWR) };
    }
}

fn io_other<E: fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Mark a missing page so that an access to it fails instead of resolving a
/// zero page.
pub(crate) fn poison(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut poison = UffdioPoison {
        range: UffdioRange { start: addr, len },
        mode: 0,
        updated: 0,
    };
    loop {
        // SAFETY: `poison` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_POISON as libc::Ioctl,
                &mut poison,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

/// Wake threads waiting on a fault in the given range without copying data.
///
/// Needed after UFFDIO_COPY or UFFDIO_CONTINUE returns EEXIST: the page was
/// already resolved by a concurrent fault, but any additional threads blocked
/// on that page may not have been woken.
pub(crate) fn wake(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut range = UffdioRange { start: addr, len };
    // SAFETY: `range` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_WAKE as libc::Ioctl,
            &mut range,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Returns whether the page at `addr` in this process is present. For a
/// shared file mapping, this is whether the file holds the page, even if
/// it is not mapped at `addr`.
pub(crate) fn page_present(addr: u64) -> Result<bool, Error> {
    let mut vec = 0u8;
    // SAFETY: mincore() writes one byte for the single page at `addr`.
    let ret = unsafe { libc::mincore(addr as *mut libc::c_void, 1, &mut vec) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(vec & 1 != 0)
}

#[cfg(test)]
mod manifest_tests {
    use std::io::Write;
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn local_seed_overlays_data_and_zeroes_without_leaking_ancestor_bytes() {
        let ancestor = tempfile::NamedTempFile::new().unwrap();
        ancestor
            .as_file()
            .write_all_at(&vec![7; 8 * 4096], 0)
            .unwrap();
        let delta = tempfile::NamedTempFile::new().unwrap();
        delta.as_file().write_all_at(&vec![9; 2 * 4096], 0).unwrap();
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut source = ManifestUffdMemorySource {
            local: Some(LocalSnapshotPages {
                files: vec![
                    File::open(ancestor.path()).unwrap(),
                    File::open(delta.path()).unwrap(),
                ],
                size: 8 * 4096,
                extents: vec![
                    (0, 4096, 0, 0),
                    (4096, 4096, 0, 1),
                    (8192, 4096, 8192, 0),
                    (12288, 4096, 4096, 1),
                    (16384, 4096, 16384, 0),
                    (24576, 4096, 24576, 0),
                ],
            }),
            stream,
            buf: Vec::new(),
            zero_ranges: vec![(20480, 4096), (28672, 4096)],
            read_window_bytes: 65536,
            cache_offset: 0,
            cached_windows: Default::default(),
        };
        let size = 8 * 4096;
        // SAFETY: both anonymous allocations are exclusively owned by this test;
        // all reads/writes stay inside their bounds and both are unmapped below.
        unsafe {
            let allocate = || {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            let a = allocate();
            let b = allocate();
            assert_ne!(a, libc::MAP_FAILED);
            assert_ne!(b, libc::MAP_FAILED);
            let windows = [(0, size as u64, a as u64, 0)];
            assert_eq!(source.local_cow_seed(&windows, 4096).unwrap(), Some((0, 0)));
            assert_eq!(source.map_local_cow(&windows).unwrap(), Some(vec![]));
            assert_eq!(
                source
                    .map_local_cow(&[(0, size as u64, b as u64, 0)])
                    .unwrap(),
                Some(vec![])
            );
            let first = std::slice::from_raw_parts_mut(a as *mut u8, size);
            let second = std::slice::from_raw_parts_mut(b as *mut u8, size);
            for (page, value) in [7, 9, 7, 9, 7, 0, 7, 0].into_iter().enumerate() {
                assert!(
                    first[page * 4096..(page + 1) * 4096]
                        .iter()
                        .all(|&x| x == value)
                );
                assert!(
                    second[page * 4096..(page + 1) * 4096]
                        .iter()
                        .all(|&x| x == value)
                );
            }
            first[0] = 1;
            first[4096] = 2;
            first[20480] = 3;
            assert_eq!((second[0], second[4096], second[20480]), (7, 9, 0));
            second[8192] = 4;
            assert_eq!(first[8192], 7);
            let mut byte = [0];
            ancestor.as_file().read_exact_at(&mut byte, 0).unwrap();
            assert_eq!(byte, [7]);
            delta.as_file().read_exact_at(&mut byte, 0).unwrap();
            assert_eq!(byte, [9]);
            assert_eq!(libc::munmap(a, size), 0);
            assert_eq!(libc::munmap(b, size), 0);
        }
        // A partial pager restore must not seed pages that need UFFD faults.
        source.local.as_mut().unwrap().extents[1].2 = 1;
        assert_eq!(
            source
                .local_cow_seed(&[(0, size as u64, 0, 0)], 4096)
                .unwrap(),
            None
        );
        source.local.as_mut().unwrap().extents[1].2 = 0;
        ancestor.as_file().set_len(7 * 4096).unwrap();
        assert_eq!(
            source
                .local_cow_seed(&[(0, size as u64, 0, 0)], 4096)
                .unwrap(),
            None
        );
    }

    #[test]
    fn local_manifest_cow_preserves_source_and_sibling() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().set_len(8192).unwrap();
        tmp.as_file().write_all_at(&[7; 4096], 0).unwrap();
        tmp.as_file().write_all_at(&[9; 4096], 4096).unwrap();
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut source = ManifestUffdMemorySource {
            local: Some(LocalSnapshotPages {
                files: vec![File::open(tmp.path()).unwrap()],
                size: 12288,
                extents: vec![(0, 4096, 0, 0), (8192, 4096, 4096, 0)],
            }),
            stream,
            buf: Vec::new(),
            zero_ranges: vec![(4096, 4096)],
            read_window_bytes: 65536,
            cache_offset: 0,
            cached_windows: Default::default(),
        };
        let allocate = || unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                12288,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let a = allocate();
        let b = allocate();
        assert_ne!(a, libc::MAP_FAILED);
        assert_ne!(b, libc::MAP_FAILED);
        unsafe {
            assert_eq!(
                source.map_local_cow(&[(0, 12288, a as u64, 0)]).unwrap(),
                Some(vec![])
            );
            assert_eq!(
                source.map_local_cow(&[(0, 12288, b as u64, 0)]).unwrap(),
                Some(vec![])
            );
            let first = std::slice::from_raw_parts_mut(a as *mut u8, 12288);
            let second = std::slice::from_raw_parts_mut(b as *mut u8, 12288);
            assert_eq!(first[0], 7);
            assert_eq!(first[4096], 0);
            assert_eq!(first[8192], 9);
            first[0] = 42;
            second[8192] = 17;
            assert_eq!(second[0], 7);
            assert_eq!(first[8192], 9);
            let mut byte = [0];
            tmp.as_file().read_exact_at(&mut byte, 0).unwrap();
            assert_eq!(byte, [7]);
            // Unaligned sources must fall back before changing any mapping.
            source.local.as_mut().unwrap().extents[0].2 = 1;
            assert_eq!(
                source.map_local_cow(&[(0, 12288, a as u64, 0)]).unwrap(),
                Some(vec![(0, 4096)])
            );
            assert_eq!(first[0], 42);
            assert_eq!(libc::munmap(a, 12288), 0);
            assert_eq!(libc::munmap(b, 12288), 0);
        }
    }

    #[test]
    fn manifest_local_file_handoff_checks_coverage_and_reads_unaligned_bytes() {
        for (physical, zero_start, valid) in [
            (3_u64, 4096_u64, true),
            (8192, 4096, false),
            (3, 2048, false),
        ] {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all_at(&vec![0x67; 8192], 0).unwrap();
            let file = File::open(tmp.path()).unwrap();
            let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            let sender = thread::spawn(move || {
                assert_eq!(
                    server.send_with_fd(&[1u8][..], file.as_raw_fd()).unwrap(),
                    1
                );
                for n in [1_u64, 0, 4096, physical] {
                    server.write_all(&n.to_le_bytes()).unwrap();
                }
            });
            let source = LocalSnapshotPages::receive(&mut client, 8192, &[(zero_start, 4096)]);
            sender.join().unwrap();
            assert_eq!(source.is_ok(), valid);
            if let Ok(source) = source {
                let mut bytes = vec![0xff; 8192];
                source.read(&mut bytes, 0).unwrap();
                assert!(bytes[..4096].iter().all(|b| *b == 0x67));
                assert!(bytes[4096..].iter().all(|b| *b == 0));
                assert!(source.read(&mut bytes, 1).is_err());
            }
        }
    }

    #[test]
    fn manifest_buffering_preserves_rights_and_next_message() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("pages");
        let descriptor = dir.path().join("descriptor");
        let data = tempfile::NamedTempFile::new().unwrap();
        data.as_file().write_all_at(&[7; 4096], 0).unwrap();
        let fd = File::open(data.path()).unwrap();
        std::fs::write(
            &descriptor,
            serde_json::to_vec(
                &serde_json::json!({"socket":socket,"logical_bytes":8192,"local_file_plan":true}),
            )
            .unwrap(),
        )
        .unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for value in [8192_u64, 1, 4096, 4096] {
                stream.write_all(&value.to_le_bytes()).unwrap();
            }
            stream.send_with_fd(&[1_u8][..], fd.as_raw_fd()).unwrap();
            let mut bytes: Vec<u8> = [1_u64, 0, 4096, 0]
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect();
            bytes.push(0x42);
            stream.write_all(&bytes).unwrap();
        });
        let mut source = ManifestUffdMemorySource::open(&descriptor, 8192).unwrap();
        let mut byte = [0];
        source.stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x42]);
        let mut contents = [0; 4096];
        source
            .local
            .as_ref()
            .unwrap()
            .read(&mut contents, 0)
            .unwrap();
        assert_eq!(contents, [7; 4096]);
        server.join().unwrap();
    }

    #[test]
    fn manifest_multi_file_handoff_validates_file_indices_and_permissions() {
        for (index, writable, valid) in [(1_u64, false, true), (2, false, false), (1, true, false)]
        {
            let first = tempfile::NamedTempFile::new().unwrap();
            let second = tempfile::NamedTempFile::new().unwrap();
            first.as_file().write_all_at(&vec![0x67; 8192], 0).unwrap();
            second.as_file().write_all_at(&vec![0x89; 8192], 0).unwrap();
            let a = File::open(first.path()).unwrap();
            let b = OpenOptions::new()
                .read(true)
                .write(writable)
                .open(second.path())
                .unwrap();
            let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            let sender = thread::spawn(move || {
                server.send_with_fd(&[2u8][..], a.as_raw_fd()).unwrap();
                server.write_all(&2_u64.to_le_bytes()).unwrap();
                server.send_with_fd(&[1u8][..], b.as_raw_fd()).unwrap();
                for value in [2_u64, 0, 4096, 3, 0, 4096, 4096, 7, index] {
                    server.write_all(&value.to_le_bytes()).unwrap();
                }
            });
            let source = LocalSnapshotPages::receive(&mut client, 12288, &[(8192, 4096)]);
            sender.join().unwrap();
            assert_eq!(source.is_ok(), valid);
            if let Ok(source) = source {
                let mut bytes = vec![0xff; 12288];
                source.read(&mut bytes, 0).unwrap();
                assert!(bytes[..4096].iter().all(|b| *b == 0x67));
                assert!(bytes[4096..8192].iter().all(|b| *b == 0x89));
                assert!(bytes[8192..].iter().all(|b| *b == 0));
            }
        }
    }

    #[test]
    fn manifest_source_checks_size_and_sparse_bounds() {
        for (size, offset, length, valid) in [
            (8192_u64, 4096_u64, 4096_u64, true),
            (4096, 0, 4096, false),
            (8192, 8192, 4096, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("pages");
            let descriptor = dir.path().join("descriptor");
            std::fs::write(
                &descriptor,
                serde_json::to_vec(&serde_json::json!({
                    "socket":socket,"logical_bytes":8192
                }))
                .unwrap(),
            )
            .unwrap();
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let bytes: Vec<u8> = [size, 1, offset, length]
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect();
                let _ = stream.write_all(&bytes);
                let mut b = [0];
                let _ = stream.read(&mut b);
            });
            let result = ManifestUffdMemorySource::open(&descriptor, 8192);
            assert_eq!(result.is_ok(), valid);
            drop(result);
            server.join().unwrap();
        }
    }
    #[test]
    fn manifest_window_caches_source_and_clips_to_range() {
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            for (off, count) in [(0u64, 8192u64), (8192, 4096)] {
                let mut req = [0; 16];
                server.read_exact(&mut req).unwrap();
                assert_eq!(u64::from_le_bytes(req[..8].try_into().unwrap()), off);
                assert_eq!(
                    u64::from_le_bytes(req[8..].try_into().unwrap()),
                    count | 1u64 << 63
                );
                server.write_all(&count.to_le_bytes()).unwrap();
                server
                    .write_all(&vec![if off == 0 { 7 } else { 9 }; count as usize])
                    .unwrap();
            }
        });
        let mut source = ManifestUffdMemorySource {
            local: None,
            zero_ranges: Vec::new(),
            stream: client,
            buf: Vec::new(),
            cache_offset: 0,
            cached_windows: std::collections::VecDeque::new(),
            read_window_bytes: 8192,
        };
        let range = UffdRange {
            host_addr: 0,
            length: 12288,
            source_offset: 0,
            page_size: 4096,
        };
        assert_eq!(source.read_page(&range, 0).unwrap(), &[7; 4096]);
        assert_eq!(source.read_page(&range, 1).unwrap(), &[7; 4096]);
        assert_eq!(source.read_page(&range, 2).unwrap(), &[9; 4096]);
        assert_eq!(source.read_page(&range, 1).unwrap(), &[7; 4096]);
        assert!(source.read_page(&range, 3).is_err());
        worker.join().unwrap();
    }
}
