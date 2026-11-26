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

use vm_memory::bitmap::AtomicBitmap;
use vm_migration::protocol::{MemoryRange, Request, Response, Status};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::migration::transport::SocketStream;
use crate::userfaultfd;

pub(crate) fn trace_remote_fault(event: &str, offset: u64, bytes: u64, result: i32) {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ENABLED.get_or_init(|| std::env::var("KUASAR_REMOTE_FAULT_TRACE").as_deref() == Ok("1")) {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let line = format!(
            "REMOTE_PAGE ns={ns} pid={} thread={:?} event={event} offset={offset} bytes={bytes} result={result}\n",
            std::process::id(),
            std::thread::current().id()
        );
        let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), line.as_bytes());
    }
}

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
/// Successful resolution reports the contiguous, populated page-index span.
/// Callers publish every page in their existing bitmap, including speculative
/// neighbors, so queued faults and background loading do not fetch them again.
pub(crate) trait UffdMemorySource: Send {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
        _served: &AtomicBitmap,
    ) -> Result<std::ops::Range<u64>, io::Error>;

    // Only immutable private snapshot sources opt in. Incoming postcopy and
    // shared backing retain their original missing/minor fault semantics.
    fn resolve_served(
        &mut self,
        _fd: BorrowedFd<'_>,
        _range: &UffdRange,
        _page_idx: u64,
    ) -> io::Result<bool> {
        Ok(false)
    }

    fn native_handler(&self) -> bool {
        false
    }
    fn native_start(&mut self, _uffd: &Uffd) -> io::Result<()> {
        Err(io::Error::other("Native UFFD unsupported"))
    }
    fn native_wait(&mut self, _stop: &vmm_sys_util::eventfd::EventFd) -> io::Result<bool> {
        Err(io::Error::other("Native UFFD unsupported"))
    }
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
        _served: &AtomicBitmap,
    ) -> Result<std::ops::Range<u64>, io::Error> {
        let page_size = range.page_size as usize;
        let page_addr = range.page_addr(page_idx);
        let file_pos = range.page_source_offset(page_idx);

        if self.buf.len() < page_size {
            self.buf.resize(page_size, 0);
        }
        self.file
            .read_exact_at(&mut self.buf[..page_size], file_pos)?;

        match copy(uffd_fd, page_addr, self.buf.as_ptr(), range.page_size) {
            Ok(()) => Ok(page_idx..page_idx + 1),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Installed concurrently. Wake any blocked threads.
                if let Err(e) = wake(uffd_fd, page_addr, range.page_size) {
                    log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                }
                Ok(page_idx..page_idx + 1)
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
    chunk_window: bool,
    #[serde(default)]
    local_file_plan: bool,
    #[serde(default)]
    initialize_delta: bool,
    #[serde(default)]
    native_handler: bool,
}
pub(crate) struct ManifestUffdMemorySource {
    pub(crate) native_handler: bool,
    local: Option<LocalSnapshotPages>,
    read_window_bytes: u64,
    chunk_window: bool,
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
        if d.initialize_delta && !d.local_file_plan {
            return Err(io::Error::other(
                "Inline delta requires a local parent plan",
            ));
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
            native_handler: d.native_handler && !d.local_file_plan,
            read_window_bytes: d.read_window_bytes,
            chunk_window: d.chunk_window,
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
            .missing
            .iter()
            .any(|&(off, len)| !off.is_multiple_of(page) || !len.is_multiple_of(page))
        {
            return Ok(None);
        }
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
                for &(start, length) in self.zero_ranges.iter().chain(local.missing.iter()) {
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
        let mut missing: Vec<_> = local
            .extents
            .iter()
            .filter(|&&(_, _, physical, _)| !physical.is_multiple_of(page))
            .map(|&(off, len, _, _)| (off, len))
            .chain(local.missing.iter().copied())
            .collect();
        missing.sort_unstable();
        Ok(Some(missing))
    }
    /// Fill a bounded delta directly into fresh anonymous RAM before KVM runs.
    /// The server authenticates each complete read before sending it. Any short
    /// read aborts restore; no partially initialized VM becomes runnable.
    /// Caller must uphold the same exclusive private-window ownership as map_local_cow.
    pub(crate) unsafe fn initialize_delta(
        &mut self,
        windows: &[(u64, u64, u64, i32)],
        missing: &[(u64, u64)],
    ) -> io::Result<()> {
        use std::io::Write;
        let local = self
            .local
            .as_ref()
            .ok_or_else(|| io::Error::other("Missing local delta plan"))?;
        if missing != local.missing || missing.iter().map(|e| e.1).sum::<u64>() > 16 * 1024 * 1024 {
            return Err(io::Error::other("Invalid inline delta plan"));
        }
        // Validate complete destination coverage before requesting any bytes.
        for &(start, len) in missing {
            let mut at = start;
            for &(off, size, _, _) in windows {
                if at >= off && at < off + size {
                    at = (off + size).min(start + len);
                }
            }
            if at != start + len {
                return Err(io::Error::other("Unmapped inline delta"));
            }
        }
        self.stream.write_all(&[0; 16])?;
        for &(start, len) in missing {
            for &(off, size, host, _) in windows {
                let lo = start.max(off);
                let hi = (start + len).min(off + size);
                if lo >= hi {
                    continue;
                }
                // SAFETY: map_local_cow has left these validated, disjoint delta
                // windows private and anonymous; no vCPU/device can access them.
                let dst = unsafe {
                    std::slice::from_raw_parts_mut((host + lo - off) as *mut u8, (hi - lo) as usize)
                };
                self.stream.read_exact(dst)?;
            }
        }
        Ok(())
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
            let cost = windows.len() + self.zero_ranges.len() + local.missing.len();
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
        if self.chunk_window {
            // Chunk windows are installed into guest RAM once. Keeping a second
            // plaintext LRU would duplicate that state; reuse a single buffer.
            self.buf.clear();
            return;
        }
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
    // Cache only immutable source bytes, never guest RAM. Installing a source
    // window cannot overwrite an already live guest page.
    fn read_page(&mut self, range: &UffdRange, page_idx: u64) -> io::Result<&[u8]> {
        use std::io::Write;
        if range.page_size > 2 * 1024 * 1024 || page_idx >= range.num_pages() {
            return Err(io::Error::other("Unsupported Manifest page request"));
        }
        let offset = range.page_source_offset(page_idx);
        if let Some(local) = &self.local {
            let i = local
                .missing
                .partition_point(|&(off, len)| off + len <= offset);
            if local
                .missing
                .get(i)
                .is_none_or(|&(off, _)| off >= offset + range.page_size)
            {
                self.buf.resize(range.page_size as usize, 0);
                local.read(&mut self.buf, offset)?;
                self.cache_offset = offset;
                return Ok(&self.buf);
            }
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
        let chunk_window = window && self.chunk_window;
        request[8..].copy_from_slice(
            &(count
                | if window { 1u64 << 63 } else { 0 }
                | if chunk_window { 1u64 << 62 } else { 0 })
            .to_le_bytes(),
        );
        self.buf.clear(); // An I/O error must never leave a valid cache entry.
        trace_remote_fault("read", offset, count, 0);
        self.stream.write_all(&request)?;
        let returned_offset = if chunk_window {
            let mut start = [0; 8];
            self.stream.read_exact(&mut start)?;
            u64::from_le_bytes(start)
        } else {
            offset
        };
        let returned = if window {
            let mut length = [0; 8];
            self.stream.read_exact(&mut length)?;
            u64::from_le_bytes(length)
        } else {
            count
        };
        if returned < range.page_size
            || returned > if chunk_window { 1 << 20 } else { count }
            || returned % range.page_size != 0
            || returned_offset % range.page_size != 0
            || returned_offset > offset
            || returned_offset
                .checked_add(returned)
                .is_none_or(|end| end < offset + range.page_size)
        {
            return Err(io::Error::other("Invalid Manifest returned window"));
        }
        self.buf.resize(returned as usize, 0);
        if let Err(err) = self.stream.read_exact(&mut self.buf) {
            self.buf.clear();
            return Err(err);
        }
        trace_remote_fault("read_done", returned_offset, returned, 0);
        self.cache_offset = returned_offset;
        let inner = (offset - returned_offset) as usize;
        Ok(&self.buf[inner..inner + range.page_size as usize])
    }
}

// The fd pins the immutable plaintext snapshot inode. Packed offsets need not
// be mmap-aligned: pread supplies only the faulted page, UFFD installs private
// RAM, and writes remain ordinary guest CoW writes. No RAM fd crosses processes.
struct LocalSnapshotPages {
    files: Vec<File>,
    size: u64,
    extents: Vec<(u64, u64, u64, usize)>,
    missing: Vec<(u64, u64)>,
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
        if n != 1 || (marker != [1] && marker != [2] && marker != [3]) {
            return Err(io::Error::other("Invalid local snapshot handoff"));
        }
        let version = marker[0];
        let multiple = version >= 2;
        let mut files = vec![file];
        if multiple {
            let mut count = [0; 8];
            stream.read_exact(&mut count)?;
            let count = u64::from_le_bytes(count);
            if !(if version == 3 { 1 } else { 2 }..=64).contains(&count) {
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
        let mut records =
            std::io::BufReader::with_capacity(65536, (&mut *stream).take(count * width));
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
        drop(records);
        let mut missing = Vec::new();
        if version == 3 {
            stream.read_exact(&mut word)?;
            let count = u64::from_le_bytes(word);
            if count == 0 || count > 1 << 20 {
                return Err(io::Error::other("Invalid missing snapshot extent count"));
            }
            let mut end = 0;
            for _ in 0..count {
                stream.read_exact(&mut word)?;
                let off = u64::from_le_bytes(word);
                stream.read_exact(&mut word)?;
                let len = u64::from_le_bytes(word);
                if off < end || off > size || len == 0 || len > size - off {
                    return Err(io::Error::other("Invalid missing snapshot extent"));
                }
                missing.push((off, len));
                end = off + len;
            }
        }
        let mut coverage: Vec<_> = extents
            .iter()
            .map(|(o, n, _, _)| (*o, *n))
            .chain(zeros.iter().copied())
            .chain(missing.iter().copied())
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
            missing,
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
// Preserve shared kernel zero pages for private anonymous RAM. In particular,
// snapshot/fork readers must not turn every absent zero page into a private 4 KiB
// allocation. The input has already passed the source authentication boundary.
fn install_manifest_page(fd: BorrowedFd<'_>, addr: u64, data: &[u8]) -> io::Result<()> {
    let result = install_manifest_page_inner(fd, addr, data);
    trace_remote_fault(
        "install",
        addr,
        data.len() as u64,
        result
            .as_ref()
            .err()
            .and_then(|e| e.raw_os_error())
            .unwrap_or(0),
    );
    result
}

fn install_manifest_page_inner(fd: BorrowedFd<'_>, addr: u64, data: &[u8]) -> io::Result<()> {
    if !data.is_empty() && data.len().is_multiple_of(4096) && data.iter().all(|b| *b == 0) {
        #[repr(C)]
        struct UffdioZeropage {
            start: u64,
            len: u64,
            mode: u64,
            zeropage: i64,
        }
        let mut zero = UffdioZeropage {
            start: addr,
            len: data.len() as u64,
            mode: 0,
            zeropage: 0,
        };
        loop {
            // SAFETY: zero matches the Linux uffdio_zeropage ABI, and addr is
            // the registered destination page just as for UFFDIO_COPY below.
            let ret = unsafe {
                libc::ioctl(
                    fd.as_raw_fd(),
                    userfaultfd::UFFDIO_ZEROPAGE as libc::Ioctl,
                    &mut zero,
                )
            };
            if ret >= 0 {
                return Ok(());
            }
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) => thread::yield_now(),
                // Other backing types may not support ZEROPAGE. Preserve their
                // existing authenticated COPY behavior instead.
                Some(libc::EINVAL) | Some(libc::ENOTTY) => break,
                _ => return Err(err),
            }
        }
    }
    copy(fd, addr, data.as_ptr(), data.len() as u64)
}

// Native UFFD installs a contiguous tail with one ioctl, not one per page.
// Keep zero and nonzero runs separate: zero pages must remain shared zero pages,
// rather than allocating private RAM as a side effect of batching.
fn install_manifest_tail(fd: BorrowedFd<'_>, addr: u64, data: &[u8]) -> u64 {
    let mut done = 0usize;
    while done < data.len() {
        let zero = data[done..done + 4096].iter().all(|b| *b == 0);
        let mut end = done + 4096;
        while end < data.len() && data[end..end + 4096].iter().all(|b| *b == 0) == zero {
            end += 4096;
        }
        if install_manifest_page(fd, addr + done as u64, &data[done..end]).is_err() {
            // COPY/ZEROPAGE may have installed a prefix before encountering a
            // present page. Reconcile pagewise; neither ioctl overwrites live
            // guest data, and an unexpected error only stops speculative work.
            while done < end {
                match install_manifest_page(fd, addr + done as u64, &data[done..done + 4096]) {
                    Ok(()) => (),
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) => (),
                    Err(_) => return (done / 4096) as u64,
                }
                done += 4096;
            }
        } else {
            done = end;
        }
    }
    (done / 4096) as u64
}

impl UffdMemorySource for ManifestUffdMemorySource {
    fn native_handler(&self) -> bool {
        self.native_handler
    }
    fn native_start(&mut self, uffd: &Uffd) -> io::Result<()> {
        use std::io::Write;
        self.stream.write_all(&u64::MAX.to_le_bytes())?;
        self.stream
            .write_all(&(uffd.ranges().len() as u64).to_le_bytes())?;
        let n = self
            .stream
            .send_with_fd(&[1u8][..], uffd.fd().as_raw_fd())?;
        if n != 1 {
            return Err(io::Error::other("Incomplete native UFFD capability"));
        }
        for range in uffd.ranges() {
            for value in [range.host_addr, range.length, range.source_offset] {
                self.stream.write_all(&value.to_le_bytes())?;
            }
        }
        let mut ack = [0u8];
        self.stream.read_exact(&mut ack)?;
        if ack != [1] {
            return Err(io::Error::other("Native UFFD registration rejected"));
        }
        Ok(())
    }
    fn native_wait(&mut self, stop: &vmm_sys_util::eventfd::EventFd) -> io::Result<bool> {
        use std::io::Write;
        let mut fds = [
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: fds owns two initialized pollfd records for live descriptors.
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if fds[0].revents != 0 {
                let command = stop.read()?;
                if command & 1 != 0 {
                    return Ok(false);
                }
                if command & 2 != 0 {
                    self.stream.write_all(&[2])?;
                    let mut ack = [0];
                    self.stream.read_exact(&mut ack)?;
                    if ack != [2] {
                        return Err(io::Error::other("Native UFFD export rejected"));
                    }
                    return Ok(true);
                }
            }
            if fds[1].revents != 0 {
                return Err(io::Error::other("Native UFFD owner disconnected"));
            }
        }
    }

    fn resolve(
        &mut self,
        fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
        served: &AtomicBitmap,
    ) -> io::Result<std::ops::Range<u64>> {
        trace_remote_fault(
            "resolve",
            range.page_source_offset(page_idx),
            range.page_size,
            0,
        );
        let data = self.read_page(range, page_idx)?;
        let addr = range.page_addr(page_idx);
        match install_manifest_page(fd, addr, data) {
            Ok(()) => (),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => wake(fd, addr, range.page_size)?,
            Err(e) => return Err(e),
        }
        // The authenticated immutable window has already been fetched. Install
        // its remaining pages without another guest fault/context switch. COPY
        // never replaces a present page, so concurrent guest writes win. This
        // is bounded by the negotiated window, not by the size of guest RAM.
        let mut installed_start = page_idx;
        let mut installed_end = page_idx + 1;
        if range.page_size == 4096 {
            let offset = range.page_source_offset(page_idx);
            let end =
                (self.cache_offset + self.buf.len() as u64).min(range.source_offset + range.length);
            let mut suffix_end = page_idx + 1;
            while range.page_source_offset(suffix_end) + 4096 <= end
                && !served.is_bit_set(suffix_end as usize)
            {
                suffix_end += 1;
            }
            let first = (offset + 4096 - self.cache_offset) as usize;
            let last = (range.page_source_offset(suffix_end) - self.cache_offset) as usize;
            installed_end += install_manifest_tail(fd, addr + 4096, &self.buf[first..last]);

            let start = self.cache_offset.max(range.source_offset);
            let mut prefix_start = page_idx;
            while range.page_source_offset(prefix_start) >= start + 4096
                && !served.is_bit_set((prefix_start - 1) as usize)
            {
                prefix_start -= 1;
            }
            let first = (range.page_source_offset(prefix_start) - self.cache_offset) as usize;
            let last = (offset - self.cache_offset) as usize;
            // Return only a contiguous installed range around the urgent page.
            // Record even a partial prefix before returning the contiguous range;
            // a later discard must never resurrect immutable source bytes.
            let count =
                install_manifest_tail(fd, range.page_addr(prefix_start), &self.buf[first..last]);
            for page in prefix_start..prefix_start + count {
                served.set_bit(page as usize);
            }
            if count == page_idx - prefix_start {
                installed_start = prefix_start;
            }
        }
        Ok(installed_start..installed_end)
    }
    fn resolve_served(
        &mut self,
        fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> io::Result<bool> {
        if range.page_size != 4096 {
            return Ok(false);
        }
        let addr = range.page_addr(page_idx);
        // Match native UFFD StateLoaded: a discarded anonymous page is zero;
        // a queued duplicate on a live page converges via EEXIST and wake.
        // Never reread immutable snapshot bytes over a released guest page.
        let installed = match install_manifest_page(fd, addr, &[0; 4096]) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                wake(fd, addr, 4096)?;
                false
            }
            Err(e) => return Err(e),
        };
        // Native UFFD fills a bounded tail of a known Zero run. The served
        // bitmap also covers zero metadata: don't turn it into one round trip
        // per zero page. Discarded data pages have no such source capability.
        let offset = range.page_source_offset(page_idx);
        let index = self
            .zero_ranges
            .partition_point(|&(off, len)| off + len <= offset);
        if installed
            && let Some(&(off, len)) = self.zero_ranges.get(index)
            && off <= offset
        {
            let end = (off + len)
                .min(range.source_offset + range.length)
                .min(offset + 65536);
            let mut next = offset + 4096;
            while next + 4096 <= end {
                let target = range.host_addr + next - range.source_offset;
                // Stop at a live guest page (EEXIST) or any speculative error.
                // Never extend beyond the authenticated zero metadata span.
                if install_manifest_page(fd, target, &[0; 4096]).is_err() {
                    break;
                }
                next += 4096;
            }
        }
        trace_remote_fault("served_zero", range.page_source_offset(page_idx), 4096, 0);
        Ok(true)
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
        _served: &AtomicBitmap,
    ) -> Result<std::ops::Range<u64>, io::Error> {
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
                Ok(()) => Ok(page_idx..page_idx + 1),
                // This is fine, someone mapped the page before us.
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(page_idx..page_idx + 1)
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
                Ok(()) => Ok(page_idx..page_idx + 1),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(page_idx..page_idx + 1)
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
    fn hybrid_handoff_requires_exact_coverage() {
        for (missing, valid) in [(4096u64, true), (0, false), (8192, false)] {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all_at(&vec![7; 8192], 0).unwrap();
            let file = File::open(tmp.path()).unwrap();
            let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            let sender = thread::spawn(move || {
                server.send_with_fd(&[3u8][..], file.as_raw_fd()).unwrap();
                // one FD, one data extent, then one mandatory pager extent
                for n in [1u64, 1, 0, 4096, 0, 0, 1, missing, 4096] {
                    server.write_all(&n.to_le_bytes()).unwrap();
                }
            });
            let result = LocalSnapshotPages::receive(&mut client, 8192, &[]);
            sender.join().unwrap();
            assert_eq!(result.is_ok(), valid);
        }
    }

    #[test]
    fn hybrid_multi_fd_preserves_protocol_version() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().set_len(8192).unwrap();
        let file = File::open(tmp.path()).unwrap();
        let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            server.send_with_fd(&[3u8][..], file.as_raw_fd()).unwrap();
            server.write_all(&2u64.to_le_bytes()).unwrap();
            server.send_with_fd(&[1u8][..], file.as_raw_fd()).unwrap();
            for n in [1u64, 0, 4096, 0, 1, 1, 4096, 4096] {
                server.write_all(&n.to_le_bytes()).unwrap();
            }
        });
        let result = LocalSnapshotPages::receive(&mut client, 8192, &[]).unwrap();
        assert_eq!(result.missing, [(4096, 4096)]);
        assert_eq!(result.files.len(), 2);
        sender.join().unwrap();
    }

    #[test]
    fn hybrid_seed_masks_delta_and_reads_it_from_pager() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all_at(&vec![7; 32768], 0).unwrap();
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut request = [0; 16];
            server.read_exact(&mut request).unwrap();
            assert_eq!(u64::from_le_bytes(request[..8].try_into().unwrap()), 12288);
            server.write_all(&4096u64.to_le_bytes()).unwrap();
            server.write_all(&vec![9; 4096]).unwrap();
        });
        let mut source = ManifestUffdMemorySource {
            native_handler: false,
            local: Some(LocalSnapshotPages {
                files: vec![File::open(tmp.path()).unwrap()],
                size: 32768,
                extents: [0u64, 4096, 8192, 16384, 20480, 24576]
                    .iter()
                    .map(|&o| (o, 4096, o, 0))
                    .collect(),
                missing: vec![(12288, 4096)],
            }),
            stream: client,
            buf: Vec::new(),
            zero_ranges: vec![(28672, 4096)],
            read_window_bytes: 65536,
            chunk_window: false,
            cache_offset: 0,
            cached_windows: Default::default(),
        };
        // SAFETY: new exclusively owned anonymous mapping, released below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                32768,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        assert!(
            source
                .local_cow_seed(&[(0, 32768, ptr as u64, 0)], 4096)
                .unwrap()
                .is_some()
        );
        // SAFETY: the mapping is untouched and exclusively owned by this test.
        unsafe {
            assert_eq!(
                source.map_local_cow(&[(0, 32768, ptr as u64, 0)]).unwrap(),
                Some(vec![(12288, 4096)])
            );
            let bytes = std::slice::from_raw_parts_mut(ptr as *mut u8, 32768);
            assert_eq!(bytes[0], 7);
            assert_eq!(bytes[12288], 0, "stale parent data exposed in delta range");
            assert_eq!(bytes[28672], 0);
            bytes[0] = 42;
        }
        let range = UffdRange {
            host_addr: ptr as u64 + 12288,
            length: 4096,
            source_offset: 12288,
            page_size: 4096,
        };
        assert_eq!(source.read_page(&range, 0).unwrap(), &[9; 4096]);
        worker.join().unwrap();
        let mut byte = [0];
        tmp.as_file().read_exact_at(&mut byte, 0).unwrap();
        assert_eq!(byte, [7]);
        // SAFETY: exact owned mapping, no future access.
        assert_eq!(unsafe { libc::munmap(ptr, 32768) }, 0);
    }

    #[test]
    #[ignore = "Requires userfaultfd permission; run explicitly as root"]
    fn manifest_window_install_preserves_present_guest_page() {
        let fd = create(0).unwrap();
        // SAFETY: anonymous mapping owned solely by this test; released below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                12288,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        register(fd.as_fd(), ptr as u64, 12288, false).unwrap();
        let live = vec![0xa5; 4096];
        copy(fd.as_fd(), ptr as u64 + 4096, live.as_ptr(), 4096).unwrap();
        let (client, _server) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut source = ManifestUffdMemorySource {
            native_handler: false,
            local: None,
            zero_ranges: Vec::new(),
            stream: client,
            buf: [vec![0x37; 8192], vec![0; 4096]].concat(),
            cache_offset: 0,
            cached_windows: std::collections::VecDeque::new(),
            read_window_bytes: 16384,
            chunk_window: false,
        };
        let range = UffdRange {
            host_addr: ptr as u64,
            length: 12288,
            source_offset: 0,
            page_size: 4096,
        };
        let served = AtomicBitmap::new(12288, std::num::NonZeroUsize::new(4096).unwrap());
        assert_eq!(
            source.resolve(fd.as_fd(), &range, 2, &served).unwrap(),
            0..3
        );
        assert!(page_present(ptr as u64 + 8192).unwrap());
        // SAFETY: all three registered pages have been populated; no concurrent writer.
        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, 12288) };
        assert!(bytes[..4096].iter().all(|x| *x == 0x37));
        assert!(bytes[4096..8192].iter().all(|x| *x == 0xa5));
        assert!(bytes[8192..].iter().all(|x| *x == 0));
        // SAFETY: the final page is a writable private mapping; a write must
        // CoW the kernel zero page without modifying its source window.
        unsafe { (ptr as *mut u8).add(8192).write_volatile(0x92) };
        assert!(source.buf[8192..].iter().all(|x| *x == 0));
        assert!(source.resolve_served(fd.as_fd(), &range, 1).unwrap());
        // SAFETY: this populated mapping belongs to this test alone.
        assert_eq!(
            unsafe { (ptr as *const u8).add(4096).read_volatile() },
            0xa5
        );
        // SAFETY: discard exactly the owned middle page, with no other reader.
        assert_eq!(
            unsafe { libc::madvise((ptr as *mut u8).add(4096).cast(), 4096, libc::MADV_DONTNEED) },
            0
        );
        served.set_bit(1);
        // SAFETY: discard the owned first page to trigger neighbor population.
        assert_eq!(unsafe { libc::madvise(ptr, 4096, libc::MADV_DONTNEED) }, 0);
        assert_eq!(
            source.resolve(fd.as_fd(), &range, 0, &served).unwrap(),
            0..1
        );
        // A neighbor fill must not resurrect the discarded old snapshot bytes.
        assert!(!page_present(ptr as u64 + 4096).unwrap());
        assert!(source.resolve_served(fd.as_fd(), &range, 1).unwrap());
        // SAFETY: resolve_served has installed the page synchronously.
        let discarded = unsafe { std::slice::from_raw_parts((ptr as *const u8).add(4096), 4096) };
        assert!(discarded.iter().all(|x| *x == 0));
        assert!(source.buf[4096..8192].iter().all(|x| *x == 0x37));
        drop(fd);
        // SAFETY: this is the original mapping and length, no references used afterwards.
        assert_eq!(unsafe { libc::munmap(ptr, 12288) }, 0);
    }

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
            native_handler: false,
            local: Some(LocalSnapshotPages {
                missing: Vec::new(),
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
            chunk_window: false,
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
            native_handler: false,
            local: Some(LocalSnapshotPages {
                missing: Vec::new(),
                files: vec![File::open(tmp.path()).unwrap()],
                size: 12288,
                extents: vec![(0, 4096, 0, 0), (8192, 4096, 4096, 0)],
            }),
            stream,
            buf: Vec::new(),
            zero_ranges: vec![(4096, 4096)],
            read_window_bytes: 65536,
            chunk_window: false,
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
    #[ignore = "Requires userfaultfd permission; run explicitly as root"]
    fn manifest_zero_tail_respects_extent_and_live_writes() {
        let fd = create(0).unwrap();
        // SAFETY: mapping owned by this test; no concurrent readers/writers.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        register(fd.as_fd(), ptr as u64, 16384, false).unwrap();
        copy(fd.as_fd(), ptr as u64 + 8192, [0xa5; 4096].as_ptr(), 4096).unwrap();
        let (client, _server) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut source = ManifestUffdMemorySource {
            native_handler: false,
            local: None,
            zero_ranges: vec![(0, 12288)],
            stream: client,
            buf: Vec::new(),
            read_window_bytes: 65536,
            chunk_window: true,
            cache_offset: 0,
            cached_windows: std::collections::VecDeque::new(),
        };
        let range = UffdRange {
            host_addr: ptr as u64,
            length: 16384,
            source_offset: 0,
            page_size: 4096,
        };
        assert!(source.resolve_served(fd.as_fd(), &range, 0).unwrap());
        assert!(page_present(ptr as u64 + 4096).unwrap());
        assert!(!page_present(ptr as u64 + 12288).unwrap());
        // SAFETY: the first three pages have been populated, with no other user.
        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, 12288) };
        assert!(bytes[..8192].iter().all(|b| *b == 0));
        assert!(bytes[8192..].iter().all(|b| *b == 0xa5));
        assert!(source.buf.is_empty());
        drop(fd);
        // SAFETY: original mapping, no later access.
        assert_eq!(unsafe { libc::munmap(ptr, 16384) }, 0);
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
    fn inline_delta_initializes_only_missing_private_bytes() {
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut req = [1; 16];
            server.read_exact(&mut req).unwrap();
            assert_eq!(req, [0; 16]);
            server.write_all(&[9; 4096]).unwrap();
        });
        let mut source = ManifestUffdMemorySource {
            native_handler: false,
            local: Some(LocalSnapshotPages {
                files: Vec::new(),
                size: 8192,
                extents: Vec::new(),
                missing: vec![(4096, 4096)],
            }),
            zero_ranges: Vec::new(),
            stream: client,
            buf: Vec::new(),
            cache_offset: 0,
            cached_windows: std::collections::VecDeque::new(),
            read_window_bytes: 65536,
            chunk_window: false,
        };
        let mut ram = vec![7u8; 8192];
        let windows = [(0, 8192, ram.as_mut_ptr() as u64, 0)];
        // SAFETY: exclusively owned test RAM, with no other reader/writer.
        unsafe { source.initialize_delta(&windows, &[(4096, 4096)]) }.unwrap();
        assert_eq!(&ram[..4096], &[7; 4096]);
        assert_eq!(&ram[4096..], &[9; 4096]);
        worker.join().unwrap();
    }

    #[test]
    fn manifest_chunk_window_uses_returned_start_and_rejects_invalid_span() {
        for (start, length, valid) in [
            (0u64, 12288u64, true),
            (8192, 4096, false),
            (0, 4096, false),
            (0, 2 << 20, false),
        ] {
            let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
            let worker = thread::spawn(move || {
                let mut req = [0; 16];
                server.read_exact(&mut req).unwrap();
                assert_eq!(u64::from_le_bytes(req[..8].try_into().unwrap()), 4096);
                assert_eq!(u64::from_le_bytes(req[8..].try_into().unwrap()) >> 62, 3);
                server.write_all(&start.to_le_bytes()).unwrap();
                server.write_all(&length.to_le_bytes()).unwrap();
                if valid {
                    server
                        .write_all(&[vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat())
                        .unwrap();
                }
            });
            let mut source = ManifestUffdMemorySource {
                native_handler: false,
                local: None,
                zero_ranges: Vec::new(),
                stream: client,
                buf: Vec::new(),
                cache_offset: 0,
                cached_windows: std::collections::VecDeque::new(),
                read_window_bytes: 65536,
                chunk_window: true,
            };
            let range = UffdRange {
                host_addr: 0,
                length: 16384,
                source_offset: 0,
                page_size: 4096,
            };
            let result = source.read_page(&range, 1);
            assert_eq!(result.is_ok(), valid);
            if valid {
                assert_eq!(result.unwrap(), &[2; 4096]);
                assert_eq!(source.read_page(&range, 0).unwrap(), &[1; 4096]);
                source.retain_window();
                assert!(source.cached_windows.is_empty());
                assert!(source.buf.is_empty());
            }
            worker.join().unwrap();
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
            native_handler: false,
            local: None,
            zero_ranges: Vec::new(),
            stream: client,
            buf: Vec::new(),
            cache_offset: 0,
            cached_windows: std::collections::VecDeque::new(),
            read_window_bytes: 8192,
            chunk_window: false,
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
