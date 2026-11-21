// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

//! Sparse snapshot/copy helpers for the `MemoryManager` and offload daemon.
//! File copies preserve holes using `lseek(SEEK_DATA)`/`lseek(SEEK_HOLE)`,
//! with a dense fallback when sparse-seek is unsupported. Private guest RAM
//! is read from memory instead and all-zero pages are left as holes.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::FileExt;

// Only use in the single-threaded frozen capture child, after all UFFD
// registrations have been resolved/removed and no KVM VM can write this RAM.
// A non-present, non-swapped, unmarked PTE in a truly anonymous private VMA
// denotes demand-zero memory. File-backed nonresident pages are NOT zero.
// Inspect actual VMAs: GuestRegion flags can predate a MAP_FIXED restore.
pub(crate) fn frozen_anonymous_read_ranges(
    address: u64,
    length: u64,
) -> io::Result<Option<Vec<(u64, u64)>>> {
    if vm_allocator::page_size::get_page_size() != 4096 || address % 4096 != 0 || length % 4096 != 0
    {
        return Ok(None);
    }
    let Some(end) = address.checked_add(length) else {
        return Ok(None);
    };
    if !anonymous_private_coverage(&std::fs::read_to_string("/proc/self/maps")?, address, end) {
        return Ok(None);
    }
    let pagemap = File::open("/proc/self/pagemap")?;
    let mut buffer = [0u8; 64 * 1024];
    let mut page = 0;
    let pages = length / 4096;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    while page < pages {
        let count = (pages - page).min((buffer.len() / 8) as u64);
        pagemap.read_exact_at(
            &mut buffer[..count as usize * 8],
            (address / 4096 + page) * 8,
        )?;
        for entry in buffer[..count as usize * 8].chunks_exact(8) {
            let entry = u64::from_ne_bytes(entry.try_into().unwrap());
            // Soft-dirty is allowed on a never-faulted mapping. Every other
            // flag (including swapped, present, guard or UFFD markers) forces
            // the normal read, irrespective of masked/unavailable PFNs.
            if entry & !(1 << 55) != 0 {
                let offset = page * 4096;
                if let Some(last) = ranges.last_mut()
                    && last.0 + last.1 == offset
                {
                    last.1 += 4096;
                } else {
                    if ranges.len() == 1 << 20 {
                        return Ok(None);
                    }
                    ranges.push((offset, 4096));
                }
            }
            page += 1;
        }
    }
    Ok(Some(ranges))
}

fn anonymous_private_coverage(maps: &str, start: u64, end: u64) -> bool {
    let mut cursor = start;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 {
            return false;
        }
        let Some((lo, hi)) = fields[0].split_once('-') else {
            return false;
        };
        let (Ok(lo), Ok(hi)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) else {
            return false;
        };
        if hi <= cursor {
            continue;
        }
        if lo > cursor
            || fields.len() != 5
            || fields[1] != "rw-p"
            || fields[3] != "00:00"
            || fields[4] != "0"
        {
            return false;
        }
        cursor = hi.min(end);
        if cursor == end {
            return true;
        }
    }
    false
}

/// Snapshot a quiesced memory range into a newly created, zero-filled file.
/// Read actual guest bytes, not the mapping's backing file: private CoW pages
/// (including pages overwritten with zeroes) need not match that file.
/// Memory use is bounded; adjacent nonzero pages share one write operation.
pub fn write_memory_sparse(
    destination: &File,
    destination_offset: u64,
    length: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
) -> io::Result<u64> {
    const ZERO_PAGE: [u8; 4096] = [0; 4096];
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    let mut written = 0;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        read(offset, &mut buffer[..count])?;
        let mut run = None;
        for (index, page) in buffer[..count].chunks(4096).enumerate() {
            let start = index * 4096;
            // Slice equality uses the optimized byte comparison routine instead
            // of a scalar early-exit loop over every byte of empty RAM.
            if page != &ZERO_PAGE[..page.len()] {
                run.get_or_insert(start);
            } else if let Some(begin) = run.take() {
                destination.write_all_at(
                    &buffer[begin..start],
                    destination_offset + offset + begin as u64,
                )?;
                written += (start - begin) as u64;
            }
        }
        if let Some(begin) = run {
            destination.write_all_at(
                &buffer[begin..count],
                destination_offset + offset + begin as u64,
            )?;
            written += (count - begin) as u64;
        }
        offset += count as u64;
    }
    Ok(written)
}

/// Find the next populated (data) extent in `[cursor, end)` of `fd`,
/// driven by `lseek(SEEK_DATA)` / `lseek(SEEK_HOLE)`. Returns
/// `Ok(Some((offset, len)))` for the next data extent within the window,
/// or `Ok(None)` if there is no more data. Returns `Err` if the fd or
/// filesystem does not support `SEEK_HOLE` (e.g. hugetlbfs) or for any
/// other I/O error. Callers should treat a first-call error as "fall
/// back to the dense path".
pub fn next_data_extent(
    fd: BorrowedFd<'_>,
    cursor: u64,
    end: u64,
) -> io::Result<Option<(u64, u64)>> {
    let raw = fd.as_raw_fd();
    // SAFETY: BorrowedFd guarantees the fd is valid for the lifetime of
    // the borrow; lseek does not consume or close it.
    let data_off = unsafe { libc::lseek(raw, cursor as i64, libc::SEEK_DATA) };
    if data_off < 0 {
        let e = io::Error::last_os_error();
        // ENXIO from SEEK_DATA means there is no more data at or after
        // cursor. Any other error means the filesystem does not support
        // SEEK_HOLE; the caller falls back to the dense path.
        return if e.raw_os_error() == Some(libc::ENXIO) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let data_off = data_off as u64;
    if data_off >= end {
        return Ok(None);
    }
    // SAFETY: same as above.
    let hole_off = unsafe { libc::lseek(raw, data_off as i64, libc::SEEK_HOLE) };
    if hole_off < 0 {
        return Err(io::Error::last_os_error());
    }
    let hole_off = (hole_off as u64).min(end);
    Ok(Some((data_off, hole_off - data_off)))
}

/// Copy `[src_offset, src_offset+len)` of `src` to `dst` at `dst_offset`,
/// writing only the populated extents so `dst` keeps its holes. `dst` must
/// already be sized (e.g. via `set_len`). Returns `Ok(true)` if the region
/// was written sparsely, or `Ok(false)` if `SEEK_HOLE` is unsupported on the
/// source fd (caller should fall back to a dense copy).
pub fn write_region_sparse(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<bool> {
    let src_fd = src.as_fd();
    let end = src_offset
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;

    // First call to next_data_extent doubles as a SEEK_HOLE-support probe:
    // a non-ENXIO error means the filesystem doesn't support sparse-seek;
    // tell the caller to use the dense path instead.
    let mut next = match next_data_extent(src_fd, src_offset, end) {
        Ok(opt) => opt,
        Err(_) => return Ok(false),
    };

    const CHUNK: usize = 1 << 20;
    let mut buf = vec![0u8; CHUNK];

    while let Some((data_off, ext_len)) = next {
        debug_assert!(data_off >= src_offset);
        let in_region = data_off
            .checked_sub(src_offset)
            .expect("extent precedes src_offset");
        let mut written = 0u64;
        while written < ext_len {
            let this = ((ext_len - written) as usize).min(CHUNK);
            let slice = &mut buf[..this];
            let read = src.read_at(slice, data_off + written)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "read_at returned 0 inside data extent",
                ));
            }
            let mut wrote_total = 0;
            while wrote_total < read {
                let n = dst.write_at(
                    &slice[wrote_total..read],
                    dst_offset + in_region + written + wrote_total as u64,
                )?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write_at returned 0",
                    ));
                }
                wrote_total += n;
            }
            written += read as u64;
        }
        // Subsequent next_data_extent failures are real I/O errors, not
        // unsupported-FS, since the first probe succeeded.
        next = next_data_extent(src_fd, data_off + ext_len, end)?;
    }
    Ok(true)
}

/// Copy `[src_offset, src_offset+len)` of `src` to `dst` at `dst_offset`,
/// keeping `dst` sparse when the source filesystem supports `SEEK_HOLE` and
/// falling back to a dense byte copy otherwise (e.g. hugetlbfs). `dst` must
/// already be sized (e.g. via `set_len`). This is the sparse-or-dense wrapper
/// shared by all file-to-file copy consumers (e.g. the offload daemon).
pub fn copy_region(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<()> {
    if write_region_sparse(src, src_offset, dst, dst_offset, len)? {
        return Ok(());
    }
    // Dense fallback: source filesystem lacks SEEK_HOLE (e.g. hugetlbfs).
    const CHUNK: usize = 1 << 20;
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    while done < len {
        let this = ((len - done) as usize).min(CHUNK);
        src.read_exact_at(&mut buf[..this], src_offset + done)?;
        dst.write_all_at(&buf[..this], dst_offset + done)?;
        done += this as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn anonymous_capture_rejects_file_shared_and_gapped_mappings() {
        use super::anonymous_private_coverage as covered;
        assert!(covered("1000-4000 rw-p 00000000 00:00 0", 0x1000, 0x4000));
        for maps in [
            "1000-4000 rw-p 00000000 08:01 7 /tmp/snapshot",
            "1000-4000 rw-s 00000000 00:00 0",
            "2000-4000 rw-p 00000000 00:00 0",
            "1000-4000 rw-p 00000000 00:00 0 [anon:unknown]",
        ] {
            assert!(!covered(maps, 0x1000, 0x4000), "{maps}");
        }
    }

    #[test]
    fn anonymous_capture_reads_present_pages_but_not_untouched_zeroes() {
        use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};
        if vm_allocator::page_size::get_page_size() != 4096 {
            return;
        }
        let memory = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 3 * 4096)]).unwrap();
        memory.write_obj(0xabu8, GuestAddress(4096)).unwrap();
        let address = memory.get_host_address(GuestAddress(0)).unwrap() as u64;
        let ranges = super::frozen_anonymous_read_ranges(address, 3 * 4096)
            .unwrap()
            .unwrap();
        assert_eq!(ranges, vec![(4096, 4096)]);
        // An overwritten zero page must also be read (its PTE remains present).
        memory.write_obj(0u8, GuestAddress(4096)).unwrap();
        assert_eq!(
            super::frozen_anonymous_read_ranges(address, 3 * 4096)
                .unwrap()
                .unwrap(),
            ranges
        );
    }

    #[test]
    fn anonymous_capture_never_skips_unfaulted_file_contents() {
        use vm_memory::{FileOffset, MmapRegion};
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&[0x91; 4096], 0).unwrap();
        let region = MmapRegion::<()>::build(
            Some(FileOffset::new(file, 0)),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .unwrap();
        assert!(
            super::frozen_anonymous_read_ranges(region.as_ptr() as u64, 4096)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn private_memory_snapshot_preserves_zeroes_boundaries_and_errors() {
        use std::os::unix::fs::MetadataExt;
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0; 2 * 1024 * 1024 + 17];
        data[0] = 1;
        data[1024 * 1024 - 1] = 2;
        data[1024 * 1024] = 3;
        *data.last_mut().unwrap() = 4;
        file.as_file().set_len(data.len() as u64 + 4096).unwrap();
        let written =
            super::write_memory_sparse(file.as_file(), 4096, data.len() as u64, |off, buf| {
                buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
                Ok(())
            })
            .unwrap();
        let actual = std::fs::read(file.path()).unwrap();
        assert_eq!(&actual[4096..], data);
        assert!(actual[..4096].iter().all(|b| *b == 0));
        assert_eq!(written, 3 * 4096 + 17);
        assert!(file.as_file().metadata().unwrap().blocks() * 512 < data.len() as u64);
        assert!(
            super::write_memory_sparse(file.as_file(), 0, 1, |_, _| Err(std::io::Error::other(
                "read failure"
            )))
            .is_err()
        );
    }

    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
    use std::os::unix::fs::FileExt;
    use std::{fs, io};

    use vm_allocator::page_size::get_page_size;

    use super::{next_data_extent, write_region_sparse};

    fn make_memfd(size: u64) -> fs::File {
        // SAFETY: memfd_create is a self-contained syscall; we own the
        // returned fd.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, c"sparse-test".as_ptr(), 0u32) };
        assert!(fd >= 0, "memfd_create failed");
        // SAFETY: memfd_create returned a valid fd that we now own; wrap it
        // in File so it is closed on drop.
        let f = unsafe { fs::File::from_raw_fd(fd as i32) };
        f.set_len(size).unwrap();
        f
    }

    fn collect_extents(fd: BorrowedFd<'_>, start: u64, end: u64) -> io::Result<Vec<(u64, u64)>> {
        let mut out = Vec::new();
        let mut cursor = start;
        while let Some((off, len)) = next_data_extent(fd, cursor, end)? {
            out.push((off, len));
            cursor = off + len;
        }
        Ok(out)
    }

    /// Punch an explicit hole into `f`. Tests use this instead of relying on
    /// "didn't write here" to mean "is a hole": modern shmem/tmpfs may
    /// allocate a multi-page folio on the first write and report the whole
    /// folio as data, so per-page hole tracking after a partial write is
    /// not portable. `fallocate(PUNCH_HOLE)` is the explicit "deallocate
    /// these pages" syscall and is honored on every Linux filesystem we
    /// run tests on (tmpfs, ext4, xfs, btrfs).
    fn punch_hole(f: &fs::File, off: u64, len: u64) {
        // SAFETY: FFI call; f is a valid open fd for the duration of the
        // call.
        let r = unsafe {
            libc::fallocate(
                f.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                off as libc::off_t,
                len as libc::off_t,
            )
        };
        assert_eq!(
            r,
            0,
            "fallocate PUNCH_HOLE off={off} len={len}: {}",
            io::Error::last_os_error(),
        );
    }

    /// Build a file with a deterministic sparse layout: write each `(off,
    /// len, byte)` data extent, then punch every gap into a real hole.
    /// The resulting `SEEK_DATA`/`SEEK_HOLE` extents match `data` exactly,
    /// regardless of folio/THP allocation policy on the backing FS.
    fn sparse_layout(f: &fs::File, total: u64, data: &[(u64, u64, u8)]) {
        f.set_len(total).unwrap();
        for &(off, len, byte) in data {
            f.write_all_at(&vec![byte; len as usize], off).unwrap();
        }
        let mut sorted: Vec<(u64, u64)> = data.iter().map(|&(o, l, _)| (o, l)).collect();
        sorted.sort_unstable();
        let mut cursor = 0u64;
        for (off, len) in sorted {
            assert!(off >= cursor, "overlapping data extents");
            if off > cursor {
                punch_hole(f, cursor, off - cursor);
            }
            cursor = off + len;
        }
        if cursor < total {
            punch_hole(f, cursor, total - cursor);
        }
    }

    #[test]
    fn empty_memfd_has_no_data_extents() {
        let f = make_memfd(4096 * 16);
        let extents = collect_extents(f.as_fd(), 0, 4096 * 16).unwrap();
        assert!(extents.is_empty(), "got {extents:?}");
    }

    #[test]
    fn written_pages_show_as_data_extents() {
        let page_size = get_page_size();
        let f = make_memfd(0);
        sparse_layout(
            &f,
            page_size * 16,
            &[
                (page_size * 2, page_size, 0xAB),
                (page_size * 5, page_size * 2, 0xCD),
            ],
        );
        let extents = collect_extents(f.as_fd(), 0, page_size * 16).unwrap();
        assert_eq!(
            extents,
            vec![(page_size * 2, page_size), (page_size * 5, page_size * 2)]
        );
    }

    #[test]
    fn enumeration_respects_window() {
        let f = make_memfd(4096 * 16);
        // Fully populate the file, then leave it as one big data extent.
        f.write_all_at(&vec![0xEEu8; 4096 * 16], 0).unwrap();
        let extents = collect_extents(f.as_fd(), 4096 * 4, 4096 * 8).unwrap();
        assert_eq!(extents, vec![(4096 * 4, 4096 * 4)]);
    }

    #[test]
    fn dense_file_yields_single_extent() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&vec![0xEEu8; 4096 * 8]).unwrap();
        let f = tmp.reopen().unwrap();
        let extents = collect_extents(f.as_fd(), 0, 4096 * 8).unwrap();
        assert_eq!(extents, vec![(0, 4096 * 8)]);
    }

    #[test]
    fn sparse_file_yields_extents_at_written_positions() {
        let page_size = get_page_size();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let f = tmp.reopen().unwrap();
        sparse_layout(&f, page_size * 16, &[(page_size * 4, page_size * 2, 0x55)]);
        let extents = collect_extents(f.as_fd(), 0, page_size * 16).unwrap();
        assert_eq!(extents, vec![(page_size * 4, page_size * 2)]);
    }

    #[test]
    fn single_extent_at_zero_offset() {
        let page_size = get_page_size();
        let src = make_memfd(0);
        sparse_layout(
            &src,
            page_size * 16,
            &[(page_size * 3, page_size * 2, 0x42)],
        );

        // Pre-fill dst with a sentinel byte so we can verify that
        // write_region_sparse only wrote where the source had data: any
        // byte outside the source-data extent must remain the sentinel.
        // This is FS-independent (does not depend on whether the dst
        // filesystem reports holes after a partial write).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        dst.write_all_at(&vec![0xFE; (page_size * 16) as usize], 0)
            .unwrap();

        let used = write_region_sparse(&src, 0, &dst, 0, page_size * 16).unwrap();
        assert!(used);

        let buf = fs::read(tmp.path()).unwrap();
        assert!(buf[..(page_size * 3) as usize].iter().all(|&b| b == 0xFE));
        assert!(
            buf[(page_size * 3) as usize..(page_size * 5) as usize]
                .iter()
                .all(|&b| b == 0x42)
        );
        assert!(buf[(page_size * 5) as usize..].iter().all(|&b| b == 0xFE));
    }

    #[test]
    fn two_regions_in_same_destination_file_at_dst_offset() {
        let src_a = make_memfd(0);
        sparse_layout(&src_a, 4096 * 16, &[(4096, 4096 * 2, 0xAA)]);
        let src_b = make_memfd(0);
        sparse_layout(&src_b, 4096 * 16, &[(4096 * 5, 4096 * 3, 0xBB)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        sparse_layout(&dst, 4096 * 32, &[]);

        let _ = write_region_sparse(&src_a, 0, &dst, 0, 4096 * 16).unwrap();
        let _ = write_region_sparse(&src_b, 0, &dst, 4096 * 16, 4096 * 16).unwrap();

        let buf = fs::read(tmp.path()).unwrap();
        assert!(buf[..4096].iter().all(|&b| b == 0));
        assert!(buf[4096..4096 * 3].iter().all(|&b| b == 0xAA));
        assert!(buf[4096 * 3..4096 * 16].iter().all(|&b| b == 0));
        assert!(buf[4096 * 16..4096 * 21].iter().all(|&b| b == 0));
        assert!(buf[4096 * 21..4096 * 24].iter().all(|&b| b == 0xBB));
        assert!(buf[4096 * 24..].iter().all(|&b| b == 0));
    }

    #[test]
    fn extent_at_non_zero_src_offset() {
        let src = make_memfd(0);
        sparse_layout(&src, 4096 * 32, &[(4096 * 20, 4096 * 2, 0x77)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        sparse_layout(&dst, 4096 * 16, &[]);

        let used = write_region_sparse(&src, 4096 * 16, &dst, 0, 4096 * 16).unwrap();
        assert!(used);

        let buf = fs::read(tmp.path()).unwrap();
        assert!(buf[..4096 * 4].iter().all(|&b| b == 0));
        assert!(buf[4096 * 4..4096 * 6].iter().all(|&b| b == 0x77));
        assert!(buf[4096 * 6..].iter().all(|&b| b == 0));
    }

    /// Round-trip: write two regions sparsely into a snapshot file, then
    /// read them back using the same next_data_extent + read_at pattern
    /// that fill_saved_regions uses. Verifies the restore path recovers
    /// the original content including holes.
    #[test]
    fn round_trip_sparse_write_then_read() {
        let src_a = make_memfd(0);
        sparse_layout(&src_a, 4096 * 16, &[(4096 * 2, 4096 * 3, 0xAA)]);

        let src_b = make_memfd(0);
        sparse_layout(&src_b, 4096 * 16, &[(4096 * 10, 4096 * 4, 0xBB)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        let total = 4096u64 * 32;
        sparse_layout(&dst, total, &[]);

        write_region_sparse(&src_a, 0, &dst, 0, 4096 * 16).unwrap();
        write_region_sparse(&src_b, 0, &dst, 4096 * 16, 4096 * 16).unwrap();

        // Read back using next_data_extent + read_at, mirroring
        // fill_saved_regions's sparse restore path.
        let snap = tmp.reopen().unwrap();
        let regions: Vec<(u64, u64)> = vec![(0, 4096 * 16), (4096 * 16, 4096 * 16)];
        let mut restored = vec![0u8; total as usize];

        for &(file_cursor, region_len) in &regions {
            let end = file_cursor + region_len;
            let mut cursor = file_cursor;
            while let Some((data_off, ext_len)) =
                next_data_extent(snap.as_fd(), cursor, end).unwrap()
            {
                let in_region = (data_off - file_cursor) as usize;
                let dst_start = file_cursor as usize + in_region;
                snap.read_at(
                    &mut restored[dst_start..dst_start + ext_len as usize],
                    data_off,
                )
                .unwrap();
                cursor = data_off + ext_len;
            }
        }

        // Verify content matches a dense read.
        let dense = fs::read(tmp.path()).unwrap();
        assert_eq!(restored, dense);

        // Verify the actual data landed in the right places.
        assert!(restored[..4096 * 2].iter().all(|&b| b == 0));
        assert!(restored[4096 * 2..4096 * 5].iter().all(|&b| b == 0xAA));
        assert!(restored[4096 * 5..4096 * 26].iter().all(|&b| b == 0));
        assert!(restored[4096 * 26..4096 * 30].iter().all(|&b| b == 0xBB));
        assert!(restored[4096 * 30..].iter().all(|&b| b == 0));
    }
}

/// Patch a reflink clone from frozen guest bytes. Equality is checked against
/// the clone, not dirty bits, covering both device and vCPU writes and zeroes.
/// The caller must keep the VM quiesced until its ordinary persistence barrier.
pub fn write_memory_delta_from_clone(
    destination: &File,
    destination_offset: u64,
    length: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut guest = vec![0; 1024 * 1024];
    let mut base = vec![0; guest.len()];
    let mut offset = 0;
    let mut written = 0;
    while offset < length {
        let count = (length - offset).min(guest.len() as u64) as usize;
        read(offset, &mut guest[..count])?;
        // Do not populate page cache for the clone's holes. Reading every hole
        // would allocate cache for the entire configured RAM, even though the
        // snapshot is sparse. SEEK_DATA is only an optimization; unsupported
        // filesystems still use a complete, byte-correct read.
        base[..count].fill(0);
        let begin = destination_offset + offset;
        let end = begin + count as u64;
        let mut cursor = begin;
        while cursor < end {
            match next_data_extent(destination.as_fd(), cursor, end) {
                Ok(Some((data, len))) => {
                    let start = (data - begin) as usize;
                    destination.read_exact_at(&mut base[start..start + len as usize], data)?;
                    cursor = data + len;
                }
                Ok(None) => break,
                Err(_) => {
                    destination.read_exact_at(&mut base[..count], begin)?;
                    break;
                }
            }
        }
        let mut run = None;
        for start in (0..count).step_by(4096) {
            let end = (start + 4096).min(count);
            if guest[start..end] != base[start..end] {
                run.get_or_insert(start);
            } else if let Some(begin) = run.take() {
                destination.write_all_at(
                    &guest[begin..start],
                    destination_offset + offset + begin as u64,
                )?;
                written += (start - begin) as u64;
            }
        }
        if let Some(begin) = run {
            destination.write_all_at(
                &guest[begin..count],
                destination_offset + offset + begin as u64,
            )?;
            written += (count - begin) as u64;
        }
        offset += count as u64;
    }
    Ok(written)
}

#[cfg(test)]
mod clone_delta_tests {
    use super::*;
    #[test]
    fn patches_zero_nonzero_and_partial_pages_without_changing_baseline() {
        let base = tempfile::tempfile().unwrap();
        let output = tempfile::tempfile().unwrap();
        let original = vec![0x73; 3 * 4096 + 29];
        base.write_all_at(&original, 0).unwrap();
        output.write_all_at(&original, 0).unwrap();
        let mut guest = original.clone();
        guest[..4096].fill(0);
        guest[8192..].fill(0x92);
        let written = write_memory_delta_from_clone(&output, 0, guest.len() as u64, |o, b| {
            b.copy_from_slice(&guest[o as usize..o as usize + b.len()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(written, (8192 + 29) as u64);
        let mut actual = vec![0; guest.len()];
        output.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, guest);
        base.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, original);
        assert_eq!(
            write_memory_delta_from_clone(&output, 0, guest.len() as u64, |o, b| {
                b.copy_from_slice(&guest[o as usize..o as usize + b.len()]);
                Ok(())
            })
            .unwrap(),
            0
        );
    }
    #[test]
    fn sparse_baseline_holes_and_data_match_frozen_memory() {
        let output = tempfile::tempfile().unwrap();
        let mut guest = vec![0; 3 * 1024 * 1024];
        output.set_len(guest.len() as u64).unwrap();
        output.write_all_at(&[7; 4096], 1024 * 1024 + 4096).unwrap();
        guest[1024 * 1024 + 4096..1024 * 1024 + 8192].fill(7);
        guest[..4096].fill(5);
        let written = write_memory_delta_from_clone(&output, 0, guest.len() as u64, |o, b| {
            b.copy_from_slice(&guest[o as usize..o as usize + b.len()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(written, 4096);
        let mut actual = vec![0; guest.len()];
        output.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, guest);
    }
    #[test]
    fn read_failure_is_not_reported_as_a_complete_snapshot() {
        let output = tempfile::tempfile().unwrap();
        output.set_len(4096).unwrap();
        assert!(
            write_memory_delta_from_clone(&output, 0, 4096, |_, _| Err(io::Error::other(
                "injected"
            )))
            .is_err()
        );
    }
}
