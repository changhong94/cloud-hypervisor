// SPDX-License-Identifier: Apache-2.0
//! Native Kuasar disk transport. Guest memory and virtqueues stay in the VMM;
//! only bounded disk payloads cross the socket to the native CoW disk owner.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, BorrowedDiskFd,
    CompletionCommon,
};
use crate::disk_file::*;
use crate::error::{BlockError, BlockErrorKind, BlockResult};

fn block_error(e: io::Error) -> BlockError {
    BlockError::new(BlockErrorKind::Io, e)
}
#[derive(Debug, Clone)]
pub struct NativeDisk {
    stats: Arc<NativeReadStats>,
    path: PathBuf,
    lock_file: Arc<File>,
    stream: Arc<Mutex<Option<NativeConnection>>>,
    size: Arc<AtomicU64>,
    readonly: bool,
    max_io: usize,
}
#[derive(Debug, Default)]
struct NativeReadStats {
    count: AtomicU64,
    direct: AtomicU64,
    bytes: AtomicU64,
    elapsed_ns: AtomicU64,
}
#[derive(Debug)]
struct NativeConnection {
    stream: UnixStream,
    local: Option<NativeLocalRead>,
}
#[derive(Debug)]
struct NativeLocalRead {
    file: File,
    extents: Vec<(u64, u64, u64)>,
}
impl NativeLocalRead {
    fn receive(stream: &mut UnixStream, size: u64) -> io::Result<Self> {
        let mut marker = [0];
        let (n, file) = stream.recv_with_fd(&mut marker)?;
        let file = file.ok_or_else(|| io::Error::other("Missing native local read fd"))?;
        if n != 1 || marker != [1] {
            return Err(io::Error::other("Invalid native local handoff"));
        }
        // SAFETY: file owns this descriptor throughout both fcntl calls.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: setting close-on-exec on the newly received, owned fd.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let info = file.metadata()?;
        if flags & libc::O_ACCMODE != libc::O_RDONLY || !info.is_file() {
            return Err(io::Error::other(
                "Native local read fd is not read-only regular file",
            ));
        }
        let mut word = [0; 8];
        stream.read_exact(&mut word)?;
        let count = u64::from_be_bytes(word);
        if count == 0 || count > 1 << 20 {
            return Err(io::Error::other("Invalid native local extent count"));
        }
        let mut extents = Vec::new();
        let mut end = 0;
        for _ in 0..count {
            let mut wire = [0; 24];
            stream.read_exact(&mut wire)?;
            let start = u64::from_be_bytes(wire[..8].try_into().unwrap());
            let length = u64::from_be_bytes(wire[8..16].try_into().unwrap());
            let physical = u64::from_be_bytes(wire[16..].try_into().unwrap());
            if start < end
                || start > size
                || length == 0
                || length > size - start
                || physical > info.len()
                || length > info.len() - physical
            {
                return Err(io::Error::other("Invalid native local read extent"));
            }
            end = start + length;
            extents.push((start, length, physical));
        }
        Ok(Self { file, extents })
    }
    fn read_if_covered(&self, data: &mut [u8], offset: u64) -> io::Result<bool> {
        let i = self
            .extents
            .partition_point(|(start, length, _)| start + length <= offset);
        if let Some(&(start, length, physical)) = self.extents.get(i)
            && offset >= start
            && data.len() as u64 <= start + length - offset
        {
            self.file.read_exact_at(data, physical + (offset - start))?;
            return Ok(true);
        }
        Ok(false)
    }
}
impl Drop for NativeDisk {
    fn drop(&mut self) {
        if Arc::strong_count(&self.stats) == 1 && self.stats.count.load(Ordering::Relaxed) != 0 {
            eprintln!(
                "NATIVE_DISK_READ_STATS path={} requests={} direct_requests={} bytes={} total_us={}",
                self.path.display(),
                self.stats.count.load(Ordering::Relaxed),
                self.stats.direct.load(Ordering::Relaxed),
                self.stats.bytes.load(Ordering::Relaxed),
                self.stats.elapsed_ns.load(Ordering::Relaxed) / 1000
            );
        }
    }
}
impl NativeDisk {
    pub fn open(path: &Path, readonly: bool) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut hello = [0u8; 24];
        stream.read_exact(&mut hello)?;
        let size = u64::from_be_bytes(hello[8..16].try_into().unwrap());
        let flags = u32::from_be_bytes(hello[16..20].try_into().unwrap());
        let max_io = u32::from_be_bytes(hello[20..24].try_into().unwrap()) as usize;
        if &hello[..8] != b"KBLK0001"
            || size % 512 != 0
            || flags & !3 != 0
            || (flags & 1 == 1) != readonly
            || (flags & 2 != 0 && !readonly)
            || !(512..=1048576).contains(&max_io)
            || max_io % 512 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native disk handshake mismatch",
            ));
        }
        let local = if flags & 2 != 0 {
            Some(NativeLocalRead::receive(&mut stream, size)?)
        } else {
            None
        };
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new(&lock_path))?;
        Ok(Self {
            stats: Arc::new(NativeReadStats::default()),
            path: path.to_owned(),
            lock_file: Arc::new(lock_file),
            stream: Arc::new(Mutex::new(Some(NativeConnection { stream, local }))),
            size: Arc::new(AtomicU64::new(size)),
            readonly,
            max_io,
        })
    }
    #[cfg(test)]
    fn reconnect(&self) -> io::Result<Self> {
        let next = Self::open(&self.path, self.readonly)?;
        if next.size.load(Ordering::Acquire) != self.size.load(Ordering::Acquire) {
            return Err(io::Error::other("native disk geometry changed"));
        }
        Ok(next)
    }
    fn request(&self, op: u32, offset: u64, data: &mut [u8]) -> io::Result<()> {
        let size = self.size.load(Ordering::Acquire);
        if data.len() > self.max_io
            || offset > size
            || data.len() as u64 > size - offset
            || (op != 2 && (offset % 512 != 0 || data.is_empty() || data.len() % 512 != 0))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native disk bounds",
            ));
        }
        if op == 1 && self.readonly {
            return Err(io::Error::from_raw_os_error(libc::EROFS));
        }
        let started = std::time::Instant::now();
        let mut guard = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("native disk lock poisoned"))?;
        let connection = guard
            .as_mut()
            .ok_or_else(|| io::Error::other("native disk connection failed"))?;
        // Resize swaps the connection and geometry under this same lock.
        let size = self.size.load(Ordering::Acquire);
        if offset > size || data.len() as u64 > size - offset {
            return Err(io::Error::other("Native disk resized outside request"));
        }
        let local = &connection.local;
        let stream = &mut connection.stream;
        let mut framed_reply = false;
        let mut h = [0u8; 24];
        h[..4].copy_from_slice(&op.to_be_bytes());
        h[4..8].copy_from_slice(&(data.len() as u32).to_be_bytes());
        h[8..16].copy_from_slice(&offset.to_be_bytes());
        // One outstanding operation per connection; cookie still validates framing.
        h[16..].copy_from_slice(&1u64.to_be_bytes());
        let result = (|| {
            if op == 0
                && let Some(local) = local
            {
                // A failed direct read is retried through the original owner:
                // its retry classification and OnReadFatal policy remain
                // authoritative. No write/flush ever bypasses that owner.
                if local.read_if_covered(data, offset).unwrap_or(false) {
                    self.stats.direct.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
            }
            stream.write_all(&h)?;
            if op == 1 {
                stream.write_all(data)?;
            }
            let mut reply = [0u8; 16];
            stream.read_exact(&mut reply)?;
            let error = u32::from_be_bytes(reply[..4].try_into().unwrap());
            let length = u32::from_be_bytes(reply[4..8].try_into().unwrap()) as usize;
            if reply[8..] != h[16..] || length != if error == 0 && op == 0 { data.len() } else { 0 }
            {
                return Err(io::Error::other("native disk reply mismatch"));
            }
            if error != 0 {
                framed_reply = true;
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            if op == 0 {
                stream.read_exact(data)?;
            }
            Ok(())
        })();
        // A failed request is never retried: a write may already be committed.
        // A fully framed backend error leaves the connection usable (e.g.
        // partition probes before the image is bound). Transport errors close it.
        // Close the stream so no subsequent command can consume stale framing.
        if result.is_err() && !framed_reply {
            guard.take();
        }
        if op == 0 {
            self.stats.count.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            self.stats
                .elapsed_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        result
    }
}
impl DiskSize for NativeDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.size.load(Ordering::Acquire))
    }
}
impl PhysicalSize for NativeDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        Err(block_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "native disk allocation is owned by sandboxer",
        )))
    }
}
impl DiskFd for NativeDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.lock_file.as_raw_fd())
    }
}
impl Geometry for NativeDisk {}
impl SparseCapable for NativeDisk {}
impl Resizable for NativeDisk {
    fn resize(&mut self, new_size: u64) -> BlockResult<()> {
        // Only accept geometry already committed by the native disk owner.
        // Every async queue clone observes the same capacity after publication.
        let next = Self::open(&self.path, self.readonly).map_err(block_error)?;
        if next.size.load(Ordering::Acquire) != new_size {
            return Err(block_error(io::Error::other(
                "Native resize differs from committed backend geometry",
            )));
        }
        let connection = next
            .stream
            .lock()
            .map_err(|_| block_error(io::Error::other("Native new connection poisoned")))?
            .take();
        let mut current = self
            .stream
            .lock()
            .map_err(|_| block_error(io::Error::other("Native connection poisoned")))?;
        *current = connection;
        self.size.store(new_size, Ordering::Release);
        Ok(())
    }
}
impl MetadataSync for NativeDisk {
    fn sync_metadata(&self) -> BlockResult<()> {
        self.request(2, 0, &mut []).map_err(block_error)
    }
}
impl DiskFile for NativeDisk {}
impl AsyncDiskFile for NativeDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn AsyncDiskFile>> {
        Ok(Box::new(self.clone()))
    }
    fn create_async_io(&self, _: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(NativeIo {
            disk: self.clone(),
            completions: CompletionCommon::new(),
        }))
    }
}
struct NativeIo {
    disk: NativeDisk,
    completions: CompletionCommon,
}
impl AsyncIo for NativeIo {
    fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }
    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let read = op.is_read();
        let mut offset = op.offset();
        let error = |e| {
            if read {
                AsyncIoError::ReadVectored(e)
            } else {
                AsyncIoError::WriteVectored(e)
            }
        };
        if offset < 0 {
            return Err(error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "negative disk offset",
            )));
        }
        let total = op
            .iovecs()
            .iter()
            .try_fold(0usize, |sum, v| sum.checked_add(v.iov_len))
            .ok_or_else(|| error(io::Error::other("disk length overflow")))?;
        if total == 0 || total > 16 * 1048576 || total % 512 != 0 {
            return Err(error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid operation length",
            )));
        }
        let mut payload = vec![0u8; total];
        if !read {
            let mut pos = 0;
            for v in op.iovecs() {
                if v.iov_len == 0 {
                    continue;
                }
                // SAFETY: the operation retains the iovec memory through completion.
                let data =
                    unsafe { std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len) };
                payload[pos..pos + data.len()].copy_from_slice(data);
                pos += data.len();
            }
        }
        for chunk in payload.chunks_mut(self.disk.max_io) {
            self.disk
                .request(if read { 0 } else { 1 }, offset as u64, chunk)
                .map_err(&error)?;
            offset = offset
                .checked_add(chunk.len() as i64)
                .ok_or_else(|| error(io::Error::other("disk offset overflow")))?;
        }
        if read {
            let mut pos = 0;
            for v in op.iovecs() {
                if v.iov_len == 0 {
                    continue;
                }
                // SAFETY: read operations own writable memory for each retained iovec.
                let data =
                    unsafe { std::slice::from_raw_parts_mut(v.iov_base.cast::<u8>(), v.iov_len) };
                data.copy_from_slice(&payload[pos..pos + data.len()]);
                pos += data.len();
            }
        }
        let total = i32::try_from(total)
            .map_err(|_| error(io::Error::other("disk completion overflow")))?;
        self.completions
            .complete(AsyncIoCompletion::from_operation(op, total));
        Ok(())
    }
    fn fsync(&mut self, id: Option<u64>) -> AsyncIoResult<()> {
        self.disk
            .request(2, 0, &mut [])
            .map_err(AsyncIoError::Fsync)?;
        if let Some(id) = id {
            self.completions
                .complete(AsyncIoCompletion::new(id, 0, None));
        }
        Ok(())
    }
    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completions.next_completed()
    }
    fn punch_hole(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::PunchHole(io::Error::new(
            io::ErrorKind::Unsupported,
            "discard not advertised",
        )))
    }
    fn write_zeroes(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(io::Error::new(
            io::ErrorKind::Unsupported,
            "zeroes not advertised",
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;
    #[test]
    fn native_local_read_is_adopted_on_resize_and_errors_return_to_owner() {
        let directory =
            vmm_sys_util::tempdir::TempDir::new_with_prefix("/tmp/native-local-read").unwrap();
        let path = directory.as_path().join("disk.sock");
        let image = directory.as_path().join("image");
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&image)
            .unwrap();
        writer.write_all_at(&[0x53; 4099], 0).unwrap();
        let file = File::open(&image).unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            for (size, flags) in [(0u64, 1u32), (4096, 3)] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut hello = [0u8; 24];
                hello[..8].copy_from_slice(b"KBLK0001");
                hello[8..16].copy_from_slice(&size.to_be_bytes());
                hello[16..20].copy_from_slice(&flags.to_be_bytes());
                hello[20..].copy_from_slice(&1048576u32.to_be_bytes());
                stream.write_all(&hello).unwrap();
                if flags == 3 {
                    stream.send_with_fd(&[1u8][..], file.as_raw_fd()).unwrap();
                    for value in [1u64, 0, 4096, 3] {
                        stream.write_all(&value.to_be_bytes()).unwrap();
                    }
                    for op in [0u32, 2] {
                        let mut request = [0; 24];
                        stream.read_exact(&mut request).unwrap();
                        assert_eq!(u32::from_be_bytes(request[..4].try_into().unwrap()), op);
                        let mut reply = [0; 16];
                        reply[8..].copy_from_slice(&request[16..]);
                        if op == 0 {
                            reply[..4].copy_from_slice(&(libc::EIO as u32).to_be_bytes());
                        }
                        stream.write_all(&reply).unwrap();
                    }
                }
            }
        });
        let mut disk = NativeDisk::open(&path, true).unwrap();
        let queue = disk.clone();
        disk.resize(4096).unwrap();
        let mut payload = [0; 512];
        queue.request(0, 512, &mut payload).unwrap();
        assert_eq!(payload, [0x53; 512]); // no RPC: first server request is only after truncation
        writer.set_len(2).unwrap();
        assert_eq!(
            queue
                .request(0, 512, &mut payload)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        queue.request(2, 0, &mut []).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn native_resize_requires_committed_geometry_and_updates_queue_clones() {
        let directory =
            vmm_sys_util::tempdir::TempDir::new_with_prefix("/tmp/native-resize-test").unwrap();
        let path = directory.as_path().join("disk.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            for size in [0u64, 4096, 4096] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut hello = [0u8; 24];
                hello[..8].copy_from_slice(b"KBLK0001");
                hello[8..16].copy_from_slice(&size.to_be_bytes());
                hello[20..].copy_from_slice(&1048576u32.to_be_bytes());
                stream.write_all(&hello).unwrap();
            }
        });
        let mut disk = NativeDisk::open(&path, false).unwrap();
        let queue = disk.clone();
        assert_eq!(disk.size.load(Ordering::Acquire), 0);
        assert!(disk.resize(8192).is_err());
        assert_eq!(queue.size.load(Ordering::Acquire), 0);
        disk.resize(4096).unwrap();
        assert_eq!(queue.size.load(Ordering::Acquire), 4096);
        worker.join().unwrap();
    }
    #[test]
    fn native_export_roundtrip() {
        use std::os::unix::net::UnixListener;
        let directory =
            vmm_sys_util::tempdir::TempDir::new_with_prefix("/tmp/native-disk-test").unwrap();
        let path = directory.as_path().join("disk.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let bytes = Arc::new(Mutex::new(vec![0u8; 4096]));
        let server = std::thread::spawn(move || {
            let mut workers = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let bytes = bytes.clone();
                workers.push(std::thread::spawn(move || {
                    let mut hello = [0u8; 24];
                    hello[..8].copy_from_slice(b"KBLK0001");
                    hello[8..16].copy_from_slice(&4096u64.to_be_bytes());
                    hello[20..].copy_from_slice(&1048576u32.to_be_bytes());
                    stream.write_all(&hello).unwrap();
                    loop {
                        let mut request = [0u8; 24];
                        if stream.read_exact(&mut request).is_err() {
                            break;
                        }
                        let op = u32::from_be_bytes(request[..4].try_into().unwrap());
                        let length = u32::from_be_bytes(request[4..8].try_into().unwrap()) as usize;
                        let offset =
                            u64::from_be_bytes(request[8..16].try_into().unwrap()) as usize;
                        let mut data = bytes.lock().unwrap();
                        if op == 1 {
                            stream
                                .read_exact(&mut data[offset..offset + length])
                                .unwrap();
                        }
                        let mut reply = [0u8; 16];
                        if op == 0 {
                            reply[4..8].copy_from_slice(&(length as u32).to_be_bytes());
                        }
                        reply[8..].copy_from_slice(&request[16..]);
                        stream.write_all(&reply).unwrap();
                        if op == 0 {
                            stream.write_all(&data[offset..offset + length]).unwrap();
                        }
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let disk = NativeDisk::open(&path, false).unwrap();
        assert!(NativeDisk::open(&path, true).is_err());
        let mut payload = vec![83u8; 512];
        disk.request(1, 512, &mut payload).unwrap();
        disk.request(2, 0, &mut []).unwrap();
        let reader = disk.reconnect().unwrap();
        let mut got = vec![0; 512];
        reader.request(0, 512, &mut got).unwrap();
        assert_eq!(got, payload);
        assert!(
            reader
                .request(0, reader.size.load(Ordering::Acquire), &mut got)
                .is_err()
        );
        // Rejected local bounds must not desynchronize a healthy connection.
        reader.request(0, 512, &mut got).unwrap();
        assert_eq!(got, payload);
        drop(reader);
        drop(disk);
        server.join().unwrap();
    }
}
