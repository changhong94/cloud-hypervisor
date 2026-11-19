// SPDX-License-Identifier: Apache-2.0
//! Immutable Manifest-backed RAW base for QCOW2. The descriptor is host-owned;
//! guest writes never reach this reader. Data is authenticated by the accelerator.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

const MAGIC: &[u8; 8] = b"KSMAN001";
#[derive(Clone, Debug)]
pub struct Descriptor {
    pub size: u64,
    graph: bool,
    key: [u8; 64],
    socket: String,
}
impl Descriptor {
    pub fn read(file: &crate::AlignedFile) -> io::Result<Option<Self>> {
        let mut marker = [0u8; 1];
        // SAFETY: valid borrowed fd, NUL-terminated name, one-byte output buffer.
        let n = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c"user.kuasar.manifest".as_ptr(),
                marker.as_mut_ptr().cast(),
                1,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
                return Ok(None);
            }
            return Err(e);
        }
        if n != 1 || (marker != [1] && marker != [2]) {
            return Err(io::Error::other("Invalid Manifest disk marker"));
        }
        let mut header = [0; 82];
        file.read_exact_at(&mut header, 0)?;
        if &header[..8] != MAGIC {
            return Err(io::Error::other("Invalid Manifest disk magic"));
        }
        let size = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let key: [u8; 64] = header[16..80].try_into().unwrap();
        let len = u16::from_le_bytes(header[80..82].try_into().unwrap()) as usize;
        if size == 0
            || size % 512 != 0
            || len == 0
            || len >= 108
            || !key.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(io::Error::other("Invalid Manifest disk descriptor"));
        }
        let mut socket = vec![0; len];
        file.read_exact_at(&mut socket, 82)?;
        let socket = String::from_utf8(socket).map_err(io::Error::other)?;
        if !socket.starts_with('/') || socket.contains('\0') {
            return Err(io::Error::other("Invalid Manifest socket"));
        }
        Ok(Some(Self {
            size,
            key,
            socket,
            graph: marker == [2],
        }))
    }
}
#[derive(Debug)]
pub(crate) struct Reader {
    descriptor: Descriptor,
    connection: Mutex<Option<(u32, UnixStream)>>,
}
impl Reader {
    pub(crate) fn new(descriptor: Descriptor) -> io::Result<Self> {
        let stream = Self::connect(&descriptor)?;
        Ok(Self {
            descriptor,
            connection: Mutex::new(Some((std::process::id(), stream))),
        })
    }
    fn connect(d: &Descriptor) -> io::Result<UnixStream> {
        let mut stream = UnixStream::connect(&d.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(35)))?;
        stream.set_write_timeout(Some(Duration::from_secs(35)))?;
        stream.write_all(&d.key)?;
        stream.write_all(&[u8::from(d.graph)])?;
        let mut value = [0; 8];
        stream.read_exact(&mut value)?;
        if u64::from_le_bytes(value) != d.size {
            return Err(io::Error::other("Manifest disk size mismatch"));
        }
        stream.read_exact(&mut value)?;
        let count = u64::from_le_bytes(value);
        if count > 1 << 20 {
            return Err(io::Error::other("Too many Manifest extents"));
        }
        let mut end = 0;
        for _ in 0..count {
            stream.read_exact(&mut value)?;
            let start = u64::from_le_bytes(value);
            stream.read_exact(&mut value)?;
            let len = u64::from_le_bytes(value);
            if start < end || start > d.size || len == 0 || len > d.size - start {
                return Err(io::Error::other("Invalid Manifest extent"));
            }
            end = start + len;
        }
        Ok(stream)
    }
    pub(crate) fn read_at(&self, mut offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset > self.descriptor.size || buf.len() as u64 > self.descriptor.size - offset {
            return Err(io::Error::other("Manifest read outside disk"));
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("Manifest connection poisoned"))?;
        // Never share a framed stream between host-fork parent and child. The
        // fork barrier has joined disk workers before this mutex is inherited.
        let pid = std::process::id();
        if connection.as_ref().is_none_or(|(owner, _)| *owner != pid) {
            *connection = None; // close inherited fd; do not shutdown parent's socket
            *connection = Some((pid, Self::connect(&self.descriptor)?));
        }
        let result = (|| {
            let stream = &mut connection.as_mut().unwrap().1;
            for chunk in buf.chunks_mut(2 << 20) {
                let n = chunk.len();
                stream.write_all(&offset.to_le_bytes())?;
                stream.write_all(&(n as u64).to_le_bytes())?;
                stream.read_exact(chunk)?;
                offset += n as u64;
            }
            Ok(())
        })();
        if result.is_err() {
            *connection = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn guest_bytes_cannot_enable_a_manifest_descriptor() {
        let temp = TempFile::new().unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend(512u64.to_le_bytes());
        bytes.extend([b'a'; 64]);
        bytes.extend(9u16.to_le_bytes());
        bytes.extend(b"/tmp/test");
        temp.as_file().write_all_at(&bytes, 0).unwrap();
        let file = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        assert!(Descriptor::read(&file).unwrap().is_none());
        let marker = [1u8];
        // SAFETY: valid fd, attribute string and one-byte marker buffer.
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    temp.as_file().as_raw_fd(),
                    c"user.kuasar.manifest".as_ptr(),
                    marker.as_ptr().cast(),
                    1,
                    0,
                )
            },
            0
        );
        assert_eq!(Descriptor::read(&file).unwrap().unwrap().size, 512);
        temp.as_file()
            .write_all_at(&513u64.to_le_bytes(), 8)
            .unwrap();
        assert!(Descriptor::read(&file).is_err());
    }

    #[test]
    fn process_change_reconnects_and_missing_data_is_an_error() {
        let temp = TempFile::new().unwrap();
        let socket = temp.as_path().with_extension("sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            for value in [1u8, 2, 3] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut key = [0; 65];
                stream.read_exact(&mut key).unwrap();
                assert_eq!(&key[..64], &[b'a'; 64]);
                assert_eq!(key[64], 0);
                stream.write_all(&512u64.to_le_bytes()).unwrap();
                stream.write_all(&0u64.to_le_bytes()).unwrap();
                let mut request = [0; 16];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(u64::from_le_bytes(request[..8].try_into().unwrap()), 32);
                assert_eq!(u64::from_le_bytes(request[8..].try_into().unwrap()), 4);
                if value != 3 {
                    stream.write_all(&[value; 4]).unwrap();
                }
            }
        });
        let reader = Reader::new(Descriptor {
            size: 512,
            graph: false,
            key: [b'a'; 64],
            socket: socket.to_str().unwrap().to_owned(),
        })
        .unwrap();
        let mut buf = [0; 4];
        assert!(reader.read_at(510, &mut buf).is_err());
        reader.read_at(32, &mut buf).unwrap();
        assert_eq!(buf, [1; 4]);
        reader.connection.lock().unwrap().as_mut().unwrap().0 = 0;
        reader.read_at(32, &mut buf).unwrap();
        assert_eq!(buf, [2; 4]);
        reader.connection.lock().unwrap().as_mut().unwrap().0 = 0;
        assert!(reader.read_at(32, &mut buf).is_err());
        assert!(reader.connection.lock().unwrap().is_none());
        server.join().unwrap();
        std::fs::remove_file(socket).unwrap();
    }
}
