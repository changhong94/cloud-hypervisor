// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! In-memory proof that a fresh, unpublished leaf's dirty marker is durable.
//! No proof is persisted: an ordinary reopen after a crash still rebuilds dirty
//! refcounts. Holding a File pins the inode; dropping a proof never writes it.
use std::cell::RefCell;
use std::fs::{File, Metadata};
use std::marker::PhantomData;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::rc::Rc;
use std::sync::Arc;

use super::{BackingFileConfig, QcowHeader, create_image};
use crate::AlignedFile;
use crate::error::{BlockError, BlockErrorKind};

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl From<Metadata> for Identity {
    fn from(m: Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

pub struct PreparedQcowOpen {
    file: File,
    identity: Identity,
    metadata_bytes: Arc<[u8]>,
}

/// Only initialize a new, zero-length file owned exclusively by this caller.
/// Keep the proof unpublished until checkpointing the backing image completes.
pub fn create_prepared_image(
    file: &File,
    size: u64,
    backing: Option<&BackingFileConfig>,
) -> std::io::Result<PreparedQcowOpen> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(std::io::Error::other(
            "Prepared QCOW image must be new and empty",
        ));
    }
    create_image(file, size, backing).map_err(std::io::Error::other)?;
    let mut aligned = AlignedFile::new(file.try_clone()?, false);
    let mut header = QcowHeader::new(&aligned).map_err(std::io::Error::other)?;
    // Move the normal first-writer barrier before VM pause, not remove it.
    header
        .set_dirty_bit(&mut aligned, true)
        .map_err(std::io::Error::other)?;
    file.sync_all()?;
    let mut metadata_bytes = vec![0; file.metadata()?.len().min(1024 * 1024) as usize];
    file.read_exact_at(&mut metadata_bytes, 0)?;
    Ok(PreparedQcowOpen {
        file: file.try_clone()?,
        identity: file.metadata()?.into(),
        metadata_bytes: metadata_bytes.into(),
    })
}

/// A future sealed reader. The caller must finish/drain the live writer and
/// retain its terminal close before publishing this capability to a restore.
/// Only its immutable prefix is opened during preparation. That prefix is read
/// from the current on-disk chain, not inherited recursively from old readers,
/// so compaction bounds both the chain and retained FDs across generations.
pub struct PreparedQcowBacking {
    dev: u64,
    ino: u64,
    depth: u32,
    reader: Arc<super::backing::Qcow2Backing>,
}

pub(super) fn prepare_backing(
    disk: &super::QcowDisk,
) -> crate::error::BlockResult<PreparedQcowBacking> {
    use super::parser::BackingFile;
    let config = disk
        .metadata
        .fork_backing_config()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    let prefix = BackingFile::new(
        config.as_ref(),
        disk.data_raw_file.file().is_direct(),
        super::MAX_NESTING_DEPTH - 1,
        disk.sparse,
    )?;
    let depth = 1 + prefix.as_ref().map_or(0, BackingFile::depth);
    let prefix = prefix
        .map(super::backing::shared_backing_from)
        .transpose()?;
    let data_file = disk
        .data_raw_file
        .file()
        .try_clone()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    let id = data_file
        .metadata()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    Ok(PreparedQcowBacking {
        dev: id.dev(),
        ino: id.ino(),
        depth,
        reader: Arc::new(super::backing::Qcow2Backing {
            metadata: Arc::clone(&disk.metadata),
            cluster_size: disk.metadata.cluster_size(),
            decoder: disk.metadata.decoder(),
            data_file,
            backing_file: prefix,
        }),
    })
}

pub(super) fn take_backing(
    file: &File,
    max_depth: u32,
) -> crate::error::BlockResult<Option<(Arc<dyn super::metadata::BackingRead>, u64, u32)>> {
    if BACKINGS.with(|slot| slot.borrow().is_empty()) {
        return Ok(None);
    }
    let id = file
        .metadata()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    BACKINGS.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(index) = slot
            .iter()
            .position(|view| view.dev == id.dev() && view.ino == id.ino())
        else {
            return Ok(None);
        };
        let view = slot.swap_remove(index);
        if view.depth > max_depth {
            return Err(BlockError::new(
                BlockErrorKind::Overflow,
                super::parser::Error::MaxNestingDepthExceeded,
            ));
        }
        if !view.reader.metadata.fork_close_retained() {
            return Err(BlockError::new(
                BlockErrorKind::Io,
                std::io::Error::other("Fork backing writer was not retired"),
            ));
        }
        let size = view.reader.metadata.virtual_size();
        if std::env::var_os("CH_FORK_TIMING").is_some() {
            use std::io::Write;
            let line = format!(
                "VM_FORK inherited_qcow_backing pid={} inode={} depth={}\n",
                std::process::id(),
                view.ino,
                view.depth
            );
            let _ = std::io::stderr().lock().write_all(line.as_bytes());
        }
        Ok(Some((
            view.reader as Arc<dyn super::metadata::BackingRead>,
            size,
            view.depth,
        )))
    })
}

thread_local! {
    static PREPARED: RefCell<Vec<PreparedQcowOpen>> = const { RefCell::new(Vec::new()) };
    static BACKINGS: RefCell<Vec<PreparedQcowBacking>> = const { RefCell::new(Vec::new()) };
}

/// Restrict capabilities to this restore call and thread. Unused proofs (for
/// the other branch, or after a restore failure) release their FDs on return.
pub struct PreparedQcowScope(PhantomData<Rc<()>>);
impl PreparedQcowScope {
    pub fn enter(proofs: Vec<PreparedQcowOpen>) -> Self {
        Self::enter_with_backings(proofs, Vec::new())
    }

    pub fn enter_with_backings(
        proofs: Vec<PreparedQcowOpen>,
        backings: Vec<PreparedQcowBacking>,
    ) -> Self {
        BACKINGS.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_empty(), "Nested prepared backing restore");
            *slot = backings;
        });
        PREPARED.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_empty(), "Nested prepared QCOW restore");
            *slot = proofs;
        });
        Self(PhantomData)
    }
}
impl Drop for PreparedQcowScope {
    fn drop(&mut self) {
        PREPARED.with(|slot| slot.borrow_mut().clear());
        BACKINGS.with(|slot| slot.borrow_mut().clear());
    }
}

pub(super) fn consume_metadata(file: &File) -> Result<Option<Arc<[u8]>>, BlockError> {
    if PREPARED.with(|p| p.borrow().is_empty()) {
        return Ok(None);
    }
    let identity: Identity = file
        .metadata()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?
        .into();
    PREPARED.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(index) = slot
            .iter()
            .position(|p| p.identity.dev == identity.dev && p.identity.ino == identity.ino)
        else {
            return Ok(None);
        };
        let proof = slot.swap_remove(index);
        let pinned: Identity = proof
            .file
            .metadata()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?
            .into();
        if proof.identity != identity || pinned != identity {
            return Err(BlockError::new(
                BlockErrorKind::CorruptImage,
                std::io::Error::other("Prepared QCOW image changed before activation"),
            ));
        }
        if std::env::var_os("CH_FORK_TIMING").is_some() {
            use std::io::Write;
            let line = format!(
                "VM_FORK prepared_qcow_open pid={} inode={}\n",
                std::process::id(),
                identity.ino
            );
            let _ = std::io::stderr().lock().write_all(line.as_bytes());
        }
        // The proof is single-use, scoped to a freshly initialized, unchanged
        // image. All ordinary parsing and backing-file validation still run.
        Ok(Some(proof.metadata_bytes))
    })
}

#[cfg(test)]
fn consume(file: &File) -> Result<bool, BlockError> {
    consume_metadata(file).map(|metadata| metadata.is_some())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::super::QcowDisk;
    use super::*;

    #[test]
    fn inherited_reader_uses_final_checkpoint_and_does_not_retain_old_prefix() {
        use crate::disk_file::MetadataSync;
        let directory =
            vmm_sys_util::tempdir::TempDir::new_with_prefix("/tmp/ch-fork-reader").unwrap();
        let base = directory.as_path().join("base.raw");
        std::fs::write(&base, vec![0x11; 1024 * 1024]).unwrap();
        let root_path = directory.as_path().join("root.qcow2");
        let root_file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&root_path)
            .unwrap();
        create_image(
            &root_file,
            1024 * 1024,
            Some(&BackingFileConfig {
                path: base.to_string_lossy().into_owned(),
                format: Some(super::super::header::ImageType::Raw),
            }),
        )
        .unwrap();
        let disk = QcowDisk::new(root_file, false, true, true, false).unwrap();
        let old_prefix = Arc::downgrade(disk.backing_file.as_ref().unwrap());
        disk.write_all_at(65536, &vec![0x22; 4096]);
        disk.sync_metadata().unwrap();
        let view = disk.prepare_fork_backing().unwrap().unwrap();
        assert_eq!(view.depth, 2);
        // Preparation cannot freeze live state: these later writes must be
        // present in the inherited reader after the final checkpoint.
        disk.write_all_at(65536, &vec![0x33; 4096]);
        disk.write_all_at(131072, &vec![0x44; 4096]);
        disk.sync_metadata().unwrap();
        let retirement = disk.defer_fork_shutdown().unwrap();
        let leaf = TempFile::new().unwrap().into_file();
        let proof = create_prepared_image(
            &leaf,
            1024 * 1024,
            Some(&BackingFileConfig {
                path: root_path.to_string_lossy().into_owned(),
                format: Some(super::super::header::ImageType::Qcow2),
            }),
        )
        .unwrap();
        let scope = PreparedQcowScope::enter_with_backings(vec![proof], vec![view]);
        let child = QcowDisk::new(leaf, false, true, true, false).unwrap();
        assert!(BACKINGS.with(|slot| slot.borrow().is_empty()));
        drop(scope);
        drop(disk);
        assert!(
            old_prefix.upgrade().is_none(),
            "old prefix must not accumulate across forks"
        );
        retirement.finish().unwrap();
        drop(retirement);
        assert_eq!(child.read_all_at(0, 4096), vec![0x11; 4096]);
        assert_eq!(child.read_all_at(65536, 4096), vec![0x33; 4096]);
        assert_eq!(child.read_all_at(131072, 4096), vec![0x44; 4096]);
        child.write_all_at(65536, &vec![0x55; 4096]);
        child.sync_metadata().unwrap();
        let root = QcowDisk::new(File::open(root_path).unwrap(), false, true, true, false).unwrap();
        assert_eq!(root.read_all_at(65536, 4096), vec![0x33; 4096]);
        assert_eq!(child.read_all_at(65536, 4096), vec![0x55; 4096]);
    }

    #[test]
    fn inherited_reader_rejects_unretired_writer_and_respects_depth() {
        use crate::disk_file::MetadataSync;
        let file = TempFile::new().unwrap().into_file();
        create_image(&file, 1024 * 1024, None).unwrap();
        let disk = QcowDisk::new(file.try_clone().unwrap(), false, false, true, false).unwrap();
        let view = disk.prepare_fork_backing().unwrap().unwrap();
        let scope = PreparedQcowScope::enter_with_backings(vec![], vec![view]);
        assert!(take_backing(&file, 1).is_err());
        drop(scope);
        disk.sync_metadata().unwrap();
        let retirement = disk.defer_fork_shutdown().unwrap();
        let view = disk.prepare_fork_backing().unwrap().unwrap();
        let scope = PreparedQcowScope::enter_with_backings(vec![], vec![view]);
        assert!(take_backing(&file, 0).is_err());
        drop(scope);
        retirement.finish().unwrap();
    }

    #[test]
    fn prepared_open_is_scoped_single_use_and_pins_identity() {
        let file = TempFile::new().unwrap().into_file();
        let proof = create_prepared_image(&file, 1024 * 1024, None).unwrap();
        let other = TempFile::new().unwrap().into_file();
        let scope = PreparedQcowScope::enter(vec![proof]);
        assert!(!consume(&other).unwrap());
        assert!(consume(&file).unwrap());
        assert!(!consume(&file).unwrap());
        drop(scope);
        // Losing the proof leaves the dirty marker; normal crash recovery works.
        let disk = QcowDisk::new(file.try_clone().unwrap(), false, false, true, false).unwrap();
        assert_eq!(disk.read_all_at(0, 4096), vec![0; 4096]);
    }

    #[test]
    fn changed_prepared_image_is_rejected() {
        let file = TempFile::new().unwrap().into_file();
        let proof = create_prepared_image(&file, 1024 * 1024, None).unwrap();
        // Extend the image, leaving its QCOW header valid but changing identity.
        file.write_all_at(&[0], file.metadata().unwrap().len())
            .unwrap();
        let _scope = PreparedQcowScope::enter(vec![proof]);
        let error = QcowDisk::new(file, false, false, true, false).unwrap_err();
        assert!(
            format!("{error:?}").contains("Prepared QCOW image changed"),
            "{error}"
        );
    }

    #[test]
    fn prepared_writer_still_persists_data_and_clears_dirty_on_close() {
        let file = TempFile::new().unwrap().into_file();
        let proof = create_prepared_image(&file, 1024 * 1024, None).unwrap();
        {
            let _scope = PreparedQcowScope::enter(vec![proof]);
            let disk = QcowDisk::new(file.try_clone().unwrap(), false, false, true, false).unwrap();
            assert!(PREPARED.with(|p| p.borrow().is_empty()));
            let empty_len = file.metadata().unwrap().len();
            assert!(file.metadata().unwrap().blocks() * 512 < 1024 * 1024);
            disk.write_all_at(65536, &vec![0x6c; 65536]);
            let reserved_len = file.metadata().unwrap().len();
            assert!(reserved_len > empty_len);
            assert!(reserved_len <= empty_len + 1024 * 1024);
            disk.write_all_at(131072, &vec![0x7d; 65536]);
            assert_eq!(
                file.metadata().unwrap().len(),
                reserved_len,
                "subsequent writes should use initialized free clusters without growing the host file"
            );
        }
        let reader = QcowDisk::new(file, false, false, true, false).unwrap();
        assert_eq!(reader.read_all_at(65536, 65536), vec![0x6c; 65536]);
    }
    #[test]
    fn prepared_crash_helper() {
        use crate::disk_file::MetadataSync;
        let Some(path) = std::env::var_os("QCOW_PREPARED_CRASH_IMAGE") else {
            return;
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let proof = create_prepared_image(&file, 1024 * 1024, None).unwrap();
        let _scope = PreparedQcowScope::enter(vec![proof]);
        let disk = QcowDisk::new(file, false, false, true, false).unwrap();
        disk.write_all_at(65536, &vec![0x11; 65536]);
        disk.sync_metadata().unwrap();
        disk.write_all_at(65536, &vec![0x22; 65536]);
        disk.write_all_at(262144, &vec![0x33; 65536]);
        disk.sync_metadata().unwrap();
        std::process::exit(0); // Deliberately bypass clean-close destructors.
    }

    #[test]
    fn prepared_checkpoint_survives_process_exit_without_proof() {
        let file = TempFile::new().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "formats::qcow::prepared::tests::prepared_crash_helper",
            ])
            .env("QCOW_PREPARED_CRASH_IMAGE", file.as_path())
            .status()
            .unwrap();
        assert!(status.success());
        let header = QcowHeader::new(&AlignedFile::new(
            file.as_file().try_clone().unwrap(),
            false,
        ))
        .unwrap();
        assert_ne!(header.incompatible_features & 1, 0);
        // No in-memory proof survives; ordinary dirty-image recovery must work.
        let disk = QcowDisk::new(
            file.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();
        assert_eq!(disk.read_all_at(65536, 65536), vec![0x22; 65536]);
        assert_eq!(disk.read_all_at(262144, 65536), vec![0x33; 65536]);
    }
}
