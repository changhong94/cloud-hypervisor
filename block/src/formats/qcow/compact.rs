// SPDX-License-Identifier: Apache-2.0
//! Offline sparse compaction into a new image. Existing layers are never written.
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};

use super::QcowDisk;
use super::backing::Qcow2Backing;
use super::common::apply_dealloc_action;
use super::metadata::{BackingRead, ClusterWriteMapping};
use crate::AlignedFile;

#[derive(Debug, Default)]
pub struct MergeStats {
    pub clusters: u64,
    pub bytes_read: u64,
    pub zero_clusters: u64,
    pub shadowed_clusters: u64,
}

/// Copy the newest allocated override of each cluster into a fresh destination with
/// the same raw backing and cluster size. Inputs must be read-only and quiesced;
/// the destination must be unpublished and exclusively owned by the caller.
/// Inputs are ordered oldest first. Transfer buffers are cluster-sized and the
/// deduplication set is bounded to one L2 range, not the virtual disk size; normal
/// qcow2 metadata caches still scale with image geometry. Holes are not read/copied; explicit zeros stay zeros.
pub fn merge_layers(destination: &File, layers_oldest_first: &[File]) -> io::Result<MergeStats> {
    merge_layers_cancellable(destination, layers_oldest_first, || false)
}

/// Cancellation is checked between clusters; the unpublished output must be discarded on error.
pub fn merge_layers_cancellable(
    destination: &File,
    layers_oldest_first: &[File],
    cancelled: impl Fn() -> bool,
) -> io::Result<MergeStats> {
    if !AlignedFile::new(destination.try_clone()?, false).is_writable() {
        return Err(io::Error::other("Compaction output must be writable"));
    }
    let destination_identity = destination.metadata()?;
    for file in layers_oldest_first {
        let identity = file.metadata()?;
        if AlignedFile::new(file.try_clone()?, false).is_writable()
            || (identity.dev(), identity.ino())
                == (destination_identity.dev(), destination_identity.ino())
        {
            return Err(io::Error::other(
                "Compaction inputs must be read-only and distinct from output",
            ));
        }
    }
    let mut target = QcowDisk::new(destination.try_clone()?, false, true, true, false)
        .map_err(io::Error::other)?;
    let cluster_size = target.metadata.cluster_size();
    let size = target.metadata.virtual_size();
    let mut buffer = vec![0; cluster_size as usize];
    let mut stats = MergeStats::default();
    let mut readers = Vec::with_capacity(layers_oldest_first.len());
    for file in layers_oldest_first.iter().rev() {
        let source =
            QcowDisk::new(file.try_clone()?, false, true, true, false).map_err(io::Error::other)?;
        if source.metadata.virtual_size() != size || source.metadata.cluster_size() != cluster_size
        {
            return Err(io::Error::other(
                "Compaction requires read-only layers with matching geometry",
            ));
        }
        let reader = Qcow2Backing {
            metadata: source.metadata.clone(),
            data_file: source.data_raw_file.file().try_clone()?,
            backing_file: source.backing_file.clone(),
            cluster_size,
            decoder: source.metadata.decoder(),
        };
        readers.push(reader);
    }
    let l1_count = size.div_ceil(cluster_size * (cluster_size / 8));
    for l1 in 0..l1_count {
        let mut seen = BTreeSet::new();
        for reader in &readers {
            if cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Disk merge cancelled",
                ));
            }
            for offset in reader.metadata.allocated_clusters(l1 as usize)? {
                if !seen.insert(offset) {
                    stats.shadowed_clusters += 1;
                    continue;
                }
                if cancelled() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Disk merge cancelled",
                    ));
                }
                reader.read_at(offset, &mut buffer)?;
                stats.clusters += 1;
                stats.bytes_read += (size - offset).min(cluster_size);
                if buffer.iter().all(|&byte| byte == 0) {
                    // A zero marker must hide even nonzero raw backing data.
                    let actions = target.metadata.deallocate_bytes(
                        offset,
                        (size - offset).min(cluster_size) as usize,
                        true,
                        true,
                        target.backing_file.as_deref(),
                    )?;
                    for action in actions {
                        apply_dealloc_action(&target.metadata, &mut target.data_raw_file, &action)?;
                    }
                    stats.zero_clusters += 1;
                } else {
                    let ClusterWriteMapping::Allocated { offset: physical } =
                        target.metadata.map_cluster_for_write(offset, None)?;
                    target
                        .data_raw_file
                        .file()
                        .write_all_at(&buffer, physical)?;
                }
            }
        }
    }
    target.metadata.finish()?;
    destination.sync_all()?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::formats::qcow::{BackingFileConfig, ImageType, create_image};

    #[test]
    fn sparse_merge_preserves_overlaps_zero_overrides_and_backing_holes() {
        let base = TempFile::new().unwrap();
        let size = 128 * 1024 * 1024;
        let cluster = 65536;
        base.as_file().set_len(size).unwrap();
        base.as_file()
            .write_all_at(&vec![10; cluster * 4], 0)
            .unwrap();
        let base_config = BackingFileConfig {
            path: base.as_path().to_str().unwrap().into(),
            format: Some(ImageType::Raw),
        };
        let lower = TempFile::new().unwrap();
        create_image(lower.as_file(), size, Some(&base_config)).unwrap();
        {
            let disk = QcowDisk::new(
                lower.as_file().try_clone().unwrap(),
                false,
                true,
                true,
                false,
            )
            .unwrap();
            disk.write_all_at(0, &vec![20; cluster]);
            disk.write_all_at(cluster as u64, &vec![21; cluster]);
        }
        let upper = TempFile::new().unwrap();
        create_image(
            upper.as_file(),
            size,
            Some(&BackingFileConfig {
                path: lower.as_path().to_str().unwrap().into(),
                format: Some(ImageType::Qcow2),
            }),
        )
        .unwrap();
        {
            let mut disk = QcowDisk::new(
                upper.as_file().try_clone().unwrap(),
                false,
                true,
                true,
                false,
            )
            .unwrap();
            disk.write_all_at(cluster as u64 + 512, &[30; 512]);
            let actions = disk
                .metadata
                .deallocate_bytes(0, cluster, true, true, disk.backing_file.as_deref())
                .unwrap();
            for action in actions {
                apply_dealloc_action(&disk.metadata, &mut disk.data_raw_file, &action).unwrap();
            }
        }
        let output = TempFile::new().unwrap();
        create_image(output.as_file(), size, Some(&base_config)).unwrap();
        let stats = merge_layers(
            output.as_file(),
            &[
                File::open(lower.as_path()).unwrap(),
                File::open(upper.as_path()).unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(stats.clusters, 2);
        assert_eq!(stats.shadowed_clusters, 2);
        assert_eq!(stats.zero_clusters, 1);
        assert_eq!(stats.bytes_read, 2 * cluster as u64);
        let disk = QcowDisk::new(
            File::open(output.as_path()).unwrap(),
            false,
            true,
            true,
            false,
        )
        .unwrap();
        let mut expected = vec![10; cluster * 4];
        expected[..cluster].fill(0);
        expected[cluster..2 * cluster].fill(21);
        expected[cluster + 512..cluster + 1024].fill(30);
        assert_eq!(disk.read_all_at(0, expected.len()), expected);
        let old = QcowDisk::new(
            File::open(lower.as_path()).unwrap(),
            false,
            true,
            true,
            false,
        )
        .unwrap();
        assert_eq!(old.read_all_at(0, cluster), vec![20; cluster]);
        assert!(merge_layers(output.as_file(), &[upper.as_file().try_clone().unwrap()]).is_err());
        let cancelled = TempFile::new().unwrap();
        create_image(cancelled.as_file(), size, Some(&base_config)).unwrap();
        let checks = std::cell::Cell::new(0);
        let error = merge_layers_cancellable(
            cancelled.as_file(),
            &[File::open(lower.as_path()).unwrap()],
            || {
                checks.set(checks.get() + 1);
                checks.get() >= 3
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(old.read_all_at(0, cluster), vec![20; cluster]);
    }
}
