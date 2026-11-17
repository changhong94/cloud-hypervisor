// SPDX-License-Identifier: Apache-2.0
//! Fork a stopped disk, preparing immutable prefix compaction while the guest runs. Each VM owns a directory of
//! hard links to immutable history and one private writable qcow2 leaf.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Instant;

// Includes the raw base. Compaction resets a branch to base + merged + active.
const COMPACT_AT_FILES: usize = 4;

use block::AlignedFile;
use block::formats::qcow::{self, BackingFileConfig, ImageType, QcowHeader};

use crate::api::VmForkConfig;
use crate::vm_config::{DiskConfig, VmConfig};

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

fn directory(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(invalid("Disk directories must be absolute"));
    }
    let canonical = path
        .parent()
        .unwrap()
        .canonicalize()?
        .join(path.file_name().unwrap());
    if canonical != path || fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(invalid("Disk directories must not contain aliases"));
    }
    Ok(canonical)
}

struct Chain {
    paths: Vec<PathBuf>,
    size: u64,
    format: ImageType,
}

fn chain(source: &Path, parent: &Path, image_type: block::ImageType) -> io::Result<Chain> {
    let mut paths = Vec::new();
    let mut current = source.canonicalize()?;
    let mut size = 0;
    let mut format = ImageType::Raw;
    loop {
        // Accept older managed chains as well; compact before adding a leaf.
        if paths.len() >= 10 || paths.contains(&current) {
            return Err(invalid("Disk backing chain is cyclic or too deep"));
        }
        let meta = fs::symlink_metadata(&current)?;
        if !meta.is_file() {
            return Err(invalid("Fork requires regular disk files"));
        }
        let mut file = File::open(&current)?;
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        let qcow = magic == *b"QFI\xfb";
        if paths.is_empty() {
            match image_type {
                block::ImageType::Raw if !qcow => {}
                block::ImageType::Qcow2 if qcow => {}
                _ => {
                    return Err(invalid(
                        "Writable fork requires explicit raw or qcow2 format",
                    ));
                }
            }
            size = meta.len();
        }
        if !paths.is_empty() && meta.permissions().mode() & 0o222 != 0 {
            return Err(invalid("Disk history must be sealed read-only"));
        }
        paths.push(current.clone());
        if !qcow {
            break;
        }
        if current.parent() != Some(parent) {
            return Err(invalid(
                "Qcow2 fork requires a managed relative backing chain",
            ));
        }
        let header = QcowHeader::new(&AlignedFile::new(file, false)).map_err(io::Error::other)?;
        if paths.len() == 1 {
            size = header.size;
            format = ImageType::Qcow2;
        }
        let backing = header
            .backing_file
            .ok_or_else(|| invalid("Missing managed backing file"))?;
        let name = Path::new(&backing.path);
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
        {
            return Err(invalid("Backing file must be a relative basename"));
        }
        current = parent.join(name);
        if current.canonicalize()? != current {
            return Err(invalid("Backing file aliases are unsupported"));
        }
    }
    Ok(Chain {
        paths,
        size,
        format,
    })
}

pub(crate) fn validate(config: &VmConfig, request: &VmForkConfig) -> io::Result<()> {
    let writable: Vec<_> = config
        .disks
        .iter()
        .flatten()
        .filter(|d| !d.readonly)
        .collect();
    if writable.is_empty() {
        if request.parent_disk_dir.is_some() || request.child_disk_dir.is_some() {
            return Err(invalid("Disk directories require a writable disk"));
        }
        return Ok(());
    }
    if writable.len() != 1 {
        return Err(invalid("Fork supports one writable disk"));
    }
    let parent = directory(
        request
            .parent_disk_dir
            .as_deref()
            .ok_or_else(|| invalid("Missing parent_disk_dir"))?,
    )?;
    let child = directory(
        request
            .child_disk_dir
            .as_deref()
            .ok_or_else(|| invalid("Missing child_disk_dir"))?,
    )?;
    if child.starts_with(&parent) || parent.starts_with(&child) || child.try_exists()? {
        return Err(invalid("Child disk directory must be new and separate"));
    }
    let disk = writable[0];
    let source = disk
        .path
        .as_deref()
        .ok_or_else(|| invalid("Missing disk path"))?;
    let history = chain(source, &parent, disk.image_type)?;
    let device = fs::metadata(parent.parent().unwrap())?.dev();
    if fs::metadata(child.parent().unwrap())?.dev() != device
        || history
            .paths
            .iter()
            .any(|p| fs::metadata(p).map_or(true, |m| m.dev() != device))
    {
        return Err(invalid(
            "Fork disk files and directories must be on the same filesystem",
        ));
    }
    if parent.try_exists()? && source.canonicalize()?.parent() != Some(parent.as_path()) {
        return Err(invalid("Parent disk directory is not owned by this disk"));
    }
    Ok(())
}

/// One supervisor-created worker per VM. It builds only from sealed ancestors,
/// then waits for the VMM to request publication before its next pause. Joining
/// is mandatory on publication, shutdown and every error path: no worker or
/// writable output FD can survive into the host fork.
enum MergeCommand {
    Start,
    Publish,
    Cancel,
}

pub(crate) struct MergeJob {
    cancelled: Arc<AtomicBool>,
    publish: mpsc::Sender<MergeCommand>,
    worker: Mutex<Option<JoinHandle<io::Result<()>>>>,
}

impl MergeJob {
    pub(crate) fn start(&self) {
        let _ = self.publish.send(MergeCommand::Start);
    }
    pub(crate) fn finish(&self) -> io::Result<()> {
        let started = Instant::now();
        let mut worker = self.worker.lock().unwrap();
        if let Some(worker) = worker.take() {
            let _ = self.publish.send(MergeCommand::Publish);
            let result = worker
                .join()
                .map_err(|_| invalid("Disk merge worker panicked"))?;
            eprintln!(
                "VM_FORK disk_merge_wait_before_pause_ms={:.3}",
                started.elapsed().as_secs_f64() * 1000.0
            );
            result?;
        }
        Ok(())
    }
}

impl Drop for MergeJob {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.publish.send(MergeCommand::Cancel);
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            // Cancellation discards only the unpublished output. Drop must
            // join even if the worker failed before receiving the command.
            let _ = worker.join();
        }
    }
}

fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(invalid("Disk merge path is not a regular file"));
    }
    Ok((meta.dev(), meta.ino()))
}

/// Called by the supervisor, never by a narrowed VMM worker. Building a fresh
/// candidate does not change the backing namespace during VM restoration.
pub(crate) fn start_merge(config: &VmConfig) -> io::Result<Option<Arc<MergeJob>>> {
    let Some(disk) = config.disks.iter().flatten().find(|d| !d.readonly) else {
        return Ok(None);
    };
    if disk.image_type != block::ImageType::Qcow2 {
        return Ok(None);
    }
    let active = disk
        .path
        .as_ref()
        .ok_or_else(|| invalid("Missing disk path"))?
        .clone();
    let directory = active
        .parent()
        .ok_or_else(|| invalid("Missing disk directory"))?
        .to_owned();
    let history = chain(&active, &directory, disk.image_type)?;
    if history.paths.len() < COMPACT_AT_FILES {
        return Ok(None);
    }
    let identities = history
        .paths
        .iter()
        .map(|p| identity(p))
        .collect::<io::Result<Vec<_>>>()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = cancelled.clone();
    let (publish, command) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("disk-merge".into())
        .spawn(move || merge_worker(history, identities, directory, active, stop, command))?;
    Ok(Some(Arc::new(MergeJob {
        cancelled,
        publish,
        worker: Mutex::new(Some(worker)),
    })))
}

fn merge_worker(
    history: Chain,
    identities: Vec<(u64, u64)>,
    directory: PathBuf,
    active: PathBuf,
    stop: Arc<AtomicBool>,
    command: mpsc::Receiver<MergeCommand>,
) -> io::Result<()> {
    // Do not compete with runtime reconstruction during the pause.
    let publish_now = match command.recv() {
        Ok(MergeCommand::Start) => false,
        Ok(MergeCommand::Publish) => true,
        _ => return Ok(()),
    };
    let candidate = directory.join(format!(
        ".merge-{}",
        active.file_name().unwrap().to_string_lossy()
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate)?;
    let result = (|| {
        let started = Instant::now();
        let base = history.paths.last().unwrap();
        let backing = BackingFileConfig {
            path: base
                .file_name()
                .unwrap()
                .to_str()
                .ok_or_else(|| invalid("Non-UTF8 backing path"))?
                .into(),
            format: Some(ImageType::Raw),
        };
        qcow::create_image(&file, history.size, Some(&backing)).map_err(io::Error::other)?;
        // Exclude the live leaf: its metadata and data remain entirely owned
        // by the block backend while the guest continues reading/writing.
        let inputs = history.paths[1..history.paths.len() - 1]
            .iter()
            .rev()
            .map(File::open)
            .collect::<io::Result<Vec<_>>>()?;
        let stats =
            qcow::merge_layers_cancellable(&file, &inputs, || stop.load(Ordering::Acquire))?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        eprintln!(
            "VM_FORK disk_compact input_files={} clusters={} bytes_read={} zero_clusters={} elapsed_ms={:.3} background=true shadowed_clusters={}",
            history.paths.len() - 1,
            stats.clusters,
            stats.bytes_read,
            stats.zero_clusters,
            started.elapsed().as_secs_f64() * 1000.0,
            stats.shadowed_clusters
        );
        if !publish_now {
            loop {
                match command.recv() {
                    Ok(MergeCommand::Publish) => break,
                    Ok(MergeCommand::Start) => continue,
                    _ => return Ok(()),
                }
            }
        }
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        for (path, expected) in history.paths.iter().zip(&identities) {
            if identity(path)? != *expected {
                return Err(invalid("Disk merge source identity changed"));
            }
        }
        if chain(&active, &directory, block::ImageType::Qcow2)?.paths != history.paths {
            return Err(invalid("Disk merge backing chain changed"));
        }
        // Replace only this directory's link. The old inode is pinned by
        // running backends and by other VM directories. Both old and new
        // prefixes represent exactly the same logical bytes; active writes
        // and copy-up therefore remain valid across this atomic rename.
        fs::rename(&candidate, &history.paths[1])?;
        // A failure after rename is not a rollback: the new chain is valid.
        if let Err(error) = File::open(&directory)
            .and_then(|d| d.sync_all())
            .and_then(|_| collect_garbage(&directory, &active))
        {
            eprintln!("VM_FORK disk_gc deferred: {error}");
        }
        eprintln!(
            "VM_FORK disk_merge_publish active={} live_files=3",
            active.display()
        );
        Ok(())
    })();
    drop(file);
    // After publication this name no longer exists; before publication it
    // belongs exclusively to this worker, including on cancellation/error.
    let _ = fs::remove_file(&candidate);
    result
}

pub(crate) fn ready_to_pause(config: &VmConfig) -> io::Result<()> {
    if let Some(disk) = config.disks.iter().flatten().find(|d| !d.readonly)
        && disk.image_type == block::ImageType::Qcow2
    {
        let active = disk
            .path
            .as_ref()
            .ok_or_else(|| invalid("Missing disk path"))?;
        if chain(active, active.parent().unwrap(), disk.image_type)?
            .paths
            .len()
            >= COMPACT_AT_FILES
        {
            return Err(invalid("Disk merge is unavailable; VM remains running"));
        }
    }
    Ok(())
}

/// Unpublished empty leaves and history links. Until commit, the active image
/// remains writable and the VM keeps running. Drop rolls back only owned paths.
pub(crate) struct PreparedBranch {
    index: usize,
    source: PathBuf,
    source_config_path: Option<PathBuf>,
    source_identity: (u64, u64),
    leaves: Vec<PathBuf>,
    pub(crate) opens: Vec<qcow::PreparedQcowOpen>,
    created: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    size: u64,
    history_links: usize,
}

impl Drop for PreparedBranch {
    fn drop(&mut self) {
        for path in self.created.iter().rev() {
            let _ = fs::remove_file(path);
        }
        for dir in self.dirs.iter().rev() {
            let _ = fs::remove_dir(dir);
        }
    }
}

/// Prepare only new metadata while the source guest is still running. No data
/// is read from the active leaf and no source permission/configuration changes.
pub(crate) fn prepare(
    config: &VmConfig,
    request: &VmForkConfig,
    operation: &str,
) -> io::Result<Option<PreparedBranch>> {
    validate(config, request)?;
    let Some(index) = config
        .disks
        .as_ref()
        .and_then(|ds| ds.iter().position(|d| !d.readonly))
    else {
        return Ok(None);
    };
    let disk = &config.disks.as_ref().unwrap()[index];
    let parent = request.parent_disk_dir.as_ref().unwrap();
    let child = request.child_disk_dir.as_ref().unwrap();
    let history = chain(disk.path.as_ref().unwrap(), parent, disk.image_type)?;
    if history.paths.len() >= COMPACT_AT_FILES {
        return Err(invalid(
            "Disk prefix must be compacted before pausing the VM",
        ));
    }
    // A colliding operation path belongs to the caller, not to GC. Preserve
    // the create-new failure/rollback contract before reclaiming stale links.
    if parent
        .join(format!("layer-{operation}-parent.qcow2"))
        .try_exists()?
    {
        return Err(invalid("Parent disk leaf already exists"));
    }
    // Reclaim/sync old unreachable links before adding unpublished leaves.
    // Adding a new leaf above this complete history creates no new garbage,
    // so commit need not scan/fsync the directory again while CPUs are paused.
    if parent.try_exists()? {
        collect_garbage(parent, disk.path.as_ref().unwrap())?;
    }
    let source = history.paths[0].clone();
    let meta = fs::metadata(&source)?;
    let source_identity = (meta.dev(), meta.ino());
    let mut created = Vec::new();
    let mut dirs = Vec::new();
    let result = (|| {
        if !parent.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(parent)?;
            dirs.push(parent.clone());
        }
        fs::DirBuilder::new().mode(0o700).create(child)?;
        dirs.push(child.clone());
        let mut backing = String::new();
        for (i, path) in history.paths.iter().enumerate() {
            let name = if path.parent() == Some(parent.as_path()) {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .ok_or_else(|| invalid("Non-UTF8 disk path"))?
                    .to_owned()
            } else {
                "base.raw".to_owned()
            };
            if i == 0 {
                backing = name.clone();
            }
            for dir in [parent, child] {
                let link = dir.join(&name);
                if &link != path {
                    fs::hard_link(path, &link)?;
                    created.push(link);
                }
            }
        }
        let backing_config = BackingFileConfig {
            path: backing,
            format: Some(history.format),
        };
        let mut leaves = Vec::new();
        let mut files = Vec::new();
        for (dir, suffix) in [(parent, "parent"), (child, "child")] {
            let path = dir.join(format!("layer-{operation}-{suffix}.qcow2"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            created.push(path.clone());
            files.push(file);
            leaves.push(path);
        }
        // Independent empty images can be initialized/durably flushed together.
        // Always join the helper, including when parent initialization fails.
        // The supervisor enforces the final single-thread barrier before fork.
        let initialize =
            |file: &File| qcow::create_prepared_image(file, history.size, Some(&backing_config));
        let opens = thread::scope(|scope| -> io::Result<Vec<qcow::PreparedQcowOpen>> {
            let child = thread::Builder::new()
                .name("disk-leaf".into())
                .spawn_scoped(scope, || initialize(&files[1]))?;
            let parent = initialize(&files[0]);
            let child = child
                .join()
                .map_err(|_| invalid("Disk leaf worker panicked"))?;
            Ok(vec![parent?, child?])
        })?;
        for dir in [parent, child] {
            File::open(dir)?.sync_all()?;
        }
        Ok((leaves, opens))
    })();
    let (leaves, opens) = match result {
        Ok(prepared) => prepared,
        Err(error) => {
            for path in created.iter().rev() {
                let _ = fs::remove_file(path);
            }
            for dir in dirs.iter().rev() {
                let _ = fs::remove_dir(dir);
            }
            return Err(error);
        }
    };
    Ok(Some(PreparedBranch {
        index,
        source,
        source_config_path: disk.path.clone(),
        source_identity,
        leaves,
        opens,
        created,
        dirs,
        size: history.size,
        history_links: history.paths.len(),
    }))
}

/// Called only after vCPUs/block workers have stopped, flushed, and closed.
/// Source sealing and configuration publication remain inside the pause.
pub(crate) fn commit(
    config: &mut VmConfig,
    prepared: Option<PreparedBranch>,
) -> io::Result<Option<Vec<DiskConfig>>> {
    let Some(mut prepared) = prepared else {
        return Ok(None);
    };
    let disk = config
        .disks
        .as_mut()
        .and_then(|d| d.get_mut(prepared.index))
        .ok_or_else(|| invalid("Prepared disk no longer exists"))?;
    if disk.path != prepared.source_config_path {
        return Err(invalid("Prepared disk source changed"));
    }
    let meta = fs::metadata(&prepared.source)?;
    if (meta.dev(), meta.ino()) != prepared.source_identity {
        return Err(invalid("Prepared disk inode changed"));
    }
    let mut permissions = meta.permissions();
    permissions.set_mode(permissions.mode() & !0o222);
    fs::set_permissions(&prepared.source, permissions)?;
    disk.path = Some(prepared.leaves[0].clone());
    disk.image_type = block::ImageType::Qcow2;
    disk.backing_files = true;
    let mut child_disks = config.disks.clone().unwrap();
    child_disks[prepared.index].path = Some(prepared.leaves[1].clone());
    // Publication is infallible after sealing. Disarm rollback before GC.
    prepared.created.clear();
    prepared.dirs.clear();
    eprintln!(
        "VM_FORK disk_cow parent={} child={} virtual_bytes={} history_links={}",
        prepared.leaves[0].display(),
        prepared.leaves[1].display(),
        prepared.size,
        prepared.history_links
    );
    Ok(Some(child_disks))
}

#[cfg(test)]
fn branch(
    config: &mut VmConfig,
    request: &VmForkConfig,
    operation: &str,
) -> io::Result<Option<Vec<DiskConfig>>> {
    let prepared = prepare(config, request, operation)?;
    commit(config, prepared)
}

fn collect_garbage(directory: &Path, active: &Path) -> io::Result<()> {
    let live = chain(active, directory, block::ImageType::Qcow2)?.paths;
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if (name.starts_with("layer-") || name.starts_with("compact-"))
            && name.ends_with(".qcow2")
            && entry.file_type()?.is_file()
            && !live.contains(&entry.path())
        {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    File::open(directory)?.sync_all()?;
    eprintln!(
        "VM_FORK disk_gc removed_links={removed} live_files={}",
        live.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use tempfile::TempDir;

    use super::*;

    fn fixture(root: &Path) -> (VmConfig, VmForkConfig) {
        let source = root.join("seed.raw");
        let file = File::create(&source).unwrap();
        file.set_len(512 * 1024 * 1024).unwrap();
        file.write_all_at(b"inherited", 4096).unwrap();
        let config = serde_json::from_value(serde_json::json!({
            "disks": [{"path":source, "readonly":false, "image_type":"Raw"}]
        }))
        .unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "child_api_socket":root.join("api"), "child_serial_socket":root.join("serial"),
            "parent_disk_dir":root.join("parent"), "child_disk_dir":root.join("child")
        }))
        .unwrap();
        (config, request)
    }

    #[test]
    fn cancelled_preparation_removes_only_new_paths() {
        let root = TempDir::new().unwrap();
        let (config, request) = fixture(root.path());
        let source = config.disks.as_ref().unwrap()[0].path.as_ref().unwrap();
        let before = fs::metadata(source).unwrap();
        let prepared = prepare(&config, &request, "cancel").unwrap();
        assert_eq!(
            fs::metadata(source).unwrap().permissions().mode(),
            before.permissions().mode()
        );
        OpenOptions::new()
            .write(true)
            .open(source)
            .unwrap()
            .write_all_at(b"running", 8192)
            .unwrap();
        drop(prepared);
        assert!(!request.parent_disk_dir.as_ref().unwrap().exists());
        assert!(!request.child_disk_dir.as_ref().unwrap().exists());
        assert_eq!(fs::metadata(source).unwrap().ino(), before.ino());
        let mut bytes = [0; 7];
        File::open(source)
            .unwrap()
            .read_exact_at(&mut bytes, 8192)
            .unwrap();
        assert_eq!(&bytes, b"running");
    }

    #[test]
    fn prepared_branch_inherits_writes_until_quiescence() {
        let root = TempDir::new().unwrap();
        let (mut config, request) = fixture(root.path());
        branch(&mut config, &request, "initial").unwrap();
        let source = config.disks.as_ref().unwrap()[0]
            .path
            .as_ref()
            .unwrap()
            .clone();
        let disk = qcow::QcowDisk::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&source)
                .unwrap(),
            false,
            true,
            true,
            false,
        )
        .unwrap();
        disk.write_all_at(65536 - 512, &[31; 1024]);
        let next = VmForkConfig {
            child_disk_dir: Some(root.path().join("next")),
            ..request.clone()
        };
        let prepared = prepare(&config, &next, "prepared").unwrap();
        assert_ne!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o222,
            0
        );
        disk.write_all_at(2 * 65536 - 512, &[41; 1024]);
        // Simulate the existing pause/drain/metadata sync and disk close.
        drop(disk);
        let child = commit(&mut config, prepared).unwrap().unwrap();
        let child_disk = qcow::QcowDisk::new(
            File::open(child[0].path.as_ref().unwrap()).unwrap(),
            false,
            true,
            true,
            false,
        )
        .unwrap();
        assert_eq!(child_disk.read_all_at(65536 - 512, 1024), vec![31; 1024]);
        assert_eq!(
            child_disk.read_all_at(2 * 65536 - 512, 1024),
            vec![41; 1024]
        );
        assert_eq!(child_disk.read_all_at(4096, 9), b"inherited");
    }

    #[test]
    fn prepared_branch_rejects_replaced_source_without_sealing_it() {
        let root = TempDir::new().unwrap();
        let (mut config, request) = fixture(root.path());
        let source = config.disks.as_ref().unwrap()[0]
            .path
            .as_ref()
            .unwrap()
            .clone();
        let prepared = prepare(&config, &request, "replace").unwrap();
        fs::rename(&source, root.path().join("old.raw")).unwrap();
        File::create(&source)
            .unwrap()
            .set_len(512 * 1024 * 1024)
            .unwrap();
        assert!(commit(&mut config, prepared).is_err());
        assert_ne!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o222,
            0
        );
        assert!(!request.child_disk_dir.as_ref().unwrap().exists());
        assert_eq!(
            config.disks.as_ref().unwrap()[0].path.as_ref().unwrap(),
            &source
        );
    }

    #[test]
    fn histories_survive_parent_deletion_without_data_copy() {
        let root = TempDir::new().unwrap();
        let (mut config, request) = fixture(root.path());
        let mut child = config.clone();
        child.disks = branch(&mut config, &request, "one").unwrap();
        let parent = request.parent_disk_dir.as_ref().unwrap();
        let child_dir = request.child_disk_dir.as_ref().unwrap();
        assert_eq!(
            fs::metadata(parent.join("base.raw")).unwrap().ino(),
            fs::metadata(child_dir.join("base.raw")).unwrap().ino()
        );
        assert!(
            fs::metadata(config.disks.as_ref().unwrap()[0].path.as_ref().unwrap())
                .unwrap()
                .blocks()
                * 512
                < 1024 * 1024
        );
        let next = VmForkConfig {
            parent_disk_dir: Some(child_dir.clone()),
            child_disk_dir: Some(root.path().join("grandchild")),
            ..request.clone()
        };
        let grandchild = branch(&mut child, &next, "two").unwrap().unwrap();
        fs::remove_dir_all(parent).unwrap();
        fs::remove_dir_all(child_dir).unwrap();
        fs::remove_file(root.path().join("seed.raw")).unwrap();
        let leaf = grandchild[0].path.as_ref().unwrap();
        let header = QcowHeader::new(&AlignedFile::new(File::open(leaf).unwrap(), false)).unwrap();
        assert!(
            leaf.parent()
                .unwrap()
                .join(header.backing_file.unwrap().path)
                .exists()
        );
        let mut value = [0; 9];
        File::open(root.path().join("grandchild/base.raw"))
            .unwrap()
            .read_exact_at(&mut value, 4096)
            .unwrap();
        assert_eq!(&value, b"inherited");
    }

    #[test]
    fn failed_leaf_creation_rolls_back_only_new_history_links() {
        let root = TempDir::new().unwrap();
        let (mut config, request) = fixture(root.path());
        branch(&mut config, &request, "one").unwrap();
        let parent = request.parent_disk_dir.as_ref().unwrap();
        let collision = parent.join("layer-two-parent.qcow2");
        fs::write(&collision, b"keep me").unwrap();
        let next = VmForkConfig {
            child_disk_dir: Some(root.path().join("next")),
            ..request
        };
        let old = config.disks.as_ref().unwrap()[0].path.clone().unwrap();
        assert!(branch(&mut config, &next, "two").is_err());
        assert_eq!(fs::read(collision).unwrap(), b"keep me");
        assert!(!next.child_disk_dir.unwrap().exists());
        assert_eq!(config.disks.as_ref().unwrap()[0].path.as_ref(), Some(&old));
        assert_ne!(fs::metadata(old).unwrap().permissions().mode() & 0o222, 0);
    }

    #[test]
    fn repeated_forks_bound_chains_and_reclaim_only_local_links() {
        let root = TempDir::new().unwrap();
        let (mut config, mut request) = fixture(root.path());
        let mut descendants = Vec::new();
        for generation in 0..40 {
            request.child_disk_dir = Some(root.path().join(format!("child-{generation}")));
            if let Some(job) = start_merge(&config).unwrap() {
                job.finish().unwrap();
            }
            let child = branch(&mut config, &request, &format!("generation-{generation}"))
                .unwrap()
                .unwrap();
            descendants.push((
                request.child_disk_dir.clone().unwrap(),
                child[0].path.clone().unwrap(),
            ));
            let active = config.disks.as_ref().unwrap()[0].path.as_ref().unwrap();
            assert!(
                chain(
                    active,
                    request.parent_disk_dir.as_ref().unwrap(),
                    block::ImageType::Qcow2
                )
                .unwrap()
                .paths
                .len()
                    <= COMPACT_AT_FILES
            );
            assert!(
                fs::read_dir(request.parent_disk_dir.as_ref().unwrap())
                    .unwrap()
                    .count()
                    <= COMPACT_AT_FILES
            );
        }
        fs::remove_dir_all(request.parent_disk_dir.unwrap()).unwrap();
        for (dir, active) in descendants.into_iter().rev() {
            assert!(chain(&active, &dir, block::ImageType::Qcow2).is_ok());
            fs::remove_dir_all(dir).unwrap();
        }
        assert_eq!(
            fs::metadata(root.path().join("seed.raw")).unwrap().nlink(),
            1
        );
    }

    #[test]
    fn unprepared_chain_is_rejected_without_mutation() {
        let root = TempDir::new().unwrap();
        let (mut config, mut request) = fixture(root.path());
        for generation in 0..3 {
            request.child_disk_dir = Some(root.path().join(format!("child-{generation}")));
            branch(&mut config, &request, &format!("generation-{generation}")).unwrap();
        }
        let parent = request.parent_disk_dir.as_ref().unwrap();
        let active = config.disks.as_ref().unwrap()[0].path.clone().unwrap();
        let old = chain(&active, parent, block::ImageType::Qcow2)
            .unwrap()
            .paths;
        fs::write(parent.join("layer-conflict-parent.qcow2"), b"keep").unwrap();
        request.child_disk_dir = Some(root.path().join("conflict"));
        assert!(branch(&mut config, &request, "conflict").is_err());
        assert_eq!(
            config.disks.as_ref().unwrap()[0].path.as_ref(),
            Some(&active)
        );
        assert!(!parent.join("compact-conflict.qcow2").exists());
        assert!(!request.child_disk_dir.unwrap().exists());
        assert!(old.iter().all(|p| p.exists()));
        assert_ne!(
            fs::metadata(active).unwrap().permissions().mode() & 0o222,
            0
        );
    }

    fn deep_fixture(root: &Path) -> (VmConfig, VmForkConfig) {
        let (mut config, mut request) = fixture(root);
        for generation in 0..3 {
            request.child_disk_dir = Some(root.join(format!("child-{generation}")));
            branch(&mut config, &request, &format!("generation-{generation}")).unwrap();
        }
        (config, request)
    }

    #[test]
    fn background_publish_replaces_only_local_link_and_pins_old_fds() {
        let root = TempDir::new().unwrap();
        let (config, request) = deep_fixture(root.path());
        let active = config.disks.as_ref().unwrap()[0].path.as_ref().unwrap();
        let parent = request.parent_disk_dir.as_ref().unwrap();
        let old = chain(active, parent, block::ImageType::Qcow2).unwrap();
        let pinned = File::open(&old.paths[1]).unwrap();
        let old_inode = pinned.metadata().unwrap().ino();
        let peer = request
            .child_disk_dir
            .as_ref()
            .unwrap()
            .join(old.paths[1].file_name().unwrap());
        let job = start_merge(&config).unwrap().unwrap();
        job.finish().unwrap();
        assert_ne!(identity(&old.paths[1]).unwrap().1, old_inode);
        assert_eq!(identity(&peer).unwrap().1, old_inode);
        assert_eq!(pinned.metadata().unwrap().ino(), old_inode);
        assert_eq!(
            chain(active, parent, block::ImageType::Qcow2)
                .unwrap()
                .paths
                .len(),
            3
        );
        assert_eq!(fs::read_dir(parent).unwrap().count(), 3);
        ready_to_pause(&config).unwrap();
    }

    #[test]
    fn online_copy_up_and_reopen_match_across_atomic_publication() {
        let root = TempDir::new().unwrap();
        let (config, request) = deep_fixture(root.path());
        let active = config.disks.as_ref().unwrap()[0].path.as_ref().unwrap();
        let disk = qcow::QcowDisk::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(active)
                .unwrap(),
            false,
            true,
            true,
            false,
        )
        .unwrap();
        let job = start_merge(&config).unwrap().unwrap();
        job.start();
        // Active metadata is intentionally dirty during merge/publication.
        disk.write_all_at(65536 - 512, &[21; 1024]);
        job.finish().unwrap();
        disk.write_all_at(2 * 65536 - 512, &[31; 1024]);
        assert_eq!(disk.read_all_at(4096, 9), b"inherited");
        assert_eq!(disk.read_all_at(65536 - 512, 1024), vec![21; 1024]);
        assert_eq!(disk.read_all_at(2 * 65536 - 512, 1024), vec![31; 1024]);
        drop(disk);
        let reopened =
            qcow::QcowDisk::new(File::open(active).unwrap(), false, true, true, false).unwrap();
        assert_eq!(reopened.read_all_at(4096, 9), b"inherited");
        assert_eq!(reopened.read_all_at(65536 - 512, 1024), vec![21; 1024]);
        assert_eq!(reopened.read_all_at(2 * 65536 - 512, 1024), vec![31; 1024]);
        let peer = request
            .child_disk_dir
            .as_ref()
            .unwrap()
            .join("layer-generation-2-child.qcow2");
        let peer =
            qcow::QcowDisk::new(File::open(peer).unwrap(), false, true, true, false).unwrap();
        assert_eq!(peer.read_all_at(4096, 9), b"inherited");
        assert_eq!(peer.read_all_at(65536 - 512, 1024), vec![0; 1024]);
    }

    #[test]
    fn cancelled_merge_joins_and_discards_candidate_without_publishing() {
        let root = TempDir::new().unwrap();
        let (config, request) = deep_fixture(root.path());
        let parent = request.parent_disk_dir.as_ref().unwrap();
        let before: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (p.clone(), identity(&p).unwrap())
            })
            .collect();
        let job = start_merge(&config).unwrap().unwrap();
        job.start();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while !fs::read_dir(parent).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".merge-")
        }) {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        drop(job);
        assert_eq!(fs::read_dir(parent).unwrap().count(), before.len());
        for (p, id) in before {
            assert_eq!(identity(&p).unwrap(), id);
        }
    }

    #[test]
    fn stale_candidate_cannot_replace_changed_chain() {
        let root = TempDir::new().unwrap();
        let (config, request) = deep_fixture(root.path());
        let active = config.disks.as_ref().unwrap()[0].path.as_ref().unwrap();
        let parent = request.parent_disk_dir.as_ref().unwrap();
        let job = start_merge(&config).unwrap().unwrap();
        let saved = parent.join("saved");
        fs::rename(active, &saved).unwrap();
        fs::copy(&saved, active).unwrap();
        assert!(job.finish().is_err());
        assert!(!fs::read_dir(parent).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".merge-")
        }));
        assert_eq!(
            chain(active, parent, block::ImageType::Qcow2)
                .unwrap()
                .paths
                .len(),
            4
        );
    }

    #[test]
    fn conflicts_leave_source_and_existing_files_untouched() {
        let root = TempDir::new().unwrap();
        let (mut config, request) = fixture(root.path());
        fs::create_dir(request.child_disk_dir.as_ref().unwrap()).unwrap();
        let old_path = config.disks.as_ref().unwrap()[0].path.clone();
        assert!(branch(&mut config, &request, "one").is_err());
        assert_eq!(config.disks.as_ref().unwrap()[0].path, old_path);
        assert_ne!(
            fs::metadata(old_path.unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o222,
            0
        );
        assert!(!request.parent_disk_dir.unwrap().exists());
    }
}
