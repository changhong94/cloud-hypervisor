// SPDX-License-Identifier: Apache-2.0
//! Experimental same-host fork. Only immutable state and private RAM survive
//! the teardown; no KVM object or worker is inherited by the new runtime.
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, process};

use serde::{Deserialize, Serialize};
use vm_memory::{GuestAddressSpace, GuestMemoryBackend, GuestMemoryRegion};
use vm_migration::{Pausable, Snapshot, Snapshottable};

use crate::api::VmForkConfig;
use crate::console_devices::pre_create_console_devices;
use crate::vm::{Error, Vm, VmState};
use crate::vm_config::{ConsoleOutputMode, VmConfig};
use crate::{GuestMemoryMmap, VmOwnership, Vmm};

/// Format before writing so short records from the two processes sharing the
/// stderr pipe are not interleaved inside numeric fields (PIPE_BUF atomicity).
pub(crate) fn log_line(args: std::fmt::Arguments<'_>) {
    let line = format!("{args}\n");
    let _ = io::stderr().lock().write_all(line.as_bytes());
}

macro_rules! fork_log {
    ($($arg:tt)*) => { log_line(format_args!($($arg)*)) };
}

// Start the worker while the guest is still running. It owns no VM until
// teardown has joined every vCPU/device worker; close can then overlap API
// shutdown. Joining (including abort/drop) remains mandatory before OS fork.
struct PreparedRetirement<T: Send + 'static> {
    sender: Option<std::sync::mpsc::Sender<T>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl<T: Send + 'static> PreparedRetirement<T> {
    fn new(retire: impl FnOnce(T) + Send + 'static) -> io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::Builder::new()
            .name("fork-retire".into())
            .spawn(move || {
                if ready_tx.send(()).is_ok() {
                    if let Ok(value) = receiver.recv() {
                        retire(value);
                    }
                }
            })?;
        let mut result = Self {
            sender: Some(sender),
            worker: Some(worker),
        };
        if ready_rx.recv().is_err() {
            result.join()?;
            return Err(io::Error::other(
                "VM retirement worker failed to initialize",
            ));
        }
        Ok(result)
    }
    fn submit(&mut self, value: T) -> Result<(), T> {
        match self.sender.take() {
            Some(sender) => sender.send(value).map_err(|error| error.0),
            None => Err(value),
        }
    }
    fn join(&mut self) -> io::Result<()> {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("VM retirement worker panicked"))?;
        }
        Ok(())
    }
}
impl<T: Send + 'static> Drop for PreparedRetirement<T> {
    fn drop(&mut self) {
        let _ = self.join();
    }
}
type VmRetirement = PreparedRetirement<(Arc<crate::vm::RetiredForkVm>, Option<ForkTrace>)>;

fn retire_cpu_threads(
    (manager, trace): (Arc<Mutex<crate::cpu::CpuManager>>, Option<ForkTrace>),
    reuse: bool,
) {
    set_trace(trace);
    trace_point("cpu_shutdown_begin");
    if let Err(error) = manager.lock().unwrap().shutdown() {
        fork_log!("FATAL: failed stopping fork vCPUs: {error:?}");
        // Preserve Vm::shutdown's existing fail-closed behavior.
        process::exit(1);
    }
    trace_point("vcpu_threads_joined");
    if reuse {
        if let Err(error) = manager.lock().unwrap().park_fork_vcpus() {
            fork_log!("FATAL: failed retaining stopped vCPUs: {error}");
            process::exit(1);
        }
        trace_point("parent_vcpus_parked");
    }
    drop(manager);
}

// Protect only the single-threaded host fork syscall from CFS run-queue
// stalls. RESET_ON_FORK makes the child start in SCHED_OTHER in the kernel;
// the parent restores its policy before tracing or rebuilding any worker.
// Non-default caller scheduling and unprivileged hosts are left unchanged.
struct ForkScheduling {
    active: bool,
}
impl ForkScheduling {
    fn enter() -> io::Result<Option<Self>> {
        // SAFETY: these calls query only the calling thread.
        let policy = unsafe { libc::sched_getscheduler(0) };
        if policy < 0 {
            return Err(io::Error::last_os_error());
        }
        if policy != libc::SCHED_OTHER || unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) } != 0 {
            return Ok(None);
        }
        let parameter = libc::sched_param { sched_priority: 1 };
        // SAFETY: parameter is initialized and the change affects only self.
        if unsafe {
            libc::sched_setscheduler(0, libc::SCHED_FIFO | libc::SCHED_RESET_ON_FORK, &parameter)
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { active: true }))
    }
    fn restore(&mut self) -> io::Result<()> {
        if self.active {
            let parameter = libc::sched_param { sched_priority: 0 };
            // SAFETY: both the original parent and reset child may return to
            // SCHED_OTHER without retaining realtime policy in future workers.
            if unsafe { libc::sched_setscheduler(0, libc::SCHED_OTHER, &parameter) } < 0 {
                return Err(io::Error::last_os_error());
            }
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for ForkScheduling {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            fork_log!("FATAL: cannot restore fork scheduling: {error}");
            // Do not let any VM run with an accidentally elevated policy.
            std::process::abort();
        }
    }
}

fn check_kvm_descriptors(retained: &[std::os::fd::RawFd]) -> io::Result<()> {
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if let Ok(target) = fs::read_link(entry.path())
            && target.to_string_lossy().contains("kvm")
        {
            let fd = entry
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .map_err(|_| io::Error::other("Invalid KVM descriptor"))?;
            if !retained.contains(&fd) {
                return Err(io::Error::other(
                    "Unexpected KVM descriptor survived teardown",
                ));
            }
        }
    }
    Ok(())
}

/// Linux vhost_task workers execute only a kernel callback. In kernels that
/// use one for KVM NX huge-page recovery it shares the thread group, but never
/// enters userspace or writes guest RAM. PF_USER_WORKER cannot be set by prctl.
/// Pin its TID and start time before teardown, rather than trusting a task name
/// or allowing arbitrary kernel workers at the final fork barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
struct KernelMmuWorker {
    tid: u32,
    start_time: u64,
}

fn parse_mmu_worker(tid: u32, stat: &str) -> Option<KernelMmuWorker> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if stat.get(open + 1..close)? != "kvm-nx-lpage-re" {
        return None;
    }
    let fields: Vec<_> = stat.get(close + 1..)?.split_whitespace().collect();
    let flags: u64 = fields.get(6)?.parse().ok()?;
    const PF_USER_WORKER: u64 = 0x00004000;
    if flags & PF_USER_WORKER == 0 {
        return None;
    }
    Some(KernelMmuWorker {
        tid,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

fn capture_mmu_worker() -> io::Result<Option<KernelMmuWorker>> {
    let mut worker = None;
    for task in fs::read_dir("/proc/self/task")? {
        let task = task?;
        let tid = task
            .file_name()
            .to_string_lossy()
            .parse()
            .map_err(io::Error::other)?;
        let stat = match fs::read_to_string(task.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if let Some(found) = parse_mmu_worker(tid, &stat) {
            if worker.replace(found).is_some() {
                return Err(io::Error::other("Multiple KVM MMU workers"));
            }
        }
    }
    Ok(worker)
}

fn wait_for_single_thread(worker: Option<&KernelMmuWorker>) -> io::Result<()> {
    let quiesce = Instant::now();
    loop {
        let tasks = fs::read_dir("/proc/self/task")?.collect::<io::Result<Vec<_>>>()?;
        let mut others = 0;
        for task in &tasks {
            let tid: u32 = task
                .file_name()
                .to_string_lossy()
                .parse()
                .map_err(io::Error::other)?;
            if tid == std::process::id() {
                continue;
            }
            let allowed = worker.is_some_and(|expected| {
                expected.tid == tid
                    && fs::read_to_string(task.path().join("stat"))
                        .ok()
                        .and_then(|stat| parse_mmu_worker(tid, &stat))
                        .as_ref()
                        == Some(expected)
            });
            if !allowed {
                others += 1;
            }
        }
        if others == 0 {
            break;
        }
        if quiesce.elapsed() >= Duration::from_millis(100) {
            return Err(io::Error::other(format!(
                "Refusing fork with {others} unquiesced host threads"
            )));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

/// Opt-in monotonic timeline. Shared origin survives host fork; PID distinguishes
/// parallel reconstruction in parent/child. No locks or worker handles are retained.
#[derive(Clone)]
pub struct ForkTrace {
    started: Instant,
    operation: String,
}
thread_local! {
    static TRACE: std::cell::RefCell<Option<ForkTrace>> = const { std::cell::RefCell::new(None) };
}
pub fn set_trace(trace: Option<ForkTrace>) {
    TRACE.with(|slot| *slot.borrow_mut() = trace);
}
pub fn trace_point(phase: &str) {
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow().as_ref() {
            trace.mark(phase);
        }
    });
}
/// Restore-only diagnostic scope. Preserve a surrounding fork timeline.
pub(crate) struct RestoreTrace(Option<ForkTrace>);
impl Drop for RestoreTrace {
    fn drop(&mut self) {
        trace_point("restore_done");
        set_trace(self.0.take());
    }
}
pub(crate) fn restore_trace(operation: &str) -> Option<RestoreTrace> {
    std::env::var_os("CH_RESTORE_TIMING")?;
    let previous = TRACE.with(|slot| {
        slot.replace(Some(ForkTrace {
            started: Instant::now(),
            operation: operation.to_owned(),
        }))
    });
    trace_point("restore_begin");
    Some(RestoreTrace(previous))
}

/// Field-order destructor milestone; emits only while a fork trace is active.
pub(crate) struct DropTrace(pub &'static str);
impl Drop for DropTrace {
    fn drop(&mut self) {
        trace_point(self.0);
    }
}
impl ForkTrace {
    pub fn mark(&self, phase: &str) {
        // One pipe write keeps parent/child records intact across processes.
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the supplied thread-local accounting.
        let (cpu_ms, voluntary, involuntary) =
            if unsafe { libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()) } == 0 {
                let usage = unsafe { usage.assume_init() };
                (
                    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64 * 1000.0
                        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1000.0,
                    usage.ru_nvcsw,
                    usage.ru_nivcsw,
                )
            } else {
                (0.0, 0, 0)
            };
        let scheduled = fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
        let mut fields = scheduled.split_whitespace();
        let run_ns = fields
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let wait_ns = fields
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        // SAFETY: gettid has no pointer arguments or side effects.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        // Correlate fork stages with host-side client/RPC CLOCK_MONOTONIC.
        // This diagnostic timestamp is not used for VM lifecycle decisions.
        let mut now = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the writable timespec on success.
        let mono_ns =
            if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, now.as_mut_ptr()) } == 0 {
                // SAFETY: the successful call initialized both timespec fields.
                let now = unsafe { now.assume_init() };
                now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
            } else {
                0
            };
        let line = format!(
            "VM_FORK stage op={} pid={} phase={} elapsed_ms={:.3} cpu_ms={cpu_ms:.3} voluntary={voluntary} involuntary={involuntary} tid={tid} run_ns={run_ns} wait_ns={wait_ns} mono_ns={mono_ns}\n",
            self.operation,
            process::id(),
            phase,
            self.started.elapsed().as_secs_f64() * 1000.0
        );
        let _ = io::stderr().lock().write_all(line.as_bytes());
    }
}

pub type ForkOperations = Arc<Mutex<Vec<ForkOperation>>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkPhase {
    Accepted,
    Restoring,
    Ready,
    Failed,
    ChildExited,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkOperation {
    #[serde(default)]
    pub disk_retirement: Option<Result<(), String>>,
    pub operation_id: String,
    pub state: ForkPhase,
    pub parent_pid: u32,
    pub child_pid: Option<u32>,
    pub child_api_socket: PathBuf,
    pub error: Option<String>,
    pub capture_ms: f64,
    pub parent_ready_ms: Option<f64>,
    pub ready_ms: Option<f64>,
    #[serde(skip)]
    child_start_time: Option<String>,
}

impl ForkOperation {
    pub fn pending(&self) -> bool {
        matches!(self.state, ForkPhase::Accepted | ForkPhase::Restoring)
    }
}

fn process_start_time(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    if fields.first() == Some(&"Z") {
        return None;
    }
    fields.get(19).map(|field| (*field).to_owned())
}

pub fn operations_snapshot(operations: &ForkOperations) -> Vec<ForkOperation> {
    let mut operations = operations.lock().unwrap();
    for op in operations.iter_mut() {
        if op.state == ForkPhase::Ready
            && op.parent_pid == process::id()
            && op.child_pid.is_some_and(|pid| {
                process_start_time(pid).is_none_or(|start| Some(start) != op.child_start_time)
            })
        {
            op.state = ForkPhase::ChildExited;
        }
    }
    operations.clone()
}

/// The only cross-process channel retained during runtime reconstruction.
pub struct ForkBranch {
    pub child: bool,
    stream: UnixStream,
}

impl ForkBranch {
    pub fn report(mut self, result: &Result<(), String>) -> io::Result<()> {
        let data = serde_json::to_vec(result).map_err(io::Error::other)?;
        self.stream.write_all(&data)
    }

    pub fn wait(mut self) -> Result<(), String> {
        let mut data = Vec::new();
        self.stream
            .read_to_end(&mut data)
            .map_err(|e| format!("Child readiness channel: {e}"))?;
        serde_json::from_slice(&data).map_err(|e| format!("Child exited before readiness: {e}"))?
    }
}

#[derive(Clone)]
pub struct ForkState {
    pub operation: ForkOperation,
    pub was_running: bool,
    started: Instant,
    pub request: VmForkConfig,
    pub config: VmConfig,
    snapshot: Snapshot,
    memory: Arc<GuestMemoryMmap>,
    disk_merge: Option<Arc<crate::fork_disk::MergeJob>>,
    vm_retirement: Arc<Mutex<Option<VmRetirement>>>,
    parent_vm: Arc<Mutex<Option<Arc<dyn hypervisor::Vm>>>>,
    mmu_worker: Option<KernelMmuWorker>,
    prepared_disks: Arc<Mutex<Option<crate::fork_disk::PreparedBranch>>>,
    prepared_opens: Arc<Mutex<Vec<block::formats::qcow::PreparedQcowOpen>>>,
    prepared_backings: Arc<Mutex<Vec<block::formats::qcow::PreparedQcowBacking>>>,
    retired_disks: Arc<Mutex<Vec<Box<dyn block::disk_file::ForkRetirement>>>>,
    retirement_peer: Arc<Mutex<Option<UnixStream>>>,
    disk_retirement: Option<Arc<crate::fork_retirement::DiskRetirementJob>>,
}

fn unsupported(reason: &str) -> Error {
    Error::ForkUnsupported(reason.into())
}

fn validate_config(c: &VmConfig) -> Result<(), Error> {
    let m = &c.memory;
    if m.shared
        || m.hugepages
        || m.mergeable
        || m.zones.is_some()
        || m.hotplug_size.is_some()
        || m.hotplugged_size.is_some()
        || m.reserve.unwrap_or(false)
        || c.numa.is_some()
        || c.devices.is_some()
        || c.user_devices.is_some()
        || c.vdpa.is_some()
        || c.net.as_ref().is_some_and(|nets| {
            nets.len() != 1
                || nets.iter().any(|n| {
                    n.tap.is_none()
                        || n.fds.is_some()
                        || n.vhost_user
                        || n.rate_limiter_config.is_some()
                })
        })
        || c.fs.is_some()
        || c.pmem.is_some()
        || c.generic_vhost_user.is_some()
        || c.balloon.is_some()
        || c.tpm.is_some()
        || c.platform.is_some()
        || c.rate_limit_groups.is_some()
        || c.preserved_fds.is_some()
        || c.landlock_enable
        || c.watchdog
        || c.pvpanic
        || c.serial.common.mode != ConsoleOutputMode::Socket
        || c.console.common.mode != ConsoleOutputMode::Off
        || c.disks.as_ref().is_some_and(|disks| {
            disks.iter().any(|d| {
                d.vhost_user
                    || d.path.is_none()
                    || d.rate_limit_group.is_some()
                    || d.rate_limiter_config.is_some()
            })
        })
    {
        return Err(unsupported(
            "Requires private anonymous RAM, socket serial, console off, and local disks; external devices and hotplug are unsupported",
        ));
    }
    #[cfg(target_arch = "x86_64")]
    if c.debug_console.mode != ConsoleOutputMode::Off {
        return Err(unsupported("Debug console must be off"));
    }
    #[cfg(feature = "guest_debug")]
    if c.gdb {
        return Err(unsupported("Guest debug is unsupported"));
    }
    #[cfg(feature = "pvmemcontrol")]
    if c.pvmemcontrol.is_some() {
        return Err(unsupported("pvmemcontrol is unsupported"));
    }
    #[cfg(feature = "ivshmem")]
    if c.ivshmem.is_some() {
        return Err(unsupported("ivshmem is unsupported"));
    }
    Ok(())
}

fn rewrite_net_mac(snapshot: &mut Snapshot, id: &str, mac: &[u8]) -> io::Result<bool> {
    for (name, child) in &mut snapshot.snapshots {
        if name == id {
            let mut state: virtio_devices::net::NetState =
                child.to_owned_state().map_err(io::Error::other)?;
            state.config.mac.copy_from_slice(mac);
            state.fork_identity_reset = true;
            child.snapshot_data = Some(vm_migration::SnapshotData::new_from_owned_state(state));
            return Ok(true);
        }
        if rewrite_net_mac(child, id, mac)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn new_socket_path(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(unsupported(
            "Child socket paths must be absolute file paths",
        ));
    }
    // Canonicalize the directory to catch aliases before comparing endpoints.
    let parent = path
        .parent()
        .unwrap()
        .canonicalize()
        .map_err(|_| unsupported("Child socket directory does not exist"))?;
    let path = parent.join(path.file_name().unwrap());
    if path.as_os_str().len() >= 108 {
        return Err(unsupported(
            "Child socket path exceeds sockaddr_un capacity",
        ));
    }
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    match fs::symlink_metadata(&lock) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        _ => {
            return Err(unsupported(
                "Child socket lock file already exists or is inaccessible",
            ));
        }
    }
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(path),
        _ => Err(unsupported(
            "Child socket path already exists or is inaccessible",
        )),
    }
}

/// One uncommitted preparation per VM. Drop rolls back only owned names.
pub(crate) struct PreparedSnapshotDisks {
    request: Vec<u8>,
    disks: Vec<u8>,
    branch: Option<crate::fork_disk::PreparedBranch>,
}

impl Vmm {
    pub(crate) fn prepare_snapshot_disks(&mut self, request: VmForkConfig) -> Result<(), Error> {
        self.prepared_snapshot_disks.take();
        if !self.fork_enabled || request.snapshot_directory.is_none() {
            return Err(unsupported(
                "Disk preparation requires enabled offline capture",
            ));
        }
        if self
            .fork_operations
            .lock()
            .unwrap()
            .iter()
            .any(ForkOperation::pending)
        {
            return Err(Error::ForkBusy);
        }
        if let Some(job) = self.disk_retirement.take() {
            job.wait().map_err(|e| unsupported(&e.to_string()))?;
        }
        if let Some(job) = self.disk_merge.take() {
            job.finish().map_err(|e| unsupported(&e.to_string()))?;
        }
        let vm = match &self.vm {
            VmOwnership::Owned(vm) if vm.get_state() == VmState::Running => vm,
            _ => return Err(Error::VmNotRunning),
        };
        let config = vm.get_config().lock().unwrap().clone();
        validate_config(&config)?;
        crate::fork_disk::ready_to_pause(&config).map_err(|e| unsupported(&e.to_string()))?;
        static NEXT_PREPARATION: AtomicU64 = AtomicU64::new(1);
        let operation = format!(
            "prepared-{}-{}",
            process::id(),
            NEXT_PREPARATION.fetch_add(1, Ordering::Relaxed)
        );
        let branch = crate::fork_disk::prepare(&config, &request, &operation)
            .map_err(|e| unsupported(&e.to_string()))?;
        self.prepared_snapshot_disks = Some(PreparedSnapshotDisks {
            request: serde_json::to_vec(&request).unwrap(),
            disks: serde_json::to_vec(&config.disks).unwrap(),
            branch,
        });
        Ok(())
    }

    pub(crate) fn prepare_fork(
        &mut self,
        mut request: VmForkConfig,
    ) -> Result<ForkOperation, Error> {
        if !self.fork_enabled {
            return Err(unsupported(
                "Requires x86_64 KVM, --enable-fork, a path API socket, and no landlock, event monitor, D-Bus or debugger",
            ));
        }
        #[cfg(feature = "kvm")]
        if self.hypervisor.hypervisor_type() != hypervisor::HypervisorType::Kvm {
            return Err(unsupported("Only KVM is supported"));
        }
        if self
            .fork_operations
            .lock()
            .unwrap()
            .iter()
            .any(ForkOperation::pending)
        {
            return Err(Error::ForkBusy);
        }
        let prepared_snapshot = self.prepared_snapshot_disks.take();
        let request_key = serde_json::to_vec(&request).unwrap();
        let vm = match &mut self.vm {
            VmOwnership::Owned(vm) => vm,
            VmOwnership::Migration { .. } => return Err(Error::VmMigrating),
            VmOwnership::None => return Err(Error::VmNotRunning),
        };
        vm.finish_incremental_restore_for_fork()?;
        if vm.restoring() {
            return Err(Error::VmRestoring);
        }
        if vm.get_state() != VmState::Running && vm.get_state() != VmState::Paused {
            return Err(Error::VmNotRunning);
        }
        let config = vm.get_config().lock().unwrap().clone();
        validate_config(&config)?;
        if let Some(prepared) = &prepared_snapshot {
            if prepared.request != request_key
                || prepared.disks != serde_json::to_vec(&config.disks).unwrap()
            {
                return Err(unsupported(
                    "Prepared capture no longer matches request or disks",
                ));
            }
            // PreparedBranch::commit rechecks active inode/path after quiescence.
        } else {
            crate::fork_disk::validate(&config, &request)
                .map_err(|e| unsupported(&e.to_string()))?;
        }
        if let Some(directory) = &mut request.snapshot_directory {
            let metadata = fs::symlink_metadata(&*directory)
                .map_err(|e| unsupported(&format!("Capture directory: {e}")))?;
            if !directory.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink()
                || fs::read_dir(&*directory).map_err(|e| unsupported(&e.to_string()))?.next().is_some()
            {
                return Err(unsupported("Capture requires an empty absolute directory, without a symlink"));
            }
            *directory = directory.canonicalize().map_err(|e| unsupported(&e.to_string()))?;
            if request.child_vsock.is_some() || request.child_net.is_some() {
                return Err(unsupported("Offline capture must not request a running child identity"));
            }
        }
        request.child_api_socket = new_socket_path(&request.child_api_socket)?;
        request.child_serial_socket = new_socket_path(&request.child_serial_socket)?;
        let api_lock = PathBuf::from(format!("{}.lock", request.child_api_socket.display()));
        let serial_lock = PathBuf::from(format!("{}.lock", request.child_serial_socket.display()));
        if request.child_api_socket == request.child_serial_socket
            || request.child_api_socket == serial_lock
            || request.child_serial_socket == api_lock
        {
            return Err(unsupported(
                "Child API and serial sockets and their lock files must differ",
            ));
        }
        if request.snapshot_directory.is_none() {
            match (&config.vsock, &mut request.child_vsock) {
                (Some(parent), Some(child)) => {
                    if child.cid <= 2 || child.cid == u32::MAX || child.cid == parent.cid {
                        return Err(unsupported(
                            "Child vsock CID must be distinct and greater than 2",
                        ));
                    }
                    child.socket = new_socket_path(&child.socket)?;
                    let child_lock = PathBuf::from(format!("{}.lock", child.socket.display()));
                    if child.socket == request.child_api_socket
                        || child.socket == request.child_serial_socket
                        || child.socket == api_lock
                        || child.socket == serial_lock
                        || child_lock == request.child_api_socket
                        || child_lock == request.child_serial_socket
                    {
                        return Err(unsupported("Child vsock socket must be independent"));
                    }
                    // Only CID and backend path may change; preserve PCI topology.
                    child.pci_common = parent.pci_common.clone();
                }
                (None, None) => {}
                _ => {
                    return Err(unsupported(
                        "A vsock source requires child_vsock CID and socket",
                    ));
                }
            }
            match (
                config.net.as_ref(),
                request.child_net.as_mut(),
                request.child_netns.as_ref(),
            ) {
                (Some(parent), Some(child), Some(netns)) => {
                    if child.mac.is_none()
                        || child.mac == parent[0].mac
                        || child.tap.is_none()
                        || child.fds.is_some()
                        || child.vhost_user
                        || child.num_queues != parent[0].num_queues
                        || !netns.is_absolute()
                        || !netns.exists()
                    {
                        return Err(unsupported(
                            "Child requires an independent named TAP, MAC and network namespace",
                        ));
                    }
                    use std::os::unix::fs::MetadataExt;
                    let target = fs::metadata(netns)
                        .map_err(|_| unsupported("Invalid child network namespace"))?;
                    let current = fs::metadata("/proc/self/ns/net")
                        .map_err(|_| unsupported("Cannot inspect parent network namespace"))?;
                    if target.ino() == current.ino() && target.dev() == current.dev() {
                        return Err(unsupported(
                            "Child network namespace must differ from parent",
                        ));
                    }
                    // Preserve negotiated features and PCI/queue topology exactly.
                    let tap = child.tap.clone();
                    let mac = child.mac;
                    *child = parent[0].clone();
                    child.tap = tap;
                    child.mac = mac;
                    let mut checked = config.clone();
                    checked.net = Some(vec![child.clone()]);
                    validate_config(&checked)?;
                }
                (None, None, None) => {}
                _ => {
                    return Err(unsupported(
                        "Fork requires matching parent and child network topology",
                    ));
                }
            }
        }
        if let Some(job) = &self.disk_retirement {
            job.wait().map_err(|e| unsupported(&e.to_string()))?;
        }
        self.disk_retirement.take();
        if let Some(job) = self.disk_merge.take() {
            job.finish().map_err(|e| unsupported(&e.to_string()))?;
        }
        crate::fork_disk::ready_to_pause(&config).map_err(|e| unsupported(&e.to_string()))?;
        static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);

        let operation_id = format!(
            "{}-{}",
            process::id(),
            NEXT_OPERATION.fetch_add(1, Ordering::Relaxed)
        );
        let preparation_started = Instant::now();
        let running = vm.get_state() == VmState::Running;
        let prepared_disks = if let Some(prepared) = prepared_snapshot {
            prepared.branch
        } else {
            crate::fork_disk::prepare(&config, &request, &operation_id)
                .map_err(|e| unsupported(&e.to_string()))?
        };
        fork_log!(
            "VM_FORK disk_prepare_before_pause_ms={:.3} guest_running={running}",
            preparation_started.elapsed().as_secs_f64() * 1000.0
        );
        let backing_started = Instant::now();
        let prepared_backings = vm
            .prepare_fork_backings()
            .map_err(|e| unsupported(&e.to_string()))?;
        fork_log!(
            "VM_FORK backing_prepare op={operation_id} elapsed_ms={:.3} guest_running={running}",
            backing_started.elapsed().as_secs_f64() * 1000.0
        );
        // An explicit legacy switch supports controlled same-binary comparisons.
        let parent_vm = if std::env::var_os("CH_FORK_REBUILD_PARENT").is_some() {
            None
        } else {
            vm.fork_reusable_vm()
        };
        let reuse = parent_vm.is_some();
        let mmu_worker = if reuse {
            capture_mmu_worker().map_err(|e| unsupported(&e.to_string()))?
        } else {
            None
        };
        let retirement_prepare = Instant::now();
        let mut cpu_retirement =
            PreparedRetirement::new(move |cpus| retire_cpu_threads(cpus, reuse))
                .map_err(|e| unsupported(&e.to_string()))?;
        let mut vm_retirement = if reuse {
            None
        } else {
            Some(
                VmRetirement::new(|(retired, trace)| {
                    set_trace(trace);
                    trace_point("retired_vm_drop_begin");
                    drop(retired);
                    trace_point("retired_vm_drop_done");
                })
                .map_err(|e| unsupported(&e.to_string()))?,
            )
        };
        fork_log!(
            "VM_FORK retirement_worker_prepare op={operation_id} elapsed_ms={:.3} guest_running={running}",
            retirement_prepare.elapsed().as_secs_f64() * 1000.0
        );
        // Preflush last: opening the sealed prefix may block on disk IO.
        // Putting that work after preflush leaves time for new dirty metadata
        // to accumulate before the vCPUs are stopped. The final checkpoint is
        // still mandatory even with this smaller write window.
        if running {
            let preflush_started = Instant::now();
            vm.preflush_fork_disks()
                .map_err(|e| unsupported(&e.to_string()))?;
            fork_log!(
                "VM_FORK disk_preflush op={operation_id} elapsed_ms={:.3} guest_running=true",
                preflush_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        // New empty disk metadata is prepared with the guest running. Already
        // paused callers retain that preparation time in their pause accounting.
        let started = if running {
            Instant::now()
        } else {
            preparation_started
        };
        set_trace(std::env::var_os("CH_FORK_TIMING").map(|_| ForkTrace {
            started,
            operation: operation_id.clone(),
        }));
        trace_point("pause_begin");
        if running {
            vm.pause().map_err(Error::Pause)?;
        }
        let snapshot = match vm.snapshot() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                if running {
                    vm.resume().map_err(Error::Resume)?;
                }
                return Err(Error::Snapshot(e));
            }
        };
        trace_point("snapshot_done");
        let memory = vm.guest_memory().memory().into_inner();
        let retired_disks = Arc::new(Mutex::new(vm.retain_fork_disks()));
        let retired_vm = if reuse {
            // This is a teardown commit after snapshot: a partial detach cannot
            // safely resume the old device graph. Fail closed on ioctl errors.
            trace_point("events_detach_begin");
            if let Err(error) = vm.detach_fork_events(request.snapshot_directory.is_some()) {
                fork_log!("FATAL: cannot detach old KVM events: {error}");
                process::exit(1);
            }
            trace_point("events_detach_done");
            None
        } else {
            Some(vm.retain_fork_vm())
        };
        let retired_cpus = vm.retain_fork_cpu_threads();
        let retirement_trace = std::env::var_os("CH_FORK_TIMING").map(|_| ForkTrace {
            started,
            operation: operation_id.clone(),
        });
        // vCPUs have acknowledged pause and the snapshot is complete. Their
        // loop checks the kill flag before any further KVM_RUN. Device workers
        // are also parked, so device destruction can overlap CPU thread exit.
        if let Err(cpus) = cpu_retirement.submit((retired_cpus, retirement_trace.clone())) {
            retire_cpu_threads(cpus, reuse);
        }
        self.vm = VmOwnership::None;
        self.console_info = None;
        trace_point("vm_dropped");
        if let Err(error) = cpu_retirement.join() {
            fork_log!("FATAL: failed joining fork CPU shutdown: {error}");
            process::exit(1);
        }
        trace_point("cpu_shutdown_joined");
        // Retain all KVM slot mappings through BOTH teardown branches. Only
        // then may the final KVM owner be retired concurrently with API exit.
        if let (Some(worker), Some(retired)) = (&mut vm_retirement, retired_vm) {
            let _ = worker.submit((retired, retirement_trace));
        }
        let operation = ForkOperation {
            disk_retirement: None,
            operation_id,
            state: ForkPhase::Accepted,
            parent_pid: process::id(),
            child_pid: None,
            child_api_socket: request.child_api_socket.clone(),
            error: None,
            capture_ms: started.elapsed().as_secs_f64() * 1000.0,
            parent_ready_ms: None,
            ready_ms: None,
            child_start_time: None,
        };
        let mut operations = self.fork_operations.lock().unwrap();
        if operations.len() == 64 {
            operations.remove(0);
        }
        operations.push(operation.clone());
        self.fork_state = Some(ForkState {
            operation: operation.clone(),
            was_running: running,
            started,
            request,
            config,
            snapshot,
            memory,
            disk_merge: None,
            vm_retirement: Arc::new(Mutex::new(vm_retirement)),
            parent_vm: Arc::new(Mutex::new(parent_vm)),
            mmu_worker,
            prepared_disks: Arc::new(Mutex::new(prepared_disks)),
            prepared_opens: Arc::default(),
            prepared_backings: Arc::new(Mutex::new(prepared_backings)),
            retired_disks,
            retirement_peer: Arc::default(),
            disk_retirement: None,
        });
        Ok(operation)
    }

    pub(crate) fn restore_fork(&mut self, state: ForkState) -> Result<(), Error> {
        let _prepared_opens = block::formats::qcow::PreparedQcowScope::enter_with_backings(
            std::mem::take(&mut *state.prepared_opens.lock().unwrap()),
            std::mem::take(&mut *state.prepared_backings.lock().unwrap()),
        );
        self.fork_pause_started = Some(state.started);
        self.disk_merge = state.disk_merge;
        self.disk_retirement = state.disk_retirement;
        self.vm_config = Some(Arc::new(Mutex::new(state.config)));
        self.console_info =
            Some(pre_create_console_devices(self).map_err(Error::CreateConsoleDevices)?);
        let mut vm = Vm::new_with_inherited_memory(
            self.vm_config.clone().unwrap(),
            self.exit_evt.try_clone().map_err(Error::EventFdClone)?,
            self.reset_evt.try_clone().map_err(Error::EventFdClone)?,
            self.guest_exit_evt
                .try_clone()
                .map_err(Error::EventFdClone)?,
            #[cfg(feature = "guest_debug")]
            self.vm_debug_evt.try_clone().map_err(Error::EventFdClone)?,
            &self.seccomp_action,
            Arc::clone(&self.hypervisor),
            self.activate_evt.try_clone().map_err(Error::EventFdClone)?,
            self.console_info.clone(),
            self.console_resize_pipe.clone(),
            Arc::clone(&self.original_termios_opt),
            Some(&state.snapshot),
            None,
            Some(false),
            None,
            Some(&state.memory),
            state.parent_vm.lock().unwrap().take(),
        )?;
        trace_point("vm_constructed");
        vm.restore()?;
        trace_point("vcpu_threads_ready");
        // Leave both machines paused. The API client reconnects serial sockets
        // and explicitly resumes each branch, so no guest output/input is lost.
        self.vm = VmOwnership::Owned(vm);
        Ok(())
    }
}

impl ForkState {
    pub fn trace(&self) -> Option<ForkTrace> {
        std::env::var_os("CH_FORK_TIMING").map(|_| ForkTrace {
            started: self.started,
            operation: self.operation.operation_id.clone(),
        })
    }
    pub fn mark(&self, phase: &str) {
        if let Some(trace) = self.trace() {
            trace.mark(phase);
        }
    }
    pub fn start_disk_retirement(&mut self, operations: ForkOperations) -> io::Result<()> {
        let disks = std::mem::take(&mut *self.retired_disks.lock().unwrap());
        let peer = self.retirement_peer.lock().unwrap().take();
        match crate::fork_retirement::DiskRetirementJob::spawn(
            disks,
            peer,
            self.operation.parent_pid == process::id(),
            self.operation.operation_id.clone(),
            Arc::clone(&operations),
        ) {
            Ok(job) => {
                self.disk_retirement = Some(job);
                Ok(())
            }
            Err(error) => {
                if let Some(op) = operations
                    .lock()
                    .unwrap()
                    .iter_mut()
                    .find(|op| op.operation_id == self.operation.operation_id)
                {
                    op.disk_retirement = Some(Err(error.to_string()));
                }
                Err(error)
            }
        }
    }

    /// On failure the old image may still be the writable top: close its old
    /// owner before reopening, so a delayed clean marker cannot race new writes.
    pub fn finish_disks_before_rollback(&mut self) -> io::Result<()> {
        let disks = std::mem::take(&mut *self.retired_disks.lock().unwrap());
        let mut result = Ok(());
        for disk in disks {
            if let Err(error) = disk.finish() {
                result = Err(io::Error::other(error));
            }
        }
        result
    }

    /// Spawn before narrowed runtime workers, but after the single-threaded fork.
    pub fn start_disk_merge(&mut self) -> io::Result<()> {
        self.disk_merge = crate::fork_disk::start_merge(&self.config)?;
        Ok(())
    }
    pub fn parent_ready(&mut self) {
        // All new disk backings are open now. Offline capture has no child VM
        // to restore, so close the old owner while the API/agent resume proceeds.
        // The controller still awaits this result before releasing guest tasks.
        if self.request.snapshot_directory.is_some() {
            if let Some(job) = &self.disk_retirement {
                job.start();
                self.mark("snapshot_disk_retirement_started");
            }
        }
        self.operation.parent_ready_ms = Some(self.started.elapsed().as_secs_f64() * 1000.0);
    }
    pub fn update_operation(
        &mut self,
        operations: &ForkOperations,
        result: Option<Result<(), String>>,
    ) {
        match result {
            None => self.operation.state = ForkPhase::Restoring,
            Some(result) => {
                self.operation.state = if result.is_ok() {
                    ForkPhase::Ready
                } else {
                    ForkPhase::Failed
                };
                self.operation.error = result.err();
                self.operation.ready_ms = Some(self.started.elapsed().as_secs_f64() * 1000.0);
            }
        }
        if let Some(op) = operations
            .lock()
            .unwrap()
            .iter_mut()
            .find(|op| op.operation_id == self.operation.operation_id)
        {
            self.operation.disk_retirement = op.disk_retirement.clone();
            *op = self.operation.clone();
        }
    }

    /// Called by the main supervisor after joining ALL runtime threads.
    /// Returns the branch's readiness channel. On failure the supervisor keeps
    /// this state and restores the original VM instead of discarding its RAM.
    pub fn fork_host(&mut self) -> io::Result<ForkBranch> {
        // PSS walks every resident guest page; keep diagnostic accounting out
        // of the normal pause window. This flag is inherited unchanged by the
        // child, while the readiness and optional PFN barriers remain active.
        let account_pss = std::env::var_os("CH_FORK_ACCOUNT_PSS").is_some();
        // Even after all managed JoinHandles have returned, require the kernel's
        // task list to converge to the main userspace thread and, on kernels
        // using vhost_task, the pinned kernel-only KVM MMU worker. Every other
        // surviving task causes bounded failure. Retained KVM objects own no
        // userspace worker or external RAM writer.
        let mut retirement = self.vm_retirement.lock().unwrap().take();
        let preparation: io::Result<_> = (|| {
            // Device/disk owners have already been destroyed. Only the final
            // VM fd and slot mapping retire concurrently with independent
            // disk preparation and read-only RAM accounting.
            let mut prepared = self.prepared_disks.lock().unwrap().take();
            if let Some(prepared) = &mut prepared {
                *self.prepared_opens.lock().unwrap() = std::mem::take(&mut prepared.opens);
            }
            let disks = crate::fork_disk::commit(&mut self.config, prepared)?;
            self.mark("disk_branched");
            for region in self.memory.iter() {
                let start = region.as_ptr() as usize;
                fork_log!(
                    "VM_FORK ram_range={start:x}-{:x}",
                    start + region.len() as usize
                );
            }
            let before = if account_pss {
                Some(self.ram_pss()?)
            } else {
                None
            };
            self.mark("pss_before_done");
            Ok((disks, before))
        })();
        if let Some(worker) = &mut retirement {
            worker.join()?;
        }
        let (child_disks, before) = preparation?;
        self.mark("retirement_joined");
        wait_for_single_thread(self.mmu_worker.as_ref())?;
        let retained_fds = self
            .parent_vm
            .lock()
            .unwrap()
            .as_ref()
            .map(|vm| vm.fork_raw_fds())
            .unwrap_or_default();
        check_kvm_descriptors(&retained_fds)?;
        fork_log!(
            "VM_FORK retained_parent_kvm pid={} fds={retained_fds:?}",
            process::id()
        );
        self.mark("single_thread_ready");
        self.mark("fork_boundary_ready");
        fork_log!("VM_FORK boundary threads=1 ram_pss_kib={before:?}");
        // Keep the child quiescent until optional RAM diagnostics finish,
        // before either process restores/runs a VM.
        let (mut a, mut b) = UnixStream::pair()?;
        let (retire_parent, retire_child) = UnixStream::pair()?;
        a.set_read_timeout(Some(Duration::from_secs(30)))?;
        b.set_read_timeout(Some(Duration::from_secs(30)))?;
        // SAFETY: all application workers have been joined; the check above
        // also rejects unexpected kernel/foreign workers. No KVM fd survives.
        // Supported RAM is private and has no DMA/external writers. Thus no
        // lock is owned by a vanished thread and both processes may use Rust.
        self.mark("host_fork_begin");
        let mut scheduling = match ForkScheduling::enter() {
            Ok(guard) => guard,
            Err(error) => {
                fork_log!("VM_FORK scheduling_unavailable error={error}");
                None
            }
        };
        let protected = scheduling.is_some();
        let pid = unsafe { libc::fork() };
        // Capture errno before restoring the scheduling policy.
        let fork_error = (pid < 0).then(io::Error::last_os_error);
        if let Some(guard) = &mut scheduling {
            guard.restore()?;
        }
        self.mark("host_fork_done");
        fork_log!(
            "VM_FORK scheduling_restored op={} pid={} protected={} policy={} nice={}",
            self.operation.operation_id,
            process::id(),
            protected,
            unsafe { libc::sched_getscheduler(0) },
            unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }
        );
        if let Some(error) = fork_error {
            fork_log!("VM_FORK failed: {error}; restoring parent");
            return Err(error);
        }
        if pid == 0 {
            // Only close inherited references: KvmVm/KvmVcpu destruction here
            // performs no ioctl. Old buses/events were detached BEFORE fork.
            // The child must never operate on a KVM owned by the parent's mm.
            self.parent_vm.lock().unwrap().take();
            check_kvm_descriptors(&[])?;
            self.mark("inherited_parent_kvm_closed");
            if let Some(disks) = child_disks {
                self.config.disks = Some(disks);
            }
            drop(a);
            drop(retire_parent);
            *self.retirement_peer.lock().unwrap() = Some(retire_child);
            if account_pss {
                b.write_all(&self.ram_pss()?.to_ne_bytes())?;
            }
            let mut ready = [0];
            b.read_exact(&mut ready)?;
            if self.request.snapshot_directory.is_some() {
                return Ok(ForkBranch { child: true, stream: b });
            }
            self.config.serial.common.socket = Some(self.request.child_serial_socket.clone());
            self.config.vsock = self.request.child_vsock.clone();
            if let Some(net) = self.request.child_net.clone() {
                use std::os::fd::AsRawFd;
                let namespace = fs::File::open(self.request.child_netns.as_ref().unwrap())?;
                // SAFETY: the child is single-threaded and owns no live VM/devices.
                // All subsequently created workers inherit its independent namespace.
                if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                let id = net
                    .pci_common
                    .id
                    .as_ref()
                    .ok_or_else(|| io::Error::other("Missing NIC ID"))?;
                if !rewrite_net_mac(&mut self.snapshot, id, net.mac.unwrap().get_bytes())? {
                    return Err(io::Error::other("Missing NIC snapshot"));
                }
                self.config.net = Some(vec![net]);
            }

            fork_log!(
                "VM_FORK child pid={} api={}",
                process::id(),
                self.request.child_api_socket.display()
            );
            self.operation.child_pid = Some(process::id());
            Ok(ForkBranch {
                child: true,
                stream: b,
            })
        } else {
            drop(b);
            drop(retire_child);
            *self.retirement_peer.lock().unwrap() = Some(retire_parent);
            let mut child_guard = UncommittedChild(Some(pid));
            // Both read-only checks observe the same quiescent RAM. Run the
            // complete PFN comparison alongside PSS accounting, then join it
            // before releasing the child or rebuilding either runtime.
            let mut account = || {
                let Some(before) = before else {
                    return Ok(());
                };
                let parent_pss = self.ram_pss()?;
                let mut child_pss = [0; 8];
                a.read_exact(&mut child_pss)?;
                let total = parent_pss + u64::from_ne_bytes(child_pss);
                fork_log!(
                    "VM_FORK parent pid={} child_pid={pid} combined_ram_pss_kib={total} baseline_kib={before}",
                    process::id()
                );
                self.mark("pss_after_done");
                Ok(())
            };
            let pages = if std::env::var_os("CH_FORK_VERIFY_PAGES").is_some() {
                let memory = self.memory.clone();
                let operation = self.operation.operation_id.clone();
                let (pages, ()) = verify_while_accounting(
                    move || {
                        let started = Instant::now();
                        let result = verify_shared_ram(&memory, pid as u32);
                        fork_log!(
                            "VM_FORK ram_verification op={operation} elapsed_ms={:.3} success={}",
                            started.elapsed().as_secs_f64() * 1000.0,
                            result.is_ok()
                        );
                        result
                    },
                    account,
                )?;
                Some(pages)
            } else {
                account()?;
                None
            };
            if let Some(pages) = pages {
                fork_log!("VM_FORK ram_shared_present_pages={pages} mismatched_pages=0");
            }
            self.mark("verification_done");
            a.write_all(&[1])?;
            self.operation.child_pid = Some(pid as u32);
            self.operation.child_start_time = process_start_time(pid as u32);
            child_guard.0 = None;
            Ok(ForkBranch {
                child: false,
                stream: a,
            })
        }
    }

    /// Runs only in the single-threaded CoW capture child, without a KVM VM.
    pub fn save_frozen_snapshot(&self) -> io::Result<()> {
        let directory = self.request.snapshot_directory.as_ref()
            .ok_or_else(|| io::Error::other("Missing capture directory"))?;
        let result = (|| {
            // Do not compete with parent runtime reconstruction for CPU and
            // page faults. Reuse the durability channel, without a new thread
            // or polling file. Parent loss/failure must not publish a snapshot.
            let peer = self.retirement_peer.lock().unwrap().take()
                .ok_or_else(|| io::Error::other("Missing capture retirement channel"))?;
            peer.set_read_timeout(Some(std::time::Duration::from_secs(45)))?;
            let mut bytes = Vec::new();
            peer.take(65536).read_to_end(&mut bytes)?;
            let retired: Result<(), String> = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            retired.map_err(io::Error::other)?;
            self.mark("capture_disk_durable");
            let memory = self.snapshot.snapshots.get("memory-manager")
                .ok_or_else(|| io::Error::other("Missing memory snapshot"))?;
            let full_memory = crate::memory_manager::save_frozen_memory(memory, &self.memory, directory)?;
            let mut snapshot = self.snapshot.clone();
            snapshot.snapshots.insert("memory-manager".into(), full_memory);
            for (name, bytes) in [("config.json", serde_json::to_vec(&self.config)),
                                  ("state.json", serde_json::to_vec(&snapshot))] {
                let mut f = fs::OpenOptions::new().write(true).create_new(true).open(directory.join(name))?;
                f.write_all(&bytes.map_err(io::Error::other)?)?;
                f.sync_all()?;
            }
            Ok::<_, io::Error>(())
        })();
        let status = serde_json::to_vec(&result.as_ref().map(|_| ()).map_err(|e| e.to_string()))
            .map_err(io::Error::other)?;
        let temporary = directory.join("capture-status.pending");
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        f.write_all(&status)?;
        f.sync_all()?;
        fs::rename(temporary, directory.join("capture-status.json"))?;
        fs::File::open(directory)?.sync_all()?;
        result
    }

    fn ram_pss(&self) -> io::Result<u64> {
        let smaps = fs::read_to_string("/proc/self/smaps")?;
        ram_pss_from_smaps(&smaps, |start, end| {
            self.memory.iter().any(|region| {
                let base = region.as_ptr() as usize;
                start >= base && end <= base + region.len() as usize
            })
        })
    }
}

// smaps address headers begin with a lowercase hexadecimal address; its metric
// names begin with uppercase letters. Avoid parsing every metric as an address.
// Still account for every VMA wholly contained in guest RAM, including split VMAs.
fn ram_pss_from_smaps(smaps: &str, contains: impl Fn(usize, usize) -> bool) -> io::Result<u64> {
    let mut in_ram = false;
    let mut total = 0;
    for line in smaps.lines() {
        if matches!(line.as_bytes().first(), Some(b'0'..=b'9' | b'a'..=b'f')) {
            in_ram = false;
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                in_ram = contains(start, end);
            }
        } else if in_ram && let Some(value) = line.strip_prefix("Pss:") {
            total += value
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(io::Error::other)?;
        }
    }
    Ok(total)
}

// Always join the post-fork verifier, including accounting failures. No worker
// may outlive the quiescent barrier. This does not change verification coverage.
fn verify_while_accounting<T: Send, U>(
    verify: impl FnOnce() -> io::Result<T> + Send,
    account: impl FnOnce() -> io::Result<U>,
) -> io::Result<(T, U)> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("fork-verify".into())
            .spawn_scoped(scope, verify)?;
        let accounted = account();
        let verified = worker
            .join()
            .map_err(|_| io::Error::other("RAM verifier panicked"))?;
        Ok((verified?, accounted?))
    })
}

// Optional research verification at the same barrier as PSS sampling.
// With older live descendants, pairwise PSS changes its denominator and is
// not a copy detector. PFN identity is independent of that sharing count.
fn verify_shared_ram(memory: &GuestMemoryMmap, child_pid: u32) -> io::Result<u64> {
    use std::os::unix::fs::FileExt;
    let parent = fs::File::open("/proc/self/pagemap")?;
    let child = fs::File::open(format!("/proc/{child_pid}/pagemap"))?;
    // SAFETY: sysconf has no pointer arguments or side effects here.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let mut left = [0u8; 32768];
    let mut right = [0u8; 32768];
    let mut present = 0;
    for region in memory.iter() {
        let base = region.as_ptr() as u64 / page_size;
        let pages = region.len().div_ceil(page_size);
        let mut position = 0;
        while position < pages {
            let count = (pages - position).min((left.len() / 8) as u64) as usize;
            present += verify_page_chunk(
                &mut left[..count * 8],
                &mut right[..count * 8],
                |left, right| {
                    parent.read_exact_at(left, (base + position) * 8)?;
                    child.read_exact_at(right, (base + position) * 8)
                },
            )?;
            position += count as u64;
        }
    }
    Ok(present)
}

// Pagemap reads across processes are not atomic. Re-read a mismatching
// chunk at the quiescent barrier; never accept a persistent mismatch.
fn verify_page_chunk(
    left: &mut [u8],
    right: &mut [u8],
    mut read: impl FnMut(&mut [u8], &mut [u8]) -> io::Result<()>,
) -> io::Result<u64> {
    for attempt in 0..3 {
        read(left, right)?;
        match compare_page_entries(left, right) {
            Ok(pages) => return Ok(pages),
            Err(error) if attempt == 2 => return Err(error),
            Err(error) => fork_log!(
                "VM_FORK pagemap_recheck attempt={} error={error}",
                attempt + 1
            ),
        }
    }
    unreachable!()
}

// Until the barrier succeeds, the parent exclusively owns this unreaped child.
struct UncommittedChild(Option<libc::pid_t>);
impl Drop for UncommittedChild {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: this is our unreaped child, so its PID cannot be reused.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            loop {
                // SAFETY: null status is permitted; wait only for our child.
                if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } >= 0
                    || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                {
                    break;
                }
            }
        }
    }
}

/// Equal buffers take the bulk comparison path; still inspect every present
/// entry for masked PFNs. Differing software-only flags use the masked fallback.
fn compare_page_entries(left: &[u8], right: &[u8]) -> io::Result<u64> {
    if left.len() != right.len() || !left.len().is_multiple_of(8) {
        return Err(io::Error::other("Invalid pagemap buffer length"));
    }
    const PFN_MASK: u64 = (1 << 55) - 1;
    let mut present = 0;
    let left_entries = left.as_chunks::<8>().0;
    if left == right {
        // Keep the common identical-buffer path free of per-entry slice
        // conversion, indexing and the differing-buffer branch. Every entry is
        // still checked for masked PFNs; equality alone is not sufficient.
        for entry in left_entries {
            let a = u64::from_ne_bytes(*entry);
            if a & (1 << 63) != 0 {
                if a & PFN_MASK == 0 {
                    return Err(io::Error::other(
                        "RAM PFN verification requires CAP_SYS_ADMIN",
                    ));
                }
                present += 1;
            }
        }
    } else {
        for (left, right) in left_entries.iter().zip(right.as_chunks::<8>().0) {
            let a = u64::from_ne_bytes(*left);
            let b = u64::from_ne_bytes(*right);
            if a & (1 << 63) != 0 {
                if a & PFN_MASK == 0 {
                    return Err(io::Error::other(
                        "RAM PFN verification requires CAP_SYS_ADMIN",
                    ));
                }
                present += 1;
            }
            if (a ^ b) & (PFN_MASK | (3 << 62)) != 0 {
                return Err(io::Error::other("Fork RAM physical pages differ"));
            }
        }
    }
    Ok(present)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn ram_pss_accounts_split_regions_and_excludes_other_mappings() {
        let smaps = "1000-2000 rw-p 0 00:00 0\nPss: 999 kB\n\
                     a000-b000 rw-p 0 00:00 0\nAnonymous: 4 kB\nPss: 2 kB\nPss_Anon: 2 kB\n\
                     b000-c000 rw-p 0 00:00 0\nPss: 3 kB\n\
                     c000-e000 rw-p 0 00:00 0\nPss: 999 kB\n";
        assert_eq!(
            ram_pss_from_smaps(smaps, |s, e| s >= 0xa000 && e <= 0xc000).unwrap(),
            5
        );
        assert!(ram_pss_from_smaps("a000-b000 rw-p 0\nPss: invalid kB\n", |_, _| true).is_err());
    }

    #[test]
    fn fork_scheduling_restores_parent_and_resets_child() {
        let mut guard = match ForkScheduling::enter() {
            Ok(Some(guard)) => guard,
            result => {
                assert!(
                    std::env::var_os("CH_TEST_REQUIRE_FORK_SCHEDULING").is_none(),
                    "privileged scheduling test was required but unavailable: {}",
                    result.is_err()
                );
                return;
            }
        };
        assert_eq!(
            unsafe { libc::sched_getscheduler(0) },
            libc::SCHED_FIFO | libc::SCHED_RESET_ON_FORK
        );
        // SAFETY: the test child performs ONLY raw scheduling queries and
        // _exit, never Rust allocation/locks, even in the threaded test runner.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let policy = unsafe { libc::syscall(libc::SYS_sched_getscheduler, 0) };
            let nice = unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, 0) };
            unsafe {
                libc::_exit(i32::from(
                    policy != libc::SCHED_OTHER as libc::c_long || nice != 20,
                ))
            };
        }
        guard.restore().unwrap();
        assert_eq!(unsafe { libc::sched_getscheduler(0) }, libc::SCHED_OTHER);
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }, 0);
        assert!(pid > 0);
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted
            );
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn uncommitted_child_is_killed_and_reaped() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        drop(UncommittedChild(Some(child.id() as libc::pid_t)));
        assert_eq!(
            child.try_wait().unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn pagemap_recheck_requires_matching_physical_pages() {
        let mut left = [0; 8];
        let mut right = [0; 8];
        let mut calls = 0;
        let resident = (1u64 << 63) | 123;
        assert_eq!(
            verify_page_chunk(&mut left, &mut right, |a, b| {
                calls += 1;
                a.copy_from_slice(&resident.to_ne_bytes());
                b.copy_from_slice(&(resident + u64::from(calls == 1)).to_ne_bytes());
                Ok(())
            })
            .unwrap(),
            1
        );
        assert_eq!(calls, 2);
        assert!(
            verify_page_chunk(&mut left, &mut right, |a, b| {
                a.copy_from_slice(&resident.to_ne_bytes());
                b.copy_from_slice(&(resident + 1).to_ne_bytes());
                Ok(())
            })
            .is_err()
        );
    }

    #[test]
    fn pagemap_bulk_and_masked_paths_preserve_full_verification() {
        let resident = (1u64 << 63) | 123;
        let bytes = [resident.to_ne_bytes(), 0u64.to_ne_bytes()].concat();
        assert_eq!(compare_page_entries(&bytes, &bytes).unwrap(), 1);
        assert_eq!(
            compare_page_entries(
                &resident.to_ne_bytes(),
                &(resident | (1 << 55)).to_ne_bytes()
            )
            .unwrap(),
            1
        );
        for changed in [resident + 1, resident ^ (1 << 63), resident | (1 << 62)] {
            assert!(compare_page_entries(&resident.to_ne_bytes(), &changed.to_ne_bytes()).is_err());
        }
        let masked = (1u64 << 63).to_ne_bytes();
        assert!(compare_page_entries(&masked, &masked).is_err());
        assert!(compare_page_entries(&[0], &[0]).is_err());
        assert!(compare_page_entries(&bytes, &[]).is_err());
    }

    #[test]
    fn pagemap_array_paths_check_every_entry() {
        let entries: Vec<u64> = (1..=4051).map(|pfn| (1 << 63) | pfn).collect();
        let left: Vec<u8> = entries
            .iter()
            .flat_map(|entry| entry.to_ne_bytes())
            .collect();
        assert_eq!(compare_page_entries(&left, &left).unwrap(), 4051);
        for index in [0, 2048, 4050] {
            let mut right = left.clone();
            right[index * 8..index * 8 + 8]
                .copy_from_slice(&(entries[index] | (1 << 55)).to_ne_bytes());
            assert_eq!(compare_page_entries(&left, &right).unwrap(), 4051);
            right[index * 8..index * 8 + 8].copy_from_slice(&(entries[index] + 1).to_ne_bytes());
            assert!(compare_page_entries(&left, &right).is_err());
            right[index * 8..index * 8 + 8].copy_from_slice(&(1u64 << 63).to_ne_bytes());
            assert!(compare_page_entries(&right, &right).is_err());
        }
    }

    #[test]
    fn verification_overlaps_accounting_and_joins_on_failure() {
        for verify_fail in [false, true] {
            for account_fail in [false, true] {
                let (tx, rx) = std::sync::mpsc::channel();
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                let result = verify_while_accounting(
                    move || {
                        rx.recv().unwrap();
                        done_tx.send(()).unwrap();
                        if verify_fail {
                            Err(io::Error::other("bad PFN"))
                        } else {
                            Ok(11)
                        }
                    },
                    || {
                        tx.send(()).unwrap();
                        if account_fail {
                            Err(io::Error::other("bad PSS"))
                        } else {
                            Ok(7)
                        }
                    },
                );
                done_rx.try_recv().unwrap();
                assert_eq!(result.is_err(), verify_fail || account_fail);
                if let Ok(pair) = result {
                    assert_eq!(pair, (11, 7));
                }
            }
        }
        assert!(
            verify_while_accounting(|| -> io::Result<()> { panic!("verifier") }, || Ok(()))
                .is_err()
        );
    }

    #[test]
    fn prepared_retirement_joins_on_submit_and_abort() {
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_completed = completed.clone();
        let mut worker = PreparedRetirement::new(move |value: bool| {
            worker_completed.store(value, Ordering::Release);
        })
        .unwrap();
        assert!(!completed.load(Ordering::Acquire));
        worker.submit(true).unwrap();
        worker.join().unwrap();
        assert_eq!(worker.submit(false), Err(false));
        assert!(completed.load(Ordering::Acquire));
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = PreparedRetirement::new(move |(): ()| {
            tx.send(()).unwrap();
        })
        .unwrap();
        drop(worker);
        assert!(rx.recv().is_err());
    }

    #[test]
    fn retirement_panic_prevents_fork() {
        let mut worker = PreparedRetirement::new(|(): ()| panic!("retirement failure")).unwrap();
        worker.submit(()).unwrap();
        assert!(worker.join().is_err());
    }

    fn supported() -> VmConfig {
        serde_json::from_value(serde_json::json!({
            "memory": {"size": 268435456, "shared": false},
            "serial": {"mode": "Socket", "socket": "/tmp/source.serial"},
            "console": {"mode": "Off"},
            "disks": [{"path": "/tmp/disk.raw", "readonly": true}]
        }))
        .unwrap()
    }

    #[test]
    fn rejects_shared_ram_and_external_writers() {
        let c = supported();
        validate_config(&c).unwrap();
        let mut changed = c.clone();
        changed.memory.shared = true;
        assert!(validate_config(&changed).is_err());
        let mut changed = c.clone();
        changed.disks.as_mut().unwrap()[0].readonly = false;
        assert!(validate_config(&changed).is_ok());
        let mut changed = c.clone();
        changed.disks.as_mut().unwrap()[0].vhost_user = true;
        assert!(validate_config(&changed).is_err());
        let mut changed = c.clone();
        changed.memory.hotplug_size = Some(4096);
        assert!(validate_config(&changed).is_err());
        let mut changed = c;
        changed.serial.common.mode = ConsoleOutputMode::Tty;
        assert!(validate_config(&changed).is_err());
    }

    #[test]
    fn fork_net_rewrites_only_child_mac_and_rejects_external_backend() {
        let mut config = supported();
        config.net = Some(vec![
            serde_json::from_value(serde_json::json!({
                "id":"fork-net", "tap":"tap0", "mac":"02:00:00:00:00:01", "num_queues":4
            }))
            .unwrap(),
        ]);
        validate_config(&config).unwrap();
        config.net.as_mut().unwrap()[0].fds = Some(vec![7]);
        assert!(validate_config(&config).is_err());
        let mut net = virtio_devices::net::NetState {
            avail_features: 0,
            acked_features: 0,
            config: Default::default(),
            queue_size: vec![256, 256, 256, 256],
            curr_queue_pairs: Some(1),
            fork_identity_reset: false,
        };
        net.config.mac = [2, 0, 0, 0, 0, 1];
        let mut parent = Snapshot::default();
        parent.add_snapshot("fork-net".into(), Snapshot::new_from_state(&net).unwrap());
        let mut child = parent.clone();
        assert!(rewrite_net_mac(&mut child, "fork-net", &[2, 0, 0, 0, 0, 2]).unwrap());
        let original: virtio_devices::net::NetState =
            parent.snapshots["fork-net"].to_state().unwrap();
        let derived: virtio_devices::net::NetState =
            child.snapshots["fork-net"].to_state().unwrap();
        assert_eq!(original.config.mac, [2, 0, 0, 0, 0, 1]);
        assert_eq!(derived.config.mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(derived.queue_size, original.queue_size);
        assert!(!original.fork_identity_reset);
        assert!(derived.fork_identity_reset);
    }

    #[test]
    fn socket_validation_rejects_aliases_and_existing_entries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("child.api");
        assert_eq!(new_socket_path(&path).unwrap(), path);
        fs::write(&path, "existing").unwrap();
        new_socket_path(&path).unwrap_err();
        assert_eq!(fs::read_to_string(&path).unwrap(), "existing");
        new_socket_path(Path::new("relative.api")).unwrap_err();
        new_socket_path(&temp.path().join("a".repeat(108))).unwrap_err();
        fs::write(temp.path().join("locked.lock"), "keep").unwrap();
        new_socket_path(&temp.path().join("locked")).unwrap_err();
        assert_eq!(
            fs::read_to_string(temp.path().join("locked.lock")).unwrap(),
            "keep"
        );
        let alias = temp.path().join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert_eq!(
            new_socket_path(&alias.join("new")).unwrap(),
            temp.path().join("new")
        );
        symlink("missing-target", temp.path().join("dangling")).unwrap();
        new_socket_path(&temp.path().join("dangling")).unwrap_err();
    }
    #[test]
    fn readiness_reports_errors_and_detects_early_exit() {
        for result in [Ok(()), Err("Device restore failed".to_owned())] {
            let (parent, child) = UnixStream::pair().unwrap();
            ForkBranch {
                child: true,
                stream: child,
            }
            .report(&result)
            .unwrap();
            assert_eq!(
                ForkBranch {
                    child: false,
                    stream: parent
                }
                .wait(),
                result
            );
        }
        let (parent, child) = UnixStream::pair().unwrap();
        drop(child);
        let error = ForkBranch {
            child: false,
            stream: parent,
        }
        .wait()
        .unwrap_err();
        assert!(error.contains("exited before readiness"));
        let (parent, _child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        let error = ForkBranch {
            child: false,
            stream: parent,
        }
        .wait()
        .unwrap_err();
        assert!(error.contains("readiness channel"));
    }

    #[test]
    fn status_detects_pid_reuse_without_modifying_failed_operations() {
        let operation = ForkOperation {
            disk_retirement: None,
            operation_id: "test".into(),
            state: ForkPhase::Ready,
            parent_pid: process::id(),
            child_pid: Some(process::id()),
            child_api_socket: PathBuf::from("/tmp/child.api"),
            error: None,
            capture_ms: 0.0,
            parent_ready_ms: Some(0.0),
            ready_ms: Some(0.0),
            child_start_time: process_start_time(process::id()),
        };
        let operations = Arc::new(Mutex::new(vec![operation]));
        assert_eq!(operations_snapshot(&operations)[0].state, ForkPhase::Ready);
        operations.lock().unwrap()[0].child_start_time = Some("old-process".into());
        assert_eq!(
            operations_snapshot(&operations)[0].state,
            ForkPhase::ChildExited
        );
        operations.lock().unwrap()[0].state = ForkPhase::Failed;
        assert_eq!(operations_snapshot(&operations)[0].state, ForkPhase::Failed);
    }
    #[test]
    fn retained_mmu_worker_requires_kernel_flag_and_identity() {
        fn stat(name: &str, flags: u64, start: u64) -> String {
            let mut fields = vec!["0".to_string(); 20];
            fields[0] = "S".into();
            fields[6] = flags.to_string();
            fields[19] = start.to_string();
            format!("42 ({name}) {}", fields.join(" "))
        }
        assert!(parse_mmu_worker(42, &stat("kvm-nx-lpage-re", 0x400140, 123)).is_none());
        assert!(parse_mmu_worker(42, &stat("unknown", 0x404040, 123)).is_none());
        assert!(parse_mmu_worker(42, "malformed").is_none());
        let worker = parse_mmu_worker(42, &stat("kvm-nx-lpage-re", 0x404040, 123)).unwrap();
        assert_eq!(
            worker,
            KernelMmuWorker {
                tid: 42,
                start_time: 123
            }
        );
        assert_ne!(
            Some(worker.clone()),
            parse_mmu_worker(43, &stat("kvm-nx-lpage-re", 0x404040, 123))
        );
        assert_ne!(
            Some(worker),
            parse_mmu_worker(42, &stat("kvm-nx-lpage-re", 0x404040, 124))
        );
    }
}
