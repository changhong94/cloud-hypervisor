# Same-host VM fork experiment

The `linux_fork` example boots a real Linux guest through Cloud Hypervisor's
`Vm` implementation, captures vCPU and device state in memory, retains the
existing private guest RAM mappings, and destroys the original VM runtime.
It then forks the single remaining controller thread. Both processes create
fresh KVM VMs and restore through `Vm::new_with_inherited_memory`.

The guest has two vCPUs, 256 MiB of private RAM, a serial device, and a read-only
virtio-blk device. Its PID 1 fills 32 MiB with the value 10 and performs a direct
block read before declaring readiness. After restore, each guest verifies the
entire initialized buffer, performs another O_DIRECT read using its inherited
guest file descriptor, and writes its own value to the test page.

## Run

An x86_64 Linux host with usable /dev/kvm, a Rust toolchain, a static C compiler,
cpio, and a Linux kernel with built-in initramfs, serial, and virtio-blk support
are required.

```sh
scripts/research/run-linux-fork.sh /path/to/vmlinuz /path/to/results
```

The script builds an initramfs and the example, runs it under a 150-second
timeout, and retains the seed, parent and child serial logs and results.log.
The initramfs and read-only test disk are input fixtures. RAM and VM snapshot
state remain in memory throughout the experiment.

## Thread lifecycle

The controller runs directly on the main thread and services pending virtio
activation while waiting for guest output. At the fork boundary it performs
the following steps.

1. Pause the VM and capture its Snapshot and current device configuration.
2. Retain only the guest RAM mapping handle, snapshot data, and configuration.
3. Drop the VM. Existing shutdown/destructor paths join vCPU and device workers
   and release the original KVM and device objects.
4. Require exactly one entry in /proc/self/task and no remaining KVM descriptor.
5. Call host fork, then construct new KVM VMs, memslots, devices and workers
   independently in both processes.

This example is a minimal entry point using the real VMM library. The normal
HTTP/API process now uses the supervisor described below. The test uses private RAM,
no passthrough, no external memory writer, a read-only block device and no
network. Writable disk branching and external connections need additional
resource handling.

The parent's original KVM VM is destroyed and rebuilt from its captured state
alongside the child. Both guests continue the saved Linux execution. This
choice makes the single-threaded host fork boundary explicit.

## Checks

Before fork, the guest has already written its test pages through KVM.
After fork, combined RAM PSS is required to match the pre-fork value within
16 KiB, before either runtime is rebuilt. The parent runs and writes 20 before
the child starts restoring. The child must still observe 10 and then write 30.
Both processes verify their own guest value after the other's write and verify
that shutdown returns the process to one thread.

RAM regions are adopted by retaining their original mmap objects. The unit
test checks pointer identity, preserved contents, and rejection of mismatched
layouts. Snapshot transport and its RAM serialization are bypassed.

The earlier `kvm-fork-cow.c` test isolates the same mechanism with a tiny
real-mode guest and checks that writing one page adds exactly one physical
page. Linux modifies additional kernel and device pages as it resumes, so the
Linux test reports total RAM PSS instead of requiring exactly one extra page.

## Normal HTTP/API path

The `sandbox_fork` branch also implements `PUT /api/v1/vm.fork` in the normal
`cloud-hypervisor` binary. Start it with `--api-socket /absolute/parent.api
--enable-fork`, create/boot a supported VM through the regular API, then send:

```json
{
  "child_api_socket": "/absolute/child.api",
  "child_serial_socket": "/absolute/child.serial"
}
```

For a source with virtio-vsock, also provide a distinct, non-reserved child CID
and an unused backend socket path:

```json
{
  "child_api_socket": "/absolute/child.api",
  "child_serial_socket": "/absolute/child.serial",
  "child_vsock": {"cid": 4, "socket": "/absolute/child.vsock"}
}
```

The PCI identity/topology is preserved. Both branches rebuild their own Unix
backend and deliver virtio-vsock TRANSPORT_RESET after resume. Linux re-reads the
CID and closes old connected sockets; wildcard guest listeners remain available.
No established host connection is copied into either restored backend. Guest
packets whose source CID differs from the backend's configured CID are dropped.
Clients must reconnect RPC/Task streams after fork. See the sibling Kuasar
`scripts/research/run-agent-fork.sh` for real guest-agent/container validation.

HTTP 200 returns an operation record with an `operation_id` and state `Accepted`;
it acknowledges acceptance, **not completion**. The source can be Running
or Paused. The request captures state and drains VM workers; the VMM then closes
and joins its signal handler. The main supervisor joins the VMM and HTTP server
(the latter flushes the response), releases all old channels and eventfds, and
requires one task and no KVM descriptors before calling host fork. It recreates
all eventfds, channels, KVM VMs, vCPU/device workers, signal handlers, HTTP servers
and serial listeners independently. Both branches adopt the inherited mmap
objects and restore vCPU/device state in memory. No memory.img is produced.

The parent PID and API path stay the same. Existing API and serial connections
close during the transition. Reconnect to the **parent** API and poll
`GET /api/v1/vm.fork-status`, selecting the returned `operation_id`. The response
is an array of the most recent 64 operations. Records contain the parent/child
PIDs, child API path, state, error and timings. `Accepted`/`Restoring` are pending;
`Ready` means both HTTP listeners and both restored runtimes have started. The
VMs remain paused: connect their serial sockets, then `PUT vm.resume` separately.
`Failed` reports host fork, child startup, readiness EOF or timeout errors. If
the source was running, failure recovery resumes it; if paused, it stays paused.
A child that exits after readiness is reported as `ChildExited` when queried.
PID start times distinguish reused PIDs. There is no persistent operation store
or child termination API; history is bounded, local to the VMM process, and
copied into descendants. The source endpoint owns the authoritative record.

Poll with a timeout and tolerate connection failures or HTTP 503 responses
while the source API restarts. A lost acknowledgement can be recovered
by listing the source's operations. Child startup errors travel back over a
private socket pair, not an API request served by the child. The supervisor
waits up to 30 seconds on that readiness channel while the restored parent API
is available. Requests to fork again during an active operation return 409
while the new API is serving; requests left on the old connection receive 503 or disconnect.
The source runtime is reconstructed before child failure recovery, so even a
child that cannot bind its API socket does not discard the parent's RAM. A
parent restoration failure is fatal and remains visible in the process log;
this mechanism cannot recover a broken source disk or host-wide KVM failure.

Timings start immediately before pausing the source: `capture_ms` measures
pause/state capture/VM teardown, `parent_ready_ms` measures source runtime and
HTTP listener reconstruction, and `ready_ms` measures the completed operation
(including child readiness or failure recovery). These are debug-build research
measurements; they exclude the caller-controlled delay before explicit resume.

The supported envelope is x86_64 KVM, private anonymous RAM, socket serial,
console/debug console off, local disks and optional userspace vsock/NIC. The
writable-disk extension below supports one buffered managed CoW disk. Unsupported
configurations are rejected before pausing the source. Passthrough,
vhost-user, shared/hugepage/mergeable memory, memory hotplug/zones, other external
devices, landlock, active debugger, D-Bus and event-monitor threads are excluded.
Fork is opt-in with `--enable-fork`; the default `--seccomp true` remains enabled.
The supervisor installs a union of existing worker syscall/argument policies,
allowing it to rebuild workers after host fork. Each worker still installs its
own narrower filter. The supervisor filter is installed only once, so repeated
forks do not accumulate seccomp layers. Without `--enable-fork`, the normal main
thread retains its original narrow policy and vm.fork is rejected. The opt-in
supervisor has broader permissions than the ordinary main thread; this is an
explicit architectural tradeoff, not an attempt to remove installed filters.

This remains a research interface, not a production sandbox API or persistent
snapshot format. Guest identities/entropy and writable external resources need
separate branching policies. The sibling Kuasar research scripts exercise the
agent, containerd, Kubernetes, E2B SDK, network and writable-disk integrations.

Run the full HTTP test with Python 3 in addition to the prerequisites above:

```sh
scripts/research/run-http-fork.sh /path/to/vmlinuz /path/to/results
```

It creates/boots Linux through HTTP, checks invalid fork requests preserve the
running source, calls vm.fork, reconnects both API and serial endpoints, and
resumes the parent first. Only serial input supplies the parent value 20 and
child value 30; no test-only host memory API is used. Both guests validate all
32 MiB inherited data and read the restored virtio-blk device. RAM-only PSS at
the single-threaded fork boundary must remain unchanged (16 KiB accounting
tolerance). After execution, both RAM PSS values must stay below 75% of the
pre-fork baseline. Independent pause/resume and shutdown test eventfd isolation;
the child continues after parent exit and then shuts down via its rebuilt signal
handler. A second fork from the running child verifies that the lifecycle can
repeat and that a grandchild keeps running after its parent exits. A process without
`--enable-fork` rejects fork without breaking its API. The script retains
results.json, serial logs, VMM log and smaps.

The HTTP test also injects two real child failures: an unbindable child API
socket and an uncreatable serial socket during VM restoration. It checks both
Running and Paused source recovery. Ten further rounds submit two concurrent fork requests before reading either
response, require exactly one acceptance, alternate graceful child shutdown and SIGKILL,
and verify `ChildExited`, continued guest execution, unchanged task/FD counts
and unchanged per-thread seccomp filter counts. Every userspace thread must
remain in seccomp filter mode. Results include operation timings and resource
counts. No writable-disk or Kuasar behavior is covered by this test.

## Writable disk fork

`vm.fork` accepts `parent_disk_dir` and `child_disk_dir` when exactly one disk
is writable. Both must be absolute, separate paths on the same host filesystem
as the source image. The child directory must not exist; the parent directory
is created on the first fork and reused for descendants. Directory parents must
already exist. The initial disk must be an exclusively owned regular raw file
with explicit `image_type=raw`, buffered I/O (`direct=false`), no vhost-user or
rate limiter. Additional read-only disks retain their existing restrictions.

After stopping vCPUs and draining/flushing block workers, the supervisor closes
all disk/KVM descriptors. It links immutable history into each VM's own directory,
creates two empty qcow2 leaves with relative backing names, fsyncs the new leaves
and directories, seals the old active inode read-only, and updates both VM configs.
Only then does it fork RAM and rebuild each backend with a distinct writable FD.
Dirty guest page cache, filesystem/journal state, and open guest FDs are inherited
with RAM. Subsequent writeback goes to that branch's own disk leaf. There is no
`memory.img`, guest-RAM memcpy, disk flattening or full-disk copy.

Each directory contains hard links to every ancestor, so unlinking a destroyed
VM's directory cannot invalidate another VM's backing chain. Kuasar removes each
owned directory on normal sandbox deletion. Direct HTTP users own directory
cleanup after their VM exits. The initial raw input is consumed/sealed and remains
caller-owned; do not boot it writable again, chmod it, modify any sealed inode or
allow another host writer. Mode bits are a lifecycle guard, not protection against
a privileged host administrator. Descendant active images must retain the managed
relative chain layout. Generations are no longer limited to nine: when the source
chain reaches four files, a background worker prepares a compacted immutable
prefix over the same raw base. Before the next fork pauses the guest, the worker
publishes base + merged prefix + active leaf; branching adds one new leaf.
Cold-booting an externally supplied long managed chain does not start a worker:
such a fork is rejected before pausing; this profile starts from a fresh raw seed.
The qcow2 reader's defensive recursion limit is unchanged.

Preparation uses create-new files and tracks only newly created links. Failure
before sealing rolls these back and restores the original VM. After committing
the pivot, failure to fork/restore a child leaves the parent on its equivalent new
leaf; the failed child's directory belongs to the caller for cleanup. This is a
live-process feature, not a host-crash recovery or restart protocol. Source sealing and namespace publication belong to the
fork supervisor and its disk merge worker;
ordinary VMM/API/device workers retain
their previous seccomp filters. Explicit fork-enabled VMMs additionally allow
new-directory/history-link preparation as described below.

Validation lives in Kuasar's `scripts/research`: real Linux ext4 container rootfs,
Kubernetes/CRI and unmodified E2B SDK tests verify both deletion orders, cache-cold
reads/exec, independent file changes, shared history inodes and unchanged sealed
layer hashes. The `block` unit suite additionally checks partial-cluster CoW and
reopening both branches; VMM tests cover rollback conflicts and repeated compaction.

### Bounded multi-generation disk chains

The supervisor creates a joinable disk merge worker after each host fork when the
restored chain has four files. The worker waits until `vm.resume` before doing disk
I/O, so reconstruction does not compete with compaction. It reads **only sealed
ancestors**, excluding the live writable leaf, and creates one private `.merge-*`
candidate with the original raw backing. Allocated clusters are applied oldest to
newest; holes are skipped and explicit zero overrides retained. Cluster-sized data
buffers and normal qcow2 metadata caches are used. No guest RAM is copied or serialized.

The next `vm.fork` waits for that worker **before pausing the guest**. The worker
validates the captured chain paths and device/inode identities, seals and syncs the
candidate, and atomically renames it over the first backing link in this VM's directory.
The active leaf/header is not rewritten. Existing block readers hold open FDs on the
old prefix, whose bytes are equivalent to the new prefix; online writes and partial
cluster copy-up remain valid. Restore opens the shorter chain. Other VMs' hard links
still refer to the old inode. Directory sync and local unreachable-link collection
follow the committed rename. A post-publication GC error is deferred, not rolled back.

The worker is joined before the first vCPU pause and before the supervisor's
single-thread check. VM deletion and control-loop exit cancel and join it; cancellation
is checked between clusters. Unpublished candidates are removed on failure/cancel.
A merge failure rejects fork while the guest remains running. There is no foreground
merge fallback inside the pause. Filesystem operations can still block on storage;
this removes merge data copying from the pause, not all fork request latency.

The live chain remains at most four files, plus at most one unpublished candidate.
An idle VM may retain its candidate until its next fork or deletion. Garbage collection
unlinks only unreachable managed layer names in this VM's owned directory. Open block
FDs pin old inodes until teardown; other VM links pin them for those VMs. Normal Kuasar
deletion removes the entire owned directory. This bounds per-VM chain/candidate count,
not total space across arbitrary live ancestors. Host-crash recovery and persistent
VM restart remain outside this live-fork profile. Filesystem permissions are a lifecycle
guard, not isolation against a privileged host writer.

`VM_FORK pause_ms` measures from immediately before `vm.pause` through the successful
explicit `vm.resume`, separately for parent and child. `disk_merge_wait_before_pause_ms`
records join/publication waiting with the guest still running. `disk_compact ...
background=true` measures the background build; `disk_merge_publish` records publication.

`CH_FORK_VERIFY_PAGES=1` enables research-only `/proc/*/pagemap` verification at the
pre-restore fork barrier (requires CAP_SYS_ADMIN). It compares every guest page's
presence/swap state and PFN and logs the count of identical resident pages. With
multiple older VMs sharing pages, parent+child PSS changes because the proportional
sharing denominator changes; equality to the source PSS is valid only for the earlier
two-VM fixture. Physical page identity is the no-RAM-copy assertion in multi-generation
tests. No physical page numbers are emitted to logs.

### Fork pause phase timing and reconstruction

Set `CH_FORK_TIMING=1` to emit `VM_FORK stage` records with operation ID, host PID,
phase and milliseconds from the common pre-pause monotonic origin. Parent/child
milestones share that origin across fork. The VMM trace is thread-local and does
not retain locks or workers across fork; each record is written in one pipe write.
The trace covers CPU/device pause, snapshot capture, vCPU and device worker joins,
object destruction, API shutdown, disk branching, host fork, PSS/PFN verification,
KVM and memory setup, vCPU/device restore, API binding and explicit resume. API
binding and parent/child rebuild happen in parallel: do not sum their durations.

Empty parent/child qcow2 leaves are initialized and synced concurrently. The scoped
helper is joined even if initialization fails, and the single-thread check is
repeated after disk branching before host fork. All existing file/directory syncs,
sealing, rollback, KVM FD checks and the bounded thread-exit barrier remain in place.

Before spawning any restored runtime or disk-merge workers, the supervisor grows
the descriptor table again. The child can receive a small table after fork even
though the source expanded its table at initial boot. `F_DUPFD_CLOEXEC` reserves a
free high slot (up to 4096 entries, bounded by RLIMIT_NOFILE), then closes it; no
existing descriptor is overwritten and the limit is not raised. This avoids
multithreaded FD-table expansion in device restoration. Trace logs also record
FDSize before/after, and expansion failure keeps the existing best-effort fallback.

PSS page-table walks in parent and child now overlap while both guests remain
stopped. Optional full PFN verification still checks every guest page's present/
swap state and physical identity, rejecting masked PFNs. Equal pagemap chunks use
a bulk equality path; differing software flags use the same masked comparison.
No RAM verification, durability sync, state restore or thread join is skipped.

Kuasar polls the read-only fork operation status every 1 ms during the first
250 ms, then returns to a 20 ms interval for slow/error paths. It still never
replays a fork mutation after a lost response, and retains the 45-second timeout.
Both guest resumes remain explicit and ordered after sandbox adoption/persistence.

Use Kuasar's `scripts/research/analyze-fork-stages.py BEFORE/host.log AFTER/host.log`
for phase distributions, branch-specific restore timings and FDSize samples.
`compare-fork-pauses.py` reports the maximum parent/child pause per successful fork.
Both baseline and optimized validation should retain `CH_FORK_VERIFY_PAGES=1` and
the same direct-I/O stress so diagnostic work is included in both measurements.


### Fork teardown overlap and tail-latency measurements

`CH_FORK_TIMING=1` additionally separates vCPU/device worker joins, VMGenID slot
removal, device/CPU/memory-manager object destruction, and the last VM reference.
The `kvm_vm_dropped` milestone marks release of the VM object's reference; for
the fork retirement path, **`retired_kvm_closed`** marks release of the retained
last reference. Do not mistake moving that release to a helper for eliminating
its cost. `retirement_joined` and `fork_boundary_ready` delimit the final wait.

After successful capture, fork teardown retains only the KVM VM reference and
VMGenID mapping. The mapping remains alive through KVM VM destruction, so whole
VM teardown need not separately delete its slot. Ordinary teardown and hot
unplug retain their original unregister behavior. All application workers and
writable disk owners are destroyed first. The supervisor closes the retained VM
in a scoped helper while committing prepared disk branches and reading PSS. Both success
and error paths join the helper. Only then does it require one actual kernel
thread and no KVM descriptors before `fork()`. KVM's NX huge-page recovery task
may exist until the last VM fd closes; the barrier must follow retirement.

Use Kuasar's `scripts/research/analyze-fork-stages.py` for stage distributions and
`compare-fork-pauses.py` for each fork's maximum parent/child pause through API
resume. Both report median, nearest-rank P95/P99, maximum and sample count.
Parallel stages must not be summed. Keep PFN verification, PSS sampling, tracing,
guest configuration and concurrent I/O enabled identically for both versions.


### Prepare empty disk branches before pausing

After joining/publishing a pending prefix merge, fork prepares only fresh empty
qcow2 leaves and history hard links while the guest remains running. Source data
and permissions are unchanged. New files and directories are synced here; the
existing vCPU/device pause still drains and syncs active I/O. Only after disk
owners close does the supervisor verify source path/inode identity, seal it,
and publish the new configuration. Uncommitted preparation owns its rollback
paths and removes only those paths on capture/pause/commit failure.

`disk_prepare_before_pause_ms` reports this work separately, with `guest_running`.
It is still part of end-to-end fork request latency. Already-paused callers keep
preparation in their pause accounting. `CH_FORK_TIMING=1` also emits block pause
milestones for I/O drain, metadata sync and worker parking.

Only `--enable-fork` selects the `ForkVmm` filter, adding mkdir/link/rmdir (and
applicable *at variants) to the ordinary VMM policy for preparation and rollback.
Sealing/rename/setns remain supervisor-only; exec/ptrace are not added. Device
threads still apply their own narrower filters. The ordinary VMM policy is
unchanged. Preparation helper threads are scoped and joined before capture;
the final actual-single-thread/no-KVM-fd barrier remains mandatory.


Read-only qcow2 metadata owners no longer fsync during final destruction; writable
owners still flush data/metadata and clear the dirty bit. A reader must not clear
a live writer's dirty state. Stale local-link GC and its directory sync now run
before empty-leaf preparation, with operation-path collision checks first. Adding
a leaf on top of the retained history creates no new garbage, so no second GC
scan/directory sync is needed in the paused commit phase.
