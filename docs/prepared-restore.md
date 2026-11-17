# Preparing an image-independent restore slot

The research branch exposes `PUT /api/v1/vmm.prepare` with a normal `VmConfig`
JSON body. It requires an empty VMM and ordinary x86-64 KVM. It validates the
profile, creates a KVM VM and the boot vCPUs, and retains them without RAM,
disks, network devices or guest execution. Paths in the supplied configuration
are not opened to attach application devices. No application image is selected.

A subsequent `vm.restore` using `CopyOnWrite` consumes this prepared VM once.
The CPU configuration and hypervisor VM profile must match exactly. MSR
configuration for prepared vCPUs is generated from that CPU profile, as in the
ordinary CPU manager. The actual CPU/device state and RAM come from the selected
template. Other restore modes or incompatible profiles are rejected. A restore
failure follows the existing delete/cleanup path, releasing prepared resources.
`vm.delete` also releases an unconsumed slot; a second preparation is then allowed.
Normal boots and restores without preparation retain their prior behavior.

The Kuasar template resource pool uses this after retiring its temporary generic
guest. Each slot owns its KVM resources; they are neither shared across processes
nor pooled per image. Retained vCPUs have never run. The existing live-parent fork
path remains separate and retains its existing barriers and CoW behavior.

This moves KVM object creation into measured pool preparation/refill work, not
out of accounting. Memory mapping, device construction, state restore, guest
identity reset and initial command execution remain in request latency. The
interface does not promise a particular latency and does not change host CPU
frequency policy, process priority or CPU affinity.
