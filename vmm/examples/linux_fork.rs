// SPDX-License-Identifier: Apache-2.0
//! Minimal single-controller Linux VM fork experiment. See scripts/research/run-linux-fork.sh.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod experiment {
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use std::{env, io, process, thread};

    use anyhow::{Context, Result, ensure};
    use seccompiler::SeccompAction;
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{
        Bytes, GuestAddress, GuestAddressSpace, GuestMemoryBackend, GuestMemoryRegion,
    };
    use vm_migration::{Pausable, Snapshot, Snapshottable};
    use vmm::console_devices::{ConsoleInfo, ConsoleTransport};
    use vmm::vm::Vm;
    use vmm::vm_config::VmConfig;
    use vmm_sys_util::eventfd::EventFd;

    fn event() -> Result<EventFd> {
        Ok(EventFd::new(libc::EFD_NONBLOCK)?)
    }

    fn create(
        config: VmConfig,
        snapshot: Option<&Snapshot>,
        memory: Option<&vm_memory::GuestMemoryMmap<AtomicBitmap>>,
        console: &Path,
    ) -> Result<Vm> {
        let console = ConsoleInfo {
            serial: ConsoleTransport::File(Arc::new(File::create(console)?)),
            console: ConsoleTransport::Off,
            debug: ConsoleTransport::Off,
        };
        Vm::new_with_inherited_memory(
            Arc::new(Mutex::new(config)),
            event()?,
            event()?,
            event()?,
            #[cfg(feature = "guest_debug")]
            event()?,
            &SeccompAction::Allow,
            hypervisor::new()?,
            event()?,
            Some(console),
            None,
            Arc::new(Mutex::new(None)),
            snapshot,
            None,
            Some(false),
            None,
            memory,
            None,
        )
        .map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    fn wait_line(vm: &Vm, path: &Path, prefix: &str) -> Result<String> {
        let start = Instant::now();
        loop {
            vm.activate_virtio_devices()
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let text = fs::read_to_string(path).unwrap_or_default();
            if let Some(line) = text.lines().find(|line| line.starts_with(prefix)) {
                return Ok(line.to_owned());
            }
            ensure!(
                start.elapsed() < Duration::from_secs(60),
                "Timed out waiting for {prefix} in {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn thread_count() -> Result<usize> {
        Ok(fs::read_dir("/proc/self/task")?.count())
    }

    fn ram_pss(memory: &vm_memory::GuestMemoryMmap<AtomicBitmap>) -> Result<u64> {
        let smaps = fs::read_to_string("/proc/self/smaps")?;
        let mut in_ram = false;
        let mut total = 0;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                in_ram = memory.iter().any(|region| {
                    let base = region.as_ptr() as usize;
                    start >= base && end <= base + region.len() as usize
                });
            }
            if in_ram && let Some(value) = line.strip_prefix("Pss:") {
                total += value.split_whitespace().next().unwrap().parse::<u64>()?;
            }
        }
        Ok(total)
    }

    fn run() -> Result<()> {
        let args: Vec<_> = env::args().collect();
        ensure!(
            args.len() == 4,
            "Usage: linux_fork KERNEL INITRAMFS OUTPUT_DIR"
        );
        let output = Path::new(&args[3]);
        fs::create_dir_all(output)?;
        ensure!(
            thread_count()? == 1,
            "Controller must start single-threaded"
        );
        let disk_path = output.join("read-only-disk.raw");
        let mut disk = File::create(&disk_path)?;
        disk.set_len(1024 * 1024)?;
        disk.write_all(b"fork-device-state")?;
        drop(disk);
        let config: VmConfig = serde_json::from_value(serde_json::json!({
            "cpus": {"boot_vcpus": 2, "max_vcpus": 2},
            "memory": {"size": 268435456, "shared": false, "thp": false},
            "payload": {
                "kernel": args[1], "initramfs": args[2],
                "cmdline": "console=ttyS0 earlyprintk=serial panic=-1 rdinit=/init"
            },
            "disks": [{"path": disk_path, "readonly": true, "image_type": "Raw"}],
            "serial": {"mode": "File", "file": output.join("seed.log")},
            "console": {"mode": "Off"}
        }))?;
        let seed_log = output.join("seed.log");
        let mut vm = create(config.clone(), None, None, &seed_log)?;
        vm.boot().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let ready = wait_line(&vm, &seed_log, "FORK_READY ")?;
        let fields: Vec<_> = ready.split_whitespace().collect();
        let command_gpa: u64 = fields[1].parse()?;
        let data_gpa: u64 = fields[2].parse()?;
        println!("Linux seed ready, host threads={}", thread_count()?);
        vm.pause()?;
        let snapshot = vm.snapshot()?;
        let config = vm.get_config().lock().unwrap().clone();
        let memory = vm.guest_memory().memory();
        ensure!(
            memory.read_obj::<u64>(GuestAddress(data_gpa))? == 10,
            "Seed data mismatch"
        );
        let before = ram_pss(&memory)?;
        ensure!(
            before >= 32 * 1024,
            "RAM accounting missed initialized pages"
        );
        // Drop joins vCPU/device workers and releases KVM, device and event descriptors.
        // Keep only immutable snapshot data and the reference-counted RAM mappings.
        drop(vm);
        ensure!(thread_count()? == 1, "VM teardown left host threads alive");
        for entry in fs::read_dir("/proc/self/fd")? {
            let path = entry?.path();
            if let Ok(target) = fs::read_link(path) {
                ensure!(
                    !target.to_string_lossy().contains("kvm"),
                    "VM teardown retained a KVM descriptor: {}",
                    target.display()
                );
            }
        }
        println!("Fork boundary threads=1, RAM PSS before={before} KiB");
        let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
        parent_socket.set_read_timeout(Some(Duration::from_secs(90)))?;
        child_socket.set_read_timeout(Some(Duration::from_secs(90)))?;
        // SAFETY: all VMM workers were joined and only this controller thread remains.
        // RAM is private, no passthrough or external writers exist in this fixed config.
        let child = unsafe { libc::fork() };
        ensure!(child >= 0, "fork failed: {}", io::Error::last_os_error());
        let is_child = child == 0;
        let own_pss = ram_pss(&memory)?;
        let role = if is_child { "child" } else { "parent" };
        let mut channel = if is_child {
            drop(parent_socket);
            child_socket.write_all(&own_pss.to_le_bytes())?;
            child_socket
        } else {
            drop(child_socket);
            let mut bytes = [0; 8];
            parent_socket.read_exact(&mut bytes)?;
            let combined = own_pss + u64::from_le_bytes(bytes);
            println!("Fork RAM combined PSS={combined} KiB, baseline={before} KiB");
            ensure!(combined <= before + 16, "RAM copied at fork");
            parent_socket
        };
        if is_child {
            // Parent finishes its guest write before the child VM is even rebuilt.
            let mut token = [0];
            channel.read_exact(&mut token)?;
        }
        let log = output.join(format!("{role}.log"));
        let mut vm = create(config, Some(&snapshot), Some(&memory), &log)?;
        vm.restore().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        vm.resume()?;
        let value = if is_child { 30u64 } else { 20u64 };
        // The guest reads and verifies its data before writing its assigned value.
        memory.write_obj(value, GuestAddress(command_gpa))?;
        let result = wait_line(&vm, &log, "FORK_RESULT ")?;
        ensure!(
            result == format!("FORK_RESULT initial=10 value={value}"),
            "{role}: {result}"
        );
        println!(
            "{role} pid={} threads={} {result}",
            process::id(),
            thread_count()?
        );
        channel.write_all(&[1])?;
        let mut byte = [0];
        channel.read_exact(&mut byte)?;
        if !is_child {
            channel.write_all(&[1])?;
        }
        ensure!(
            memory.read_obj::<u64>(GuestAddress(data_gpa))? == value,
            "Cross-VM write observed"
        );
        // Both guests remain alive while we verify isolation.
        thread::sleep(Duration::from_millis(200));
        ensure!(
            memory.read_obj::<u64>(GuestAddress(data_gpa))? == value,
            "Late cross-VM write"
        );
        vm.pause()?;
        let after = ram_pss(&memory)?;
        ensure!(after < before * 3 / 4, "Most RAM stopped being shared");
        println!("{role} RAM PSS after running={after} KiB");
        drop(vm);
        ensure!(thread_count()? == 1, "{role} shutdown left threads alive");
        println!("{role} shutdown threads=1");
        if !is_child {
            let mut status = 0;
            // SAFETY: child is the PID returned by fork; status is a valid output pointer.
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            ensure!(waited == child, "waitpid failed");
            ensure!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "Child failed"
            );
            println!("PASS Linux fork: independent KVM VMs, inherited RAM, CoW, joined workers");
        }
        Ok(())
    }

    pub(super) fn main() -> Result<()> {
        run().context("Linux VM fork experiment")
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    experiment::main()
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("This experiment requires x86_64 Linux with KVM");
    std::process::exit(1);
}
