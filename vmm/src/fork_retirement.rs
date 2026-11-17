// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Terminal QCOW close after the checkpoint is durable and writers are gone.
//! The parent owns the close. The child receives its result, never writes the
//! inherited backing header, and cannot start another fork before completion.
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use block::disk_file::ForkRetirement;

use crate::fork::ForkOperations;

type Outcome = Result<(), String>;
pub(crate) struct DiskRetirementJob {
    worker: Mutex<Option<JoinHandle<()>>>,
    start: Mutex<Option<mpsc::Sender<()>>>,
    outcome: Arc<Mutex<Option<Outcome>>>,
}

impl DiskRetirementJob {
    pub(crate) fn spawn(
        disks: Vec<Box<dyn ForkRetirement>>,
        peer: Option<UnixStream>,
        parent: bool,
        operation: String,
        operations: ForkOperations,
    ) -> io::Result<Arc<Self>> {
        let (start, ready) = mpsc::channel();
        let outcome = Arc::new(Mutex::new(None));
        let result_slot = Arc::clone(&outcome);
        let worker = thread::Builder::new().name("disk-retire".into()).spawn(move || {
            // Do not compete with new disk opens while the VM is paused.
            // Shutdown/wait also releases this gate, so failed restore cannot
            // strand an unstarted close or discard a durability barrier.
            let _ = ready.recv();
            let started = Instant::now();
            let result = if parent {
                let result = finish_all(disks);
                // Close disk FDs before publishing completion. A dead child
                // cannot invalidate the parent's completed durability barriers.
                if let Some(mut peer) = peer {
                    let _ = serde_json::to_writer(&mut peer, &result);
                    let _ = peer.flush();
                }
                result
            } else {
                // Inherited guards know their owner PID; dropping only closes
                // this process's FDs, never flushes/clears the parent's header.
                drop(disks);
                (|| -> Outcome {
                    let peer = peer.ok_or("Missing parent retirement channel")?;
                    peer.set_read_timeout(Some(Duration::from_secs(45))).map_err(|e| e.to_string())?;
                    let mut bytes = Vec::new();
                    peer.take(65536).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                    serde_json::from_slice(&bytes).map_err(|e| format!("Parent retirement result: {e}"))?
                })()
            };
            crate::fork::log_line(format_args!(
                "VM_FORK disk_retirement op={operation} pid={} parent={parent} elapsed_ms={:.3} success={}",
                std::process::id(), started.elapsed().as_secs_f64()*1000.0, result.is_ok()));
            if let Some(op) = operations.lock().unwrap().iter_mut().find(|op| op.operation_id == operation) {
                op.disk_retirement = Some(result.clone());
            }
            *result_slot.lock().unwrap() = Some(result);
        })?;
        Ok(Arc::new(Self {
            worker: Mutex::new(Some(worker)),
            start: Mutex::new(Some(start)),
            outcome,
        }))
    }

    pub(crate) fn start(&self) {
        if let Some(start) = self.start.lock().unwrap().take() {
            let _ = start.send(());
        }
    }

    pub(crate) fn wait(&self) -> io::Result<()> {
        self.start();
        if let Some(worker) = self.worker.lock().unwrap().take() {
            if worker.join().is_err() {
                *self.outcome.lock().unwrap() = Some(Err("Disk retirement worker panicked".into()));
            }
        }
        self.outcome
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err("Disk retirement did not complete".into()))
            .map_err(io::Error::other)
    }
}

fn finish_all(disks: Vec<Box<dyn ForkRetirement>>) -> Outcome {
    let mut result = Ok(());
    for disk in disks {
        if let Err(error) = disk.finish() {
            result = Err(error.to_string());
        }
        drop(disk);
    }
    result
}

impl Drop for DiskRetirementJob {
    fn drop(&mut self) {
        // Normal destruction and the next fork must not strand a worker or FD.
        if let Err(error) = self.wait() {
            log::error!("Disk retirement failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use block::error::{BlockError, BlockErrorKind};

    use super::*;

    struct GatedClose(Mutex<mpsc::Receiver<()>>, bool);
    impl ForkRetirement for GatedClose {
        fn finish(&self) -> block::error::BlockResult<()> {
            self.0.lock().unwrap().recv().unwrap();
            if self.1 {
                Err(BlockError::new(
                    BlockErrorKind::Io,
                    io::Error::other("injected close failure"),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn close_barrier_gates_both_branches_and_preserves_failure() {
        for fail in [false, true] {
            let (a, b) = UnixStream::pair().unwrap();
            let (release, gate) = mpsc::channel();
            let parent = DiskRetirementJob::spawn(
                vec![Box::new(GatedClose(Mutex::new(gate), fail))],
                Some(a),
                true,
                "test".into(),
                Arc::default(),
            )
            .unwrap();
            let child =
                DiskRetirementJob::spawn(vec![], Some(b), false, "test".into(), Arc::default())
                    .unwrap();
            assert!(parent.outcome.lock().unwrap().is_none());
            assert!(child.outcome.lock().unwrap().is_none());
            parent.start();
            child.start();
            release.send(()).unwrap();
            assert_eq!(parent.wait().is_err(), fail);
            assert_eq!(child.wait().is_err(), fail);
            // Joining a completed failed worker must never turn failure into OK.
            assert_eq!(parent.wait().is_err(), fail);
            assert_eq!(child.wait().is_err(), fail);
        }
    }

    #[test]
    fn destruction_finishes_close_even_without_resume() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Close(Arc<AtomicBool>);
        impl ForkRetirement for Close {
            fn finish(&self) -> block::error::BlockResult<()> {
                self.0.store(true, Ordering::Release);
                Ok(())
            }
        }
        let finished = Arc::new(AtomicBool::new(false));
        let job = DiskRetirementJob::spawn(
            vec![Box::new(Close(Arc::clone(&finished)))],
            None,
            true,
            "test".into(),
            Arc::default(),
        )
        .unwrap();
        assert!(!finished.load(Ordering::Acquire));
        drop(job);
        assert!(finished.load(Ordering::Acquire));
    }

    #[test]
    fn parent_loss_does_not_acknowledge_disk_durability() {
        let (a, b) = UnixStream::pair().unwrap();
        let child = DiskRetirementJob::spawn(vec![], Some(b), false, "test".into(), Arc::default())
            .unwrap();
        drop(a);
        assert!(child.wait().is_err());
    }
}
