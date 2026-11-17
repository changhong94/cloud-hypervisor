// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::{io, result};

use anyhow::anyhow;
pub use context::{
    CompletedMigrationContext, DowntimeContext, MemoryMigrationContext, MigrationContextError,
    OngoingMigrationContext,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::MemoryRangeTable;

mod bitpos_iterator;
mod context;
pub mod protocol;
pub mod tls;

#[derive(Error, Debug)]
pub enum UffdError {
    #[error("Snapshot ranges are not page-aligned")]
    UnalignedRanges,

    #[error("Failed to create userfaultfd")]
    Create(#[source] io::Error),

    #[error("Cannot translate GPA {gpa:#x} to host address")]
    GpaTranslation {
        gpa: u64,
        #[source]
        source: vm_memory::GuestMemoryError,
    },

    #[error("Failed to register region at {addr:#x}+{len:#x}")]
    Register {
        addr: u64,
        len: u64,
        #[source]
        source: io::Error,
    },

    #[error("Region at {addr:#x}+{len:#x} missing COPY/WAKE support")]
    MissingIoctlSupport { addr: u64, len: u64 },

    #[error("Failed to configure socket")]
    SetSocket(#[source] io::Error),

    #[error("Failed to spawn handler thread")]
    SpawnThread(#[source] io::Error),

    #[error("Handler terminated before startup completed")]
    HandlerStartup,

    #[error("Handler failed after startup")]
    HandlerFailed(#[source] io::Error),
}

#[derive(Error, Debug)]
pub enum MigratableError {
    #[error("Failed to pause migratable component")]
    Pause(#[source] anyhow::Error),

    #[error("Failed to resume migratable component")]
    Resume(#[source] anyhow::Error),

    #[error("Failed to snapshot migratable component")]
    Snapshot(#[source] anyhow::Error),

    #[error("Failed to restore migratable component")]
    Restore(#[source] anyhow::Error),

    #[error("Failed to send migratable component snapshot")]
    MigrateSend(#[source] anyhow::Error),

    #[error("Failed to receive migratable component snapshot")]
    MigrateReceive(#[source] anyhow::Error),

    #[error("On-demand restore failed")]
    OnDemandRestore(#[source] UffdError),

    #[error("Socket error")]
    MigrateSocket(#[source] io::Error),

    #[error("Failed to start migration for migratable component")]
    StartDirtyLog(#[source] anyhow::Error),

    #[error("Failed to stop migration for migratable component")]
    StopDirtyLog(#[source] anyhow::Error),

    #[error("Failed to retrieve dirty ranges for migratable component")]
    DirtyLog(#[source] anyhow::Error),

    #[error("Failed to cancel migration")]
    CancelMigration(#[source] anyhow::Error),

    #[error("Failed to start migration for migratable component")]
    StartMigration(#[source] anyhow::Error),

    #[error("Failed to abort migration for migratable component")]
    AbortMigration(#[source] anyhow::Error),

    #[error("Failed to complete migration for migratable component")]
    CompleteMigration(#[source] anyhow::Error),

    #[error("Migration was cancelled")]
    Cancelled,

    #[error("Failed to release a disk lock")]
    UnlockError(#[source] anyhow::Error),

    #[error("Lifecycle operation skipped for disconnected component {0}")]
    DeviceDisconnected(String),

    #[error("Error setting up a TLS-encrypted connection")]
    Tls(#[source] tls::TlsError),

    #[error("The request conflicts with current state")]
    Conflict(#[source] anyhow::Error),
}

/// A Pausable component can be paused and resumed.
pub trait Pausable {
    /// Pause the component.
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    /// Resume the component.
    fn resume(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }
}

/// A Snapshottable component snapshot section.
///
/// Migratable component can split their migration snapshot into
/// separate sections.
/// Splitting a component migration data into different sections
/// allows for easier and forward compatible extensions.
#[derive(Clone, Default, Deserialize)]
pub struct SnapshotData {
    state: String,
    #[serde(skip)]
    cached: Option<Arc<CachedSnapshotState>>,
}

// Immutable owned state can be inherited by an in-process restore without a
// JSON round trip. Persisting or transporting it still uses the original wire
// format; the cache is never part of that format.
struct CachedSnapshotState {
    value: Box<dyn Any + Send + Sync>,
    json: OnceLock<String>,
    encode: fn(&dyn Any) -> Result<String, serde_json::Error>,
}

impl Serialize for SnapshotData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let json = self.json().map_err(serde::ser::Error::custom)?;
        let mut data = serializer.serialize_struct("SnapshotData", 1)?;
        data.serialize_field("state", json)?;
        data.end()
    }
}

impl SnapshotData {
    fn json(&self) -> Result<&str, MigratableError> {
        let Some(cached) = &self.cached else {
            return Ok(&self.state);
        };
        if cached.json.get().is_none() {
            let json = (cached.encode)(cached.value.as_ref())
                .map_err(|e| MigratableError::Snapshot(anyhow!("Error serialising: {e}")))?;
            // Concurrent serializers may compute the same immutable value. Only
            // one publishes it; all readers use the published allocation.
            let _ = cached.json.set(json);
        }
        Ok(cached.json.get().unwrap())
    }

    /// Capture owned state without encoding it until transport is requested.
    pub fn new_from_owned_state<T: Serialize + Send + Sync + 'static>(state: T) -> Self {
        Self {
            state: String::new(),
            cached: Some(Arc::new(CachedSnapshotState {
                value: Box::new(state),
                json: OnceLock::new(),
                encode: |value| serde_json::to_string(value.downcast_ref::<T>().unwrap()),
            })),
        }
    }

    /// Restore from immutable native state, or decode an ordinary saved snapshot.
    pub fn to_owned_state<T>(&self) -> Result<T, MigratableError>
    where
        T: Clone + serde::de::DeserializeOwned + 'static,
    {
        if let Some(value) = self
            .cached
            .as_ref()
            .and_then(|c| c.value.downcast_ref::<T>())
        {
            return Ok(value.clone());
        }
        self.to_state()
    }

    /// Generate the state data from the snapshot data
    pub fn to_state<'a, T>(&'a self) -> Result<T, MigratableError>
    where
        T: Deserialize<'a>,
    {
        serde_json::from_str(self.json()?)
            .map_err(|e| MigratableError::Restore(anyhow!("Error deserialising: {e}")))
    }

    /// Create from state that can be serialized
    pub fn new_from_state<T>(state: &T) -> Result<Self, MigratableError>
    where
        T: Serialize,
    {
        let state = serde_json::to_string(state)
            .map_err(|e| MigratableError::Snapshot(anyhow!("Error serialising: {e}")))?;

        Ok(SnapshotData {
            state,
            cached: None,
        })
    }
}

/// Data structure to describe snapshot data
///
/// A Snapshottable component's snapshot is a tree of snapshots, where leaves
/// contain the snapshot data. Nodes of this tree track all their children
/// through the snapshots field, which is basically their sub-components.
/// Leaves will typically have an empty snapshots map, while nodes usually
/// carry an empty snapshot_data.
///
/// For example, a device manager snapshot is the composition of all its
/// devices snapshots. The device manager Snapshot would have no snapshot_data
/// but one Snapshot child per tracked device. Then each device's Snapshot
/// would carry an empty snapshots map but a map of SnapshotData, i.e.
/// the actual device snapshot data.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Snapshot {
    /// The Snapshottable component snapshots.
    pub snapshots: BTreeMap<String, Snapshot>,

    /// The Snapshottable component's snapshot data.
    /// A map of snapshot sections, indexed by the section ids.
    pub snapshot_data: Option<SnapshotData>,
}

impl Snapshot {
    pub fn from_data(data: SnapshotData) -> Self {
        Snapshot {
            snapshot_data: Some(data),
            ..Default::default()
        }
    }

    /// Create from state that can be serialized
    pub fn new_from_state<T>(state: &T) -> Result<Self, MigratableError>
    where
        T: Serialize,
    {
        Ok(Snapshot::from_data(SnapshotData::new_from_state(state)?))
    }

    /// Keep a pure, owned state value for same-process/fork restore. Serialization
    /// still emits the original wire format through SnapshotData.
    pub fn new_from_owned_state<T: Serialize + Send + Sync + 'static>(state: T) -> Self {
        Self::from_data(SnapshotData::new_from_owned_state(state))
    }

    pub fn to_owned_state<T: Clone + serde::de::DeserializeOwned + Send + Sync + 'static>(
        &self,
    ) -> Result<T, MigratableError> {
        self.snapshot_data
            .as_ref()
            .ok_or_else(|| MigratableError::Restore(anyhow!("Missing snapshot data")))?
            .to_owned_state()
    }

    /// Add a sub-component's Snapshot to the Snapshot.
    pub fn add_snapshot(&mut self, id: String, snapshot: Snapshot) {
        self.snapshots.insert(id, snapshot);
    }

    /// Generate the state data from the snapshot
    pub fn to_state<'a, T>(&'a self) -> Result<T, MigratableError>
    where
        T: Deserialize<'a>,
    {
        self.snapshot_data
            .as_ref()
            .ok_or_else(|| MigratableError::Restore(anyhow!("Missing snapshot data")))?
            .to_state()
    }
}

pub fn snapshot_from_id<'a>(snapshot: Option<&'a Snapshot>, id: &str) -> Option<&'a Snapshot> {
    snapshot.and_then(|s| s.snapshots.get(id))
}

pub fn state_from_id<'a, T>(s: Option<&'a Snapshot>, id: &str) -> Result<Option<T>, MigratableError>
where
    T: Deserialize<'a>,
{
    if let Some(s) = s.as_ref() {
        s.snapshots.get(id).map(|s| s.to_state()).transpose()
    } else {
        Ok(None)
    }
}

/// Restore an independent copy of pure state, or decode a persisted snapshot.
pub fn owned_state_from_id<T: Clone + serde::de::DeserializeOwned + Send + Sync + 'static>(
    snapshot: Option<&Snapshot>,
    id: &str,
) -> Result<Option<T>, MigratableError> {
    snapshot_from_id(snapshot, id)
        .map(Snapshot::to_owned_state)
        .transpose()
}

/// A snapshottable component can be snapshotted.
pub trait Snapshottable: Pausable {
    /// The snapshottable component id.
    fn id(&self) -> String {
        String::new()
    }

    /// Take a component snapshot.
    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Ok(Snapshot::default())
    }
}

/// A transportable component can be sent or receive to a specific URL.
///
/// This trait is meant to be used for component that have custom
/// transport handlers.
pub trait Transportable: Pausable + Snapshottable {
    /// Send a component snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - The migratable component snapshot to send.
    /// * `destination_url` - The destination URL to send the snapshot to. This
    ///   could be an HTTP endpoint, a TCP address or a local file.
    fn send(
        &self,
        _snapshot: &Snapshot,
        _destination_url: &str,
    ) -> result::Result<(), MigratableError> {
        Ok(())
    }

    /// Receive a component snapshot.
    ///
    /// # Arguments
    ///
    /// * `source_url` - The source URL to fetch the snapshot from. This could be an HTTP
    ///   endpoint, a TCP address or a local file.
    fn recv(&self, _source_url: &str) -> result::Result<Snapshot, MigratableError> {
        Ok(Snapshot::default())
    }
}

/// Trait to define shared behaviors of components that can be migrated
///
/// Examples are device, CPU, RAM, etc.
/// All migratable components are paused before being snapshotted, and then
/// eventually resumed. Thus any Migratable component must be both Pausable
/// and Snapshottable.
/// Moreover a migratable component can be transported to a remote or local
/// destination and thus must be Transportable.
pub trait Migratable: Send + Pausable + Snapshottable + Transportable {
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        Ok(MemoryRangeTable::default())
    }

    fn notify_started_migration(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    fn notify_failed_migration(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    fn notify_completed_migration(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }
}

#[cfg(test)]
mod owned_snapshot_tests {
    use super::*;
    #[test]
    fn owned_state_preserves_wire_format_and_independent_restores() {
        let original = vec![1_u64, 2, 3, u64::MAX];
        let lazy = SnapshotData::new_from_owned_state(original.clone());
        let mut parent: Vec<u64> = lazy.to_owned_state().unwrap();
        let child: Vec<u64> = lazy.clone().to_owned_state().unwrap();
        parent[0] = 99;
        assert_eq!(child, original);
        assert!(lazy.cached.as_ref().unwrap().json.get().is_none());
        let ordinary = SnapshotData::new_from_state(&original).unwrap();
        let wire = serde_json::to_string(&lazy).unwrap();
        assert_eq!(wire, serde_json::to_string(&ordinary).unwrap());
        let decoded: SnapshotData = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded.to_owned_state::<Vec<u64>>().unwrap(), original);
        assert_eq!(lazy.to_state::<Vec<u64>>().unwrap(), original);
    }

    #[test]
    fn owned_snapshot_tree_keeps_wire_format_and_restores_independent_values() {
        let mut native = Snapshot::default();
        native.add_snapshot(
            "device".into(),
            Snapshot::new_from_owned_state(vec![7_u64, 11]),
        );
        let mut persisted = Snapshot::default();
        persisted.add_snapshot(
            "device".into(),
            Snapshot::new_from_state(&vec![7_u64, 11]).unwrap(),
        );
        assert_eq!(
            serde_json::to_value(&native).unwrap(),
            serde_json::to_value(&persisted).unwrap()
        );
        let mut first: Vec<u64> = owned_state_from_id(Some(&native), "device")
            .unwrap()
            .unwrap();
        first[0] = 99;
        assert_eq!(
            owned_state_from_id::<Vec<u64>>(Some(&native), "device").unwrap(),
            Some(vec![7, 11])
        );
        assert_eq!(
            owned_state_from_id::<Vec<u64>>(Some(&persisted), "device").unwrap(),
            Some(vec![7, 11])
        );
        assert_eq!(
            owned_state_from_id::<Vec<u64>>(Some(&native), "missing").unwrap(),
            None
        );
        assert!(Snapshot::default().to_owned_state::<Vec<u64>>().is_err());
    }

    #[test]
    fn owned_state_can_be_serialized_concurrently() {
        let snapshot = SnapshotData::new_from_owned_state(vec![42_u64; 1024]);
        std::thread::scope(|scope| {
            let threads = (0..8)
                .map(|_| scope.spawn(|| serde_json::to_string(&snapshot).unwrap()))
                .collect::<Vec<_>>();
            let expected = serde_json::to_string(&snapshot).unwrap();
            for thread in threads {
                assert_eq!(thread.join().unwrap(), expected);
            }
        });
    }
}
