// SPDX-License-Identifier: Apache-2.0
//! Rebind an immutable template to a durably prepared, private runtime slot.
use vm_migration::{Snapshot, SnapshotData};

use crate::vm::Error as VmError;
use crate::vm_config::VmConfig;

pub(crate) fn apply_config(source: &mut VmConfig, slot: &VmConfig) -> Result<(), VmError> {
    let fail = || {
        VmError::ForkUnsupported("Prepared identity requires plain private CoW RAM, read-only disks, one matching NIC and vsock".into())
    };
    if source.memory.shared
        || source.memory.hugepages
        || source.memory.zones.is_some()
        || source
            .disks
            .as_ref()
            .is_some_and(|ds| ds.iter().any(|d| !d.readonly))
    {
        return Err(fail());
    }
    let old = source
        .net
        .as_ref()
        .filter(|n| n.len() == 1)
        .ok_or_else(fail)?;
    let new = slot
        .net
        .as_ref()
        .filter(|n| n.len() == 1)
        .ok_or_else(fail)?;
    if old[0].pci_common.id.is_none()
        || old[0].pci_common.id != new[0].pci_common.id
        || new[0].mac.is_none()
        || source.vsock.is_none()
        || slot.vsock.is_none()
    {
        return Err(fail());
    }
    source.net = slot.net.clone();
    source.vsock = slot.vsock.clone();
    source.serial = slot.serial.clone();
    source.console = slot.console.clone();
    Ok(())
}

pub(crate) fn apply_snapshot(snapshot: &mut Snapshot, config: &VmConfig) -> Result<(), VmError> {
    let net = &config.net.as_ref().unwrap()[0];
    fn patch(snapshot: &mut Snapshot, id: &str, mac: &[u8]) -> Result<usize, VmError> {
        let mut count = 0;
        for (name, child) in &mut snapshot.snapshots {
            if name == id {
                let mut state: serde_json::Value = child.to_state().map_err(VmError::Restore)?;
                if !state["config"]["mac"].is_array() {
                    return Err(VmError::ForkUnsupported("Missing NIC MAC snapshot".into()));
                }
                state["config"]["mac"] = serde_json::json!(mac);
                child.snapshot_data =
                    Some(SnapshotData::new_from_state(&state).map_err(VmError::Restore)?);
                count += 1;
            }
            count += patch(child, id, mac)?;
        }
        Ok(count)
    }
    if patch(
        snapshot,
        net.pci_common.id.as_deref().unwrap(),
        net.mac.as_ref().unwrap().get_bytes(),
    )? != 1
    {
        return Err(VmError::ForkUnsupported(
            "Prepared NIC snapshot must occur exactly once".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(cid: u64, mac: &str) -> VmConfig {
        serde_json::from_value(serde_json::json!({
            "cpus":{"boot_vcpus":2,"max_vcpus":2},"memory":{"size":2147483648u64},
            "net":[{"id":"fork-net","mac":mac,"tap":format!("tap-{cid}")}],
            "vsock":{"cid":cid,"socket":format!("/slot/{cid}.vsock")},
            "disks":[{"path":"/template/root.raw","readonly":true}]
        }))
        .unwrap()
    }
    #[test]
    fn only_transport_identity_is_overridden() {
        let mut source = config(3, "02:00:00:00:00:03");
        let original = source.clone();
        let slot = config(4, "02:00:00:00:00:04");
        apply_config(&mut source, &slot).unwrap();
        assert_eq!(source.net, slot.net);
        assert_eq!(source.vsock, slot.vsock);
        assert_eq!(source.memory, original.memory);
        assert_eq!(source.cpus, original.cpus);
        assert_eq!(source.disks, original.disks);
    }
    #[test]
    fn incompatible_templates_fail_closed() {
        let slot = config(4, "02:00:00:00:00:04");
        for mode in 0..4 {
            let mut source = config(3, "02:00:00:00:00:03");
            match mode {
                0 => source.memory.shared = true,
                1 => source.memory.hugepages = true,
                2 => source.disks.as_mut().unwrap()[0].readonly = false,
                _ => source.net.as_mut().unwrap()[0].pci_common.id = Some("other".into()),
            }
            assert!(apply_config(&mut source, &slot).is_err());
        }
    }
    #[test]
    fn patch_requires_exactly_one_matching_nic() {
        let slot = config(4, "02:00:00:00:00:04");
        let nic = Snapshot::new_from_state(
            &serde_json::json!({"config":{"mac":[2,0,0,0,0,3]},"other":27}),
        )
        .unwrap();
        let mut snapshot = Snapshot::default();
        assert!(apply_snapshot(&mut snapshot, &slot).is_err());
        snapshot.add_snapshot("fork-net".into(), nic.clone());
        apply_snapshot(&mut snapshot, &slot).unwrap();
        let state: serde_json::Value = snapshot.snapshots["fork-net"].to_state().unwrap();
        assert_eq!(
            state["config"]["mac"],
            serde_json::json!([2, 0, 0, 0, 0, 4])
        );
        assert_eq!(state["other"], 27);
        let mut duplicate = Snapshot::default();
        duplicate.add_snapshot("fork-net".into(), nic);
        snapshot.add_snapshot("nested".into(), duplicate);
        assert!(apply_snapshot(&mut snapshot, &slot).is_err());
    }
}
