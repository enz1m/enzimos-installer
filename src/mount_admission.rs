// SPDX-License-Identifier: MIT
//! Complete namespace baseline plus newly retained mount proofs, never path claims.
use crate::disk_guard::Device;
use enzimos_platform::{Error, Result, mountinfo, require};
use enzimos_policy::{namespaces, topology};
use std::collections::{BTreeMap, BTreeSet};
type Namespace = (u64, u64);
type Rows = BTreeMap<(Namespace, u64), mountinfo::Row>;
#[derive(Clone)]
pub(crate) struct Proof {
    pub namespace: Namespace,
    pub row: mountinfo::Row,
    pub source: Device,
    pub uuid: String,
    pub graph: topology::Graph,
}
pub(crate) struct Baseline {
    rows: Rows,
    graphs: BTreeMap<String, topology::Graph>,
    // The copied row keys must retain their original namespace objects for the
    // whole target lifetime, rather than outliving recyclable inode numbers.
    _namespaces: namespaces::Observation,
}
fn btrfs_rows(views: &namespaces::Observation) -> Result<Rows> {
    let mut rows = BTreeMap::new();
    for view in &views.views {
        for row in &view.mounts {
            if row.filesystem == "btrfs" {
                require(
                    rows.len() < 4096
                        && rows.insert((view.identity, row.id), row.clone()).is_none(),
                    "duplicate namespace Btrfs observation",
                )?;
            }
        }
    }
    Ok(rows)
}
fn graphs() -> Result<BTreeMap<String, topology::Graph>> {
    let mut graphs = BTreeMap::new();
    let entries = match std::fs::read_dir("/sys/fs/btrfs") {
        Ok(entries) => Some(entries),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    for entry in entries.into_iter().flatten() {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error("Btrfs kernel name encoding".into()))?;
        if name == "features" {
            continue;
        }
        require(graphs.len() < 64, "Btrfs kernel member count bound")?;
        enzimos_policy::identity::uuid(&name)?;
        graphs.insert(name.clone(), topology::mounted_btrfs(&name)?);
    }
    Ok(graphs)
}
impl Baseline {
    pub(crate) fn capture(disk: Device) -> Result<Self> {
        namespaces::initial()?;
        let namespaces = namespaces::observe()?;
        let rows = btrfs_rows(&namespaces)?;
        let graphs = graphs()?;
        require(
            graphs.values().all(|g| !g.leaves.contains(&disk)),
            "selected disk has pre-existing Btrfs users",
        )?;
        let this = Self {
            rows,
            graphs,
            _namespaces: namespaces,
        };
        this.admit(&namespaces::observe()?, &[], disk)?;
        Ok(this)
    }
    pub(crate) fn admit(
        &self,
        views: &namespaces::Observation,
        owned: &[Proof],
        disk: Device,
    ) -> Result<()> {
        namespaces::initial()?;
        require(owned.len() <= 8, "installer owned mount bound")?;
        let initial = namespaces::identity(std::process::id(), "mnt")?;
        let mut rows = self.rows.clone();
        let mut expected_graphs = self.graphs.clone();
        let mut unique = BTreeSet::new();
        for proof in owned {
            require(
                proof.namespace == initial
                    && matches!(proof.row.filesystem.as_str(), "btrfs" | "vfat")
                    && proof.graph.leaves == BTreeSet::from([disk])
                    && proof.graph.nodes.contains_key(&proof.source)
                    && unique.insert((initial, proof.row.id)),
                "foreign or duplicate installer mount proof",
            )?;
            if proof.row.filesystem == "vfat" {
                require(
                    (proof.row.major, proof.row.minor) == proof.source,
                    "owned ESP has a foreign kernel source",
                )?;
                continue;
            }
            require(
                !self.graphs.contains_key(&proof.uuid)
                    && rows
                        .insert((initial, proof.row.id), proof.row.clone())
                        .is_none(),
                "owned Btrfs mount overlaps baseline",
            )?;
            if let Some(existing) = expected_graphs.insert(proof.uuid.clone(), proof.graph.clone())
            {
                require(
                    existing == proof.graph,
                    "owned Btrfs graph differs between mounts",
                )?;
            }
        }
        require(
            btrfs_rows(views)? == rows && graphs()? == expected_graphs,
            "Btrfs mount namespaces or kernel members changed outside owned staging",
        )
    }
}
pub(crate) fn paths(proofs: &[Proof]) -> BTreeMap<Device, BTreeSet<String>> {
    let mut paths = BTreeMap::<Device, BTreeSet<String>>::new();
    for proof in proofs {
        paths
            .entry(proof.source)
            .or_default()
            .insert(proof.row.target.clone());
    }
    paths
}
pub(crate) fn owns(proofs: &[Proof], namespace: Namespace, row: &mountinfo::Row) -> bool {
    proofs
        .iter()
        .any(|proof| proof.namespace == namespace && proof.row == *row)
}
