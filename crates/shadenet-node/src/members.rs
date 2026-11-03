//! The invited member set: `{"members":[leaf,...]}` turned into the depth-20 Poseidon tree
//! root a proof must name (`packages/node/lib/rln.mjs` `loadGroup`). The file is reloaded
//! when it changes on disk.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use ark_bn254::Fr;
use num_bigint::BigUint;
use serde::Deserialize;
use shadenet_rln::tree::{fr_to_dec, parse_fr, MerkleTree};

use crate::error::Error;

const TREE_DEPTH: usize = 20;
const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct MembersFile {
    members: Vec<String>,
}

struct State {
    root: String,
    leaves: HashSet<String>,
    modified: Option<SystemTime>,
}

pub(crate) struct MemberSet {
    path: PathBuf,
    rln_identifier: BigUint,
    state: RwLock<State>,
}

impl MemberSet {
    pub(crate) fn load(path: PathBuf, rln_identifier: BigUint) -> Result<Self, Error> {
        let state = read(&path, &rln_identifier)?;
        tracing::info!(
            "invited member set: {} leaves from {}",
            state.leaves.len(),
            path.display()
        );
        Ok(Self {
            path,
            rln_identifier,
            state: RwLock::new(state),
        })
    }

    /// The root a proof may name.
    pub(crate) fn root(&self) -> String {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .root
            .clone()
    }

    pub(crate) fn has_leaf(&self, leaf: &str) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .leaves
            .contains(leaf)
    }

    /// Reload the file whenever its modification time changes.
    pub(crate) async fn watch(self: Arc<Self>) {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let modified = std::fs::metadata(&self.path)
                .and_then(|m| m.modified())
                .ok();
            let unchanged = {
                let state = self.state.read().unwrap_or_else(|e| e.into_inner());
                modified.is_none() || state.modified == modified
            };
            if unchanged {
                continue;
            }
            match read(&self.path, &self.rln_identifier) {
                Ok(fresh) => {
                    tracing::info!("invited member set reloaded: {} leaves", fresh.leaves.len());
                    *self.state.write().unwrap_or_else(|e| e.into_inner()) = fresh;
                }
                Err(e) => tracing::warn!("invited member set not reloaded: {e}"),
            }
        }
    }
}

fn read(path: &PathBuf, rln_identifier: &BigUint) -> Result<State, Error> {
    let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let bytes = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.clone(),
        source,
    })?;
    let file: MembersFile = serde_json::from_slice(&bytes).map_err(|source| Error::ParseJson {
        path: path.clone(),
        source,
    })?;
    let leaves = file
        .members
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            parse_fr(leaf).map_err(|e| Error::FileContent {
                path: path.clone(),
                message: format!("members[{index}]: {e}"),
            })
        })
        .collect::<Result<Vec<Fr>, _>>()?;
    let root = fr_to_dec(&MerkleTree::new(rln_identifier, TREE_DEPTH, &leaves).root());
    Ok(State {
        root,
        leaves: leaves.iter().map(fr_to_dec).collect(),
        modified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repo_member_file_has_one_root_and_its_leaves() {
        let path = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../group/members.json"
        ));
        let set = MemberSet::load(path.clone(), BigUint::from(1_u8)).unwrap();
        assert!(!set.root().is_empty());
        let file: MembersFile = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(set.has_leaf(&file.members[0]));
        assert!(!set.has_leaf("1"));
    }
}
