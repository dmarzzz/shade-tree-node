//! The admitted root set (`gateway.mjs` `initRoots`): the union of the invited member file's
//! root and every on-chain source's recent roots, per `SHADE_TREE_ADMIT`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::chain::{Advert, ChainSource};
use crate::members::MemberSet;

pub(crate) struct Roots {
    members: Option<Arc<MemberSet>>,
    chain: Option<Arc<ChainSource>>,
}

impl Roots {
    pub(crate) fn new(members: Option<Arc<MemberSet>>, chain: Option<Arc<ChainSource>>) -> Self {
        Self { members, chain }
    }

    pub(crate) fn accepted(&self) -> HashSet<String> {
        let mut roots = HashSet::new();
        if let Some(members) = &self.members {
            roots.insert(members.root());
        }
        if let Some(chain) = &self.chain {
            roots.extend(chain.roots());
        }
        roots
    }

    /// A leaf in the invited set, for naming the tier of a slashed secret locally.
    pub(crate) fn has_leaf(&self, leaf: &str) -> bool {
        self.members.as_ref().is_some_and(|m| m.has_leaf(leaf))
    }

    /// The extras of a `wrong-group-root` refusal: the accepted roots (bounded) and, when an
    /// on-chain source exists, its observed block and live leaf count.
    pub(crate) fn advert(&self, max_roots: usize) -> Vec<(&'static str, String)> {
        let roots: Vec<String> = self.accepted().into_iter().take(max_roots).collect();
        let mut extras = vec![(
            "roots",
            serde_json::to_string(&roots).unwrap_or_else(|_| "[]".into()),
        )];
        if let Some(Advert { block, leaves }) = self.chain.as_ref().map(|c| c.advert()) {
            if let Some(block) = block {
                extras.push(("rootBlock", block.to_string()));
            }
            if let Some(leaves) = leaves {
                extras.push(("rootLeaves", leaves.to_string()));
            }
        }
        extras
    }
}
