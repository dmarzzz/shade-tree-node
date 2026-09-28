//! Opt-in capability-aware selection filter (T-FEAT-10c) — the Rust port of
//! `client/selection.mjs`'s `gatewayMeetsRequirement` / `requirementActive` /
//! `filterByCapability`.
//!
//! A request MAY carry a capability REQUIREMENT `{ port?, proto?, region? }` so the
//! client routes to a gateway that can actually serve it (a destination port the
//! gateway's egress policy allows, a mutually-supported envelope version, or a coarse
//! region). Capabilities are the gateway's SIGNED self-declaration (`caps`/`capsSig`,
//! already verified by `verify_directory` before selection).
//!
//! OPT-IN and byte-identical by default: an EMPTY requirement leaves selection
//! untouched (`is_active() == false` — the fleet is not filtered). A requirement that
//! NO gateway meets FAILS CLOSED at the call site (the `select` command prints an error
//! naming the unmet requirement rather than dialing an incapable gateway).

use shadenet_proto::{canonical_caps, GatewayEntry, DEFAULT_EGRESS_PORT, DEFAULT_PROTO_VERSION};

/// A capability requirement carried by a request. All fields OPTIONAL; an all-`None`
/// requirement is INACTIVE and never filters. Mirrors the JS `req { port?, proto?, region? }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirement {
    pub port: Option<u64>,
    pub proto: Option<u64>,
    pub region: Option<String>,
}

impl Requirement {
    /// A requirement is "active" only if it actually constrains something; an empty one
    /// leaves selection untouched (`requirementActive`, `selection.mjs`).
    pub fn is_active(&self) -> bool {
        self.port.is_some() || self.proto.is_some() || self.region.is_some()
    }

    /// Human-readable `port=..,proto=..,region=..` for the fail-closed error
    /// (`describeRequirement`, `selection.mjs`).
    /// `leaf-source=paid,max-anon` for the egress log line (the live transport path).
    #[allow(dead_code)]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = self.port {
            parts.push(format!("port={p}"));
        }
        if let Some(p) = self.proto {
            parts.push(format!("proto={p}"));
        }
        if let Some(r) = &self.region {
            parts.push(format!("region={r}"));
        }
        parts.join(",")
    }
}

/// Does one directory entry satisfy a capability requirement? Pure + TOTAL
/// (`gatewayMeetsRequirement`, `selection.mjs`).
///
/// A gateway that advertises NO caps is assumed to meet ONLY the conservative default
/// ([`DEFAULT_EGRESS_PORT`] / [`DEFAULT_PROTO_VERSION`]) — it cannot prove a non-default
/// capability, so it is not selected for one. Region is NEVER implicit: a gateway must
/// advertise a matching region bucket to satisfy a region requirement.
pub fn gateway_meets_requirement(entry: &GatewayEntry, req: &Requirement) -> bool {
    // canonicalCaps(undefined) === {} in JS: a no-caps entry canonicalizes to empty.
    let caps = entry.caps.as_ref().map(canonical_caps).unwrap_or_default();

    if let Some(port) = req.port {
        match &caps.ports {
            Some(ports) => {
                if !ports.contains(&port) {
                    return false;
                }
            }
            // No advertised ports => only the conservative default egress port.
            None => {
                if port != DEFAULT_EGRESS_PORT {
                    return false;
                }
            }
        }
    }
    if let Some(v) = req.proto {
        match caps.proto {
            Some((min, max)) => {
                if v < min || v > max {
                    return false;
                }
            }
            // No advertised range => only the conservative default proto version.
            None => {
                if v != DEFAULT_PROTO_VERSION {
                    return false;
                }
            }
        }
    }
    if let Some(region) = &req.region {
        match &caps.region {
            Some(r) if r == region => {}
            _ => return false, // region is never implicit
        }
    }
    true
}

/// Retain in `gateways` only the entries meeting `req`. No-op (leaves the list untouched)
/// when the requirement is INACTIVE, so callers stay on the byte-identical selection path
/// (`filterByCapability`, `selection.mjs`). Returns the count retained.
pub fn filter_by_capability(gateways: &mut Vec<GatewayEntry>, req: &Requirement) -> usize {
    if req.is_active() {
        gateways.retain(|g| gateway_meets_requirement(g, req));
    }
    gateways.len()
}

// ---- admission-aware selection (T-FEAT-9, docs/adr/0008) ---------------------------------
// The Rust port of `filterByAdmission` (client/selection.mjs), kept MINIMAL: filter by the
// gateway's SIGNED `caps.admits` when a leaf source is given, and `--max-anon`. Parity notes:
//   - leaf source is an explicit CLI input here (`--leaf-source invited|staked|paid`); the JS
//     client also DISCOVERS it from which set holds the leaf (SHADE_TREE_LEAF_SOURCE=auto). The Rust
//     egress path takes `--members <file>` (an exported set) so it cannot know which set that
//     was — the operator names it. Absent => no admission filtering (byte-identical).
//   - absent `admits` on an entry = legacy gateway = "may admit any path" (kept) — same rollout
//     compat rule as JS; under `--max-anon` an absent policy cannot prove invited-only (dropped).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Admission {
    /// "invited" | "staked" | "paid" (the set the member's leaf is in), or None.
    pub leaf_source: Option<String>,
    /// Keep ONLY gateways whose admits is exactly ["invited"].
    pub max_anon: bool,
}

impl Admission {
    pub fn is_active(&self) -> bool {
        self.leaf_source.is_some() || self.max_anon
    }
    /// `leaf-source=paid,max-anon` for the egress log line (the live transport path).
    #[allow(dead_code)]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(l) = &self.leaf_source {
            parts.push(format!("leaf-source={l}"));
        }
        if self.max_anon {
            parts.push("max-anon".to_string());
        }
        parts.join(",")
    }
}

/// The gateway's canonical admits list, or None when it advertises no policy.
pub fn admits_of(entry: &GatewayEntry) -> Option<Vec<String>> {
    entry.caps.as_ref().and_then(|c| canonical_caps(c).admits)
}

/// Does one entry pass the admission constraint? Pure + TOTAL. See the module note.
pub fn gateway_admits(entry: &GatewayEntry, adm: &Admission) -> bool {
    if !adm.is_active() {
        return true;
    }
    let admits = admits_of(entry);
    if adm.max_anon {
        return matches!(&admits, Some(a) if a.len() == 1 && a[0] == "invited");
    }
    match (&admits, &adm.leaf_source) {
        (None, _) => true, // legacy / no policy advertised: assume it may admit us (rollout compat)
        (Some(a), Some(src)) => a.iter().any(|x| x == src),
        (Some(_), None) => true,
    }
}

/// Retain only entries passing `adm`; no-op when inactive. Returns the count retained.
#[cfg(test)]
pub fn filter_by_admission(gateways: &mut Vec<GatewayEntry>, adm: &Admission) -> usize {
    filter_by_admission_with_demo(gateways, adm, None)
}

/// Issue #67 demo routing.  `demo.gateways` is deliberately outside the signed
/// directory bytes, so it is used only for the explicit `--leaf-source demo`
/// choice.  A named gateway qualifies, as does a legacy gateway with no signed
/// `caps.admits`; a modern gateway is never inferred to support demo merely from
/// its signed admission list (whose fixed grammar intentionally excludes demo).
pub fn filter_by_admission_with_demo(
    gateways: &mut Vec<GatewayEntry>,
    adm: &Admission,
    demo_gateways: Option<&[String]>,
) -> usize {
    if !adm.is_active() {
        return gateways.len();
    }
    if adm.leaf_source.as_deref() == Some("demo") {
        let named: std::collections::HashSet<String> = demo_gateways
            .unwrap_or_default()
            .iter()
            .map(|onion| onion.to_ascii_lowercase())
            .collect();
        gateways
            .retain(|g| admits_of(g).is_none() || named.contains(&g.onion.to_ascii_lowercase()));
    } else {
        gateways.retain(|g| gateway_admits(g, adm));
    }
    gateways.len()
}

/// `gw1..=[invited,staked] gw2..=(no policy advertised)` for the fail-closed message.
pub fn describe_fleet_admits(gateways: &[GatewayEntry]) -> String {
    if gateways.is_empty() {
        return "(empty directory)".to_string();
    }
    gateways
        .iter()
        .map(|g| {
            let short: String = g.onion.chars().take(12).collect();
            match admits_of(g) {
                Some(a) => format!("{short}..=[{}]", a.join(",")),
                None => format!("{short}..=(no policy advertised)"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The ports the fleet egresses to, for the port-not-allowed message: `443` or `80,443,8443`.
pub fn describe_fleet_ports(gateways: &[GatewayEntry]) -> String {
    let mut ports = std::collections::BTreeSet::new();
    for gateway in gateways {
        match gateway.caps.as_ref().and_then(|c| canonical_caps(c).ports) {
            Some(list) => ports.extend(list),
            None => {
                ports.insert(DEFAULT_EGRESS_PORT);
            }
        }
    }
    if ports.is_empty() {
        return DEFAULT_EGRESS_PORT.to_string();
    }
    ports
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Why no gateway passed the admission filter.
pub fn admission_refusal(adm: &Admission, before: &[GatewayEntry]) -> String {
    if adm.max_anon {
        if adm.leaf_source.as_deref() == Some("demo") {
            return "max-anon: your leaf is in the demo set; demo admission is linked to the one-shot access request. Max-anon requires an invited (members.json) leaf.".to_string();
        }
        return format!(
            "max-anon: no invited-only node in the canopy (a node qualifies only when its signed caps say admits=[invited]); fleet: {}",
            describe_fleet_admits(before)
        );
    }
    format!(
        "no node admits a {} leaf (your leaf source); fleet: {} -- obtain a leaf in a set the canopy admits (docs/CLIENTS.md \"Leaf source\")",
        adm.leaf_source.as_deref().unwrap_or("?"),
        describe_fleet_admits(before)
    )
}

/// Validate admission inputs before any dial: a bad name, or max-anon over a staked/paid leaf, is
/// a precise refusal, never a wasted proof.
pub fn check_admission(adm: &Admission) -> Result<(), String> {
    if let Some(src) = &adm.leaf_source {
        if src != "demo" && !shadenet_proto::ADMIT_PATHS.contains(&src.as_str()) {
            return Err(format!(
                "--leaf-source: expected invited, staked, paid or demo (got {src})"
            ));
        }
        if adm.max_anon && src == "demo" {
            return Err("--max-anon: your leaf is in the demo set; demo admission is linked to the one-shot access request. Max-anon requires an invited (members.json) leaf -- drop --max-anon to use a demo gateway.".to_string());
        }
        if adm.max_anon && src != "invited" {
            return Err(format!("--max-anon: your leaf is in the {src} set; an invited-only gateway would reject it (wrong-group-root). Max-anon requires an invited (members.json) leaf -- drop --max-anon to use gateways that admit {src}."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_proto::{Caps, ProtoCaps};

    fn admits_entry(admits: Option<&[&str]>) -> GatewayEntry {
        entry_with(admits.map(|a| Caps {
            admits: Some(a.iter().map(|x| x.to_string()).collect()),
            ..Default::default()
        }))
    }

    #[test]
    fn admission_filter_by_leaf_source_and_max_anon() {
        let legacy = admits_entry(None);
        let inv = admits_entry(Some(&["invited"]));
        let inv_staked = admits_entry(Some(&["staked", "invited"]));
        let all = admits_entry(Some(&["paid", "staked", "invited"]));
        // inactive: no-op
        let mut g = vec![legacy.clone(), inv.clone(), inv_staked.clone(), all.clone()];
        assert_eq!(filter_by_admission(&mut g, &Admission::default()), 4);
        // paid leaf: only `all` admits it; legacy kept (compat)
        let mut g = vec![legacy.clone(), inv.clone(), inv_staked.clone(), all.clone()];
        let adm = Admission {
            leaf_source: Some("paid".into()),
            max_anon: false,
        };
        assert_eq!(filter_by_admission(&mut g, &adm), 2);
        assert!(
            g.iter()
                .all(|e| admits_of(e).is_none()
                    || admits_of(e).unwrap().contains(&"paid".to_string()))
        );
        // staked leaf
        let mut g = vec![legacy.clone(), inv.clone(), inv_staked.clone(), all.clone()];
        let adm = Admission {
            leaf_source: Some("staked".into()),
            max_anon: false,
        };
        assert_eq!(filter_by_admission(&mut g, &adm), 3);
        // max-anon: exactly ["invited"] only; legacy dropped
        let mut g = vec![legacy.clone(), inv.clone(), inv_staked.clone(), all.clone()];
        let adm = Admission {
            leaf_source: Some("invited".into()),
            max_anon: true,
        };
        assert_eq!(filter_by_admission(&mut g, &adm), 1);
        assert_eq!(admits_of(&g[0]).unwrap(), vec!["invited".to_string()]);
        // max-anon with no invited-only gateway: empty (caller fails closed)
        let mut g = vec![legacy.clone(), inv_staked.clone(), all.clone()];
        assert_eq!(
            filter_by_admission(
                &mut g,
                &Admission {
                    leaf_source: None,
                    max_anon: true
                }
            ),
            0
        );
        assert!(describe_fleet_admits(&[legacy, all]).contains("(no policy advertised)"));
    }

    #[test]
    fn demo_admission_uses_unsigned_candidate_names_or_legacy_only() {
        let mut modern_named = admits_entry(Some(&["invited"]));
        modern_named.onion = "named.onion".into();
        let mut modern_other = admits_entry(Some(&["invited", "staked"]));
        modern_other.onion = "other.onion".into();
        let mut legacy = admits_entry(None);
        legacy.onion = "legacy.onion".into();
        let mut gateways = vec![modern_named.clone(), modern_other, legacy.clone()];
        let adm = Admission {
            leaf_source: Some("demo".into()),
            max_anon: false,
        };
        filter_by_admission_with_demo(&mut gateways, &adm, Some(&["named.onion".to_string()]));
        assert_eq!(gateways.len(), 2);
        assert!(gateways.iter().any(|g| g.onion == modern_named.onion));
        assert!(gateways.iter().any(|g| g.onion == legacy.onion));
    }

    fn entry_with(caps: Option<Caps>) -> GatewayEntry {
        GatewayEntry {
            onion: "gw.onion".to_string(),
            pubkey: String::new(),
            weight: 100,
            health: "up".to_string(),
            operator: None,
            staked: None,
            caps,
            caps_sig: None,
        }
    }

    fn full_caps() -> Caps {
        Caps {
            ports: Some(vec![80, 443]),
            region: Some("eu".to_string()),
            proto: Some(ProtoCaps { min: 4, max: 4 }),
            ..Default::default()
        }
    }

    #[test]
    fn inactive_requirement_matches_everything() {
        let req = Requirement::default();
        assert!(!req.is_active());
        // Even a no-caps gateway passes an inactive (empty) requirement.
        assert!(gateway_meets_requirement(&entry_with(None), &req));
    }

    #[test]
    fn no_caps_gateway_meets_only_conservative_floor() {
        let e = entry_with(None);
        // Default 443 / proto 4 are the implicit floor a no-caps gateway can serve.
        assert!(gateway_meets_requirement(
            &e,
            &Requirement {
                port: Some(443),
                ..Default::default()
            }
        ));
        assert!(gateway_meets_requirement(
            &e,
            &Requirement {
                proto: Some(4),
                ..Default::default()
            }
        ));
        // A non-default port/proto it never advertised => not selected (fail closed).
        assert!(!gateway_meets_requirement(
            &e,
            &Requirement {
                port: Some(80),
                ..Default::default()
            }
        ));
        assert!(!gateway_meets_requirement(
            &e,
            &Requirement {
                proto: Some(3),
                ..Default::default()
            }
        ));
        // Region is never implicit.
        assert!(!gateway_meets_requirement(
            &e,
            &Requirement {
                region: Some("eu".to_string()),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn advertised_caps_gate_by_membership_and_range() {
        let e = entry_with(Some(full_caps()));
        // Advertised port 80 is now allowed; an un-advertised 22 is not.
        assert!(gateway_meets_requirement(
            &e,
            &Requirement {
                port: Some(80),
                ..Default::default()
            }
        ));
        assert!(!gateway_meets_requirement(
            &e,
            &Requirement {
                port: Some(22),
                ..Default::default()
            }
        ));
        // proto range {4,4}: 4 in range, 3 below.
        assert!(gateway_meets_requirement(
            &e,
            &Requirement {
                proto: Some(4),
                ..Default::default()
            }
        ));
        assert!(!gateway_meets_requirement(
            &e,
            &Requirement {
                proto: Some(3),
                ..Default::default()
            }
        ));
        // region match / mismatch.
        assert!(gateway_meets_requirement(
            &e,
            &Requirement {
                region: Some("eu".to_string()),
                ..Default::default()
            }
        ));
        assert!(!gateway_meets_requirement(
            &e,
            &Requirement {
                region: Some("na".to_string()),
                ..Default::default()
            }
        ));
        // All three together, all satisfied.
        assert!(gateway_meets_requirement(
            &e,
            &Requirement {
                port: Some(443),
                proto: Some(4),
                region: Some("eu".to_string()),
            }
        ));
    }

    #[test]
    fn filter_is_noop_when_inactive_and_fails_closed_when_unmet() {
        let mut gws = vec![entry_with(None), entry_with(Some(full_caps()))];
        // Inactive requirement: list untouched (byte-identical selection path).
        let n = filter_by_capability(&mut gws, &Requirement::default());
        assert_eq!(n, 2);
        // Active requirement port=80: only the caps gateway advertises 80.
        let mut gws2 = vec![entry_with(None), entry_with(Some(full_caps()))];
        let n2 = filter_by_capability(
            &mut gws2,
            &Requirement {
                port: Some(80),
                ..Default::default()
            },
        );
        assert_eq!(n2, 1);
        assert_eq!(gws2[0].onion, "gw.onion");
        // Active requirement no gateway meets => empty (caller fails closed).
        let mut gws3 = vec![entry_with(None)];
        let n3 = filter_by_capability(
            &mut gws3,
            &Requirement {
                port: Some(8080),
                ..Default::default()
            },
        );
        assert_eq!(n3, 0);
    }

    #[test]
    fn describe_names_the_unmet_requirement() {
        let req = Requirement {
            port: Some(80),
            proto: Some(4),
            region: Some("eu".to_string()),
        };
        assert_eq!(req.describe(), "port=80,proto=4,region=eu");
    }
}
