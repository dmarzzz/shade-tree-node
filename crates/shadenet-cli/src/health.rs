//! Cross-session gateway health cache — the Rust port of the `reportResult`
//! persistence in `client/selection.mjs` (T-FEAT-19), wired for T-RUST-3.
//!
//! A one-shot `shade-tree` invocation is not a long-lived process like the JS
//! `ShadeTreeClient`, so "deprioritize a failing gateway within the session" only
//! becomes observable if the liveness feedback is persisted to disk between
//! invocations. This is exactly what `selection.mjs`'s
//! `loadHealthCache`/`saveHealthCache`/`seedHealthFromCache`/`updateHealthCache`
//! do, and this module matches their on-disk shape byte-for-byte:
//!
//! ```json
//! { "version": 1, "entries": { "<onion>.onion": { "fails": 2, "lastFail": 0,
//!                                                  "latencyMs": null, "lastSeen": 0 } } }
//! ```
//!
//! Scope + privacy (mirrors `selection.mjs`): a LOCAL file only, never sent
//! anywhere. It stores only onions the client already learned from the SIGNED
//! directory plus a fail count, a last-fail/last-seen wall clock (ms), and a
//! latency EWMA. A successful dial resets fails (recovery); a failure increments
//! toward the "down" threshold. An entry not SEEN for the decay window is treated
//! as recovered (pruned), so a gateway is never blacklisted forever.
//!
//! Everything here is default-build (serde_json only) — no `arti`/`ark`/`tokio`.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use shadenet_proto::Directory;

/// `>= 2` consecutive fails flips a gateway to health `"down"`, mirroring
/// `reportHealth` / `HEALTH_FAIL_THRESHOLD` in `lib/directory.mjs` + `selection.mjs`.
pub const FAIL_THRESHOLD: u64 = 2;
/// Max distinct gateways retained; oldest-`lastSeen` evicted first
/// (`selection.mjs` `HEALTH_MAX_ENTRIES`). Used by `save` (live/test paths).
#[cfg_attr(not(any(feature = "live", test)), allow(dead_code))]
pub const MAX_ENTRIES: usize = 512;
/// An entry not seen for this long is treated as recovered and pruned
/// (`selection.mjs` `HEALTH_DECAY_MS`, 14 days in ms).
pub const DECAY_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// One per-gateway liveness record. Field names match the JS wire keys exactly
/// (`fails`/`lastFail`/`latencyMs`/`lastSeen`) so the cache is interoperable with
/// the JS client's file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthEntry {
    #[serde(default)]
    pub fails: u64,
    #[serde(rename = "lastFail", default)]
    pub last_fail: u64,
    #[serde(rename = "latencyMs", default)]
    pub latency_ms: Option<f64>,
    #[serde(rename = "lastSeen", default)]
    pub last_seen: u64,
}

/// onion(with `.onion` suffix) -> record. `BTreeMap` keeps a stable key order so
/// the written file is deterministic (a cosmetic improvement over the JS object
/// order; the shape is identical).
pub type HealthCache = BTreeMap<String, HealthEntry>;

// The versioned envelope we write and (leniently) read.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    version: Option<u64>,
    #[serde(default)]
    entries: Option<HealthCache>,
}

#[cfg_attr(not(any(feature = "live", test)), allow(dead_code))]
#[derive(Serialize)]
struct WriteEnvelope<'a> {
    version: u64,
    entries: &'a HealthCache,
}

/// Read the persisted cache. Best-effort and TOTAL: any error
/// (missing/unwritable/corrupt) yields an empty map, so a broken cache can never
/// break selection. Tolerates the versioned envelope we write AND a bare
/// `onion -> entry` map (matches `loadHealthCache`).
pub fn load(path: Option<&Path>) -> HealthCache {
    let Some(path) = path else {
        return HealthCache::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return HealthCache::new();
    };
    if let Ok(env) = serde_json::from_str::<Envelope>(&raw) {
        if let Some(entries) = env.entries {
            return entries;
        }
        if env.version.is_none() {
            // No `entries` and no `version`: might be a bare map.
            if let Ok(bare) = serde_json::from_str::<HealthCache>(&raw) {
                return bare;
            }
        }
    }
    HealthCache::new()
}

/// Evict the oldest-`lastSeen` entries in place down to `max` so the cache can
/// never grow unboundedly (`boundHealthCache`).
#[cfg_attr(not(any(feature = "live", test)), allow(dead_code))]
fn bound(cache: &mut HealthCache, max: usize) {
    if cache.len() <= max {
        return;
    }
    let mut keys: Vec<(String, u64)> = cache
        .iter()
        .map(|(k, v)| (k.clone(), v.last_seen))
        .collect();
    keys.sort_by_key(|(_, seen)| *seen);
    let drop_n = cache.len() - max;
    for (k, _) in keys.into_iter().take(drop_n) {
        cache.remove(&k);
    }
}

/// Write-through, bounded, best-effort. Returns `true` iff the file was written; a
/// failure (no path, read-only dir, ...) is swallowed so persistence-off never
/// affects selection (`saveHealthCache`). Used by the live egress failover feedback
/// (and unit tests); not reached on the default deterministic-only build.
#[cfg_attr(not(any(feature = "live", test)), allow(dead_code))]
pub fn save(path: Option<&Path>, cache: &mut HealthCache) -> bool {
    let Some(path) = path else { return false };
    bound(cache, MAX_ENTRIES);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body = match serde_json::to_string_pretty(&WriteEnvelope {
        version: 1,
        entries: cache,
    }) {
        Ok(s) => s + "\n",
        Err(_) => return false,
    };
    std::fs::write(path, body).is_ok()
}

/// Seed a freshly-loaded directory's in-memory health from the persisted cache so
/// a gateway that failed a lot last session STARTS deprioritized (`health="down"`)
/// until it proves healthy again this session. Decay, not blacklist: an entry not
/// seen for `DECAY_MS` is pruned from the cache and ignored. Mutates
/// `dir.gateways` in place (`seedHealthFromCache`).
pub fn seed(dir: &mut Directory, cache: &mut HealthCache, now_ms: u64) {
    for g in &mut dir.gateways {
        let Some(e) = cache.get(&g.onion) else {
            continue;
        };
        if now_ms.saturating_sub(e.last_seen) >= DECAY_MS {
            cache.remove(&g.onion); // decayed: recovered, prune
            continue;
        }
        if e.fails >= FAIL_THRESHOLD {
            g.health = "down".to_string();
        }
    }
}

/// Fold one dial result into the persisted cache. Privacy guard: only persist an
/// onion the client already knows from the SIGNED directory (`known` is the set of
/// directory onions), never arbitrary caller input. A successful dial resets fails
/// (recovery); a failure increments toward the "down" threshold
/// (`updateHealthCache`). Used by the live egress failover feedback (and unit
/// tests); not reached on the default deterministic-only build.
#[cfg_attr(not(any(feature = "live", test)), allow(dead_code))]
pub fn update(
    cache: &mut HealthCache,
    known: &HashSet<String>,
    onion: &str,
    ok: bool,
    latency_ms: Option<f64>,
    now_ms: u64,
) {
    let full = if onion.ends_with(".onion") {
        onion.to_string()
    } else {
        format!("{onion}.onion")
    };
    if !known.contains(&full) {
        return; // unknown onion: don't persist
    }
    let e = cache.entry(full).or_default();
    if !ok {
        e.fails += 1;
        e.last_fail = now_ms;
    } else {
        e.fails = 0; // a successful dial recovers the gateway
        if let Some(l) = latency_ms {
            e.latency_ms = Some(match e.latency_ms {
                Some(prev) => (0.7 * prev + 0.3 * l).round(),
                None => l,
            });
        }
    }
    e.last_seen = now_ms;
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_proto::GatewayEntry;

    fn entry(onion: &str, health: &str) -> GatewayEntry {
        GatewayEntry {
            onion: onion.to_string(),
            pubkey: String::new(),
            weight: 100,
            health: health.to_string(),
            operator: None,
            staked: None,
            caps: None,
            caps_sig: None,
        }
    }

    fn dir(onions: &[&str]) -> Directory {
        Directory {
            version: 1,
            issued: 1000,
            gateways: onions.iter().map(|o| entry(o, "up")).collect(),
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        }
    }

    #[test]
    fn failing_dial_marks_down_after_threshold() {
        let mut cache = HealthCache::new();
        let known: HashSet<String> = ["a.onion".to_string()].into_iter().collect();
        update(&mut cache, &known, "a.onion", false, None, 1);
        update(&mut cache, &known, "a.onion", false, None, 2);
        assert_eq!(cache["a.onion"].fails, 2);

        let mut d = dir(&["a.onion", "b.onion"]);
        seed(&mut d, &mut cache, 3);
        assert_eq!(d.gateways[0].health, "down"); // a: 2 fails -> down
        assert_eq!(d.gateways[1].health, "up"); // b: unknown -> untouched
    }

    #[test]
    fn success_recovers_and_records_latency() {
        let mut cache = HealthCache::new();
        let known: HashSet<String> = ["a.onion".to_string()].into_iter().collect();
        update(&mut cache, &known, "a.onion", false, None, 1);
        update(&mut cache, &known, "a.onion", true, Some(50.0), 2);
        assert_eq!(cache["a.onion"].fails, 0); // recovered
        assert_eq!(cache["a.onion"].latency_ms, Some(50.0));
    }

    #[test]
    fn privacy_guard_ignores_unknown_onion() {
        let mut cache = HealthCache::new();
        let known: HashSet<String> = HashSet::new();
        update(&mut cache, &known, "evil.onion", false, None, 1);
        assert!(cache.is_empty()); // not in the signed directory -> never persisted
    }

    #[test]
    fn decayed_entry_is_pruned_not_seeded() {
        let mut cache = HealthCache::new();
        cache.insert(
            "a.onion".to_string(),
            HealthEntry {
                fails: 5,
                last_fail: 0,
                latency_ms: None,
                last_seen: 0,
            },
        );
        let mut d = dir(&["a.onion"]);
        seed(&mut d, &mut cache, DECAY_MS + 1); // way past decay
        assert_eq!(d.gateways[0].health, "up"); // recovered, not down
        assert!(cache.is_empty()); // pruned
    }

    #[test]
    fn roundtrips_and_tolerates_bare_map() {
        let dir = tempdir();
        let path = dir.join("gateway-health.json");
        let mut cache = HealthCache::new();
        let known: HashSet<String> = ["a.onion".to_string()].into_iter().collect();
        update(&mut cache, &known, "a.onion", false, None, 7);
        assert!(save(Some(&path), &mut cache));
        let back = load(Some(&path));
        assert_eq!(back["a.onion"].fails, 1);

        // A bare onion->entry map (no envelope) must also load.
        std::fs::write(&path, r#"{"b.onion":{"fails":3}}"#).unwrap();
        let bare = load(Some(&path));
        assert_eq!(bare["b.onion"].fails, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("shade-tree-health-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
