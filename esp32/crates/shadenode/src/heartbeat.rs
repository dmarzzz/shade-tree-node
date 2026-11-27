//! The heartbeat: announce this node to each Elder Tree so clients can find it.
//!
//! An Elder is itself an onion service, so the announce is an HTTP POST over a rendezvous
//! circuit dialed with the same Tor stack that hosts the node. The record is signed with the
//! node's onion identity key; nothing here trusts the Elder.

use std::time::Duration;

use microtor::crypto::rand_array;
use microtor::hs::{connect_with, fetch_descriptor};
use microtor::hsdesc::onion_address;
use microtor::hsdesc::IntroInfo;
use microtor::netdir::{backoff, now_unix};
use microtor::rt::{sleep, spawn, timeout};
use microtor::util::hex_encode;
use serde_json::Value;

use crate::node::Node;
use crate::proto::{build_announce, Caps, RatePolicy};

/// The Elder's onion virtual port.
const ELDER_PORT: u16 = 80;
/// How long an Elder's introduction points are reused before its descriptor is fetched again.
/// Descriptors last three hours; fetching one costs a circuit and tens of kilobytes.
const INTRO_CACHE: Duration = Duration::from_secs(40 * 60);

/// An Elder's introduction points from its last descriptor.
#[derive(Default)]
pub struct ElderRoute {
    known: Option<(Vec<IntroInfo>, [u8; 32], std::time::Instant)>,
}
const REPLY_LIMIT: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct HeartbeatConfig {
    /// Identity keys of the Elder Trees to announce to (the 32 bytes inside their onion
    /// addresses). They must also be listed in the onion service's `peers`.
    pub elders: Vec<[u8; 32]>,
    pub interval: Duration,
    /// Selection weight relative to other nodes (the reference default is 100; a node on a
    /// home line uses 10).
    pub weight: u64,
    /// `(address, signature)`: the operator's Ethereum address and its durable EIP-191
    /// signature over the authorization message. Elders that admit by stake require it.
    pub operator: Option<(String, String)>,
    pub region: Option<String>,
    /// Admission paths to advertise (`invited`, `staked`).
    pub admits: Vec<String>,
    /// On-chain sets this node reads roots from.
    pub sets: Vec<String>,
    /// Root freshness window to advertise, in seconds.
    pub root_freshness_seconds: u64,
}

/// The message an operator signs once (EIP-191 `personal_sign`) to bind an onion to a staked
/// address.
pub fn operator_auth_message(onion: &str, operator: &str) -> String {
    format!(
        "Shade Tree gateway operator authorization\nonion={onion}\noperator={}",
        operator.to_ascii_lowercase()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnounceOutcome {
    Accepted {
        staked: bool,
        ttl: u64,
    },
    /// The Elder answered and said no (for example `not-staked`).
    Rejected(String),
}

impl Node {
    /// The capabilities this node signs: only what it actually does.
    pub fn caps(&self, config: &HeartbeatConfig) -> Caps {
        Caps {
            ports: self.policy().ports(),
            region: config.region.clone(),
            artifacts: self.artifact_ids(),
            admits: config.admits.clone(),
            rate: Some(RatePolicy {
                epoch_seconds: self.config().epoch_seconds,
                root_freshness_seconds: config.root_freshness_seconds,
                payload_bytes_per_slot: self.config().payload_bytes_per_slot,
            }),
            session: if self.config().session_tickets {
                crate::session::CLASSES
                    .iter()
                    .map(|c| c.id.to_string())
                    .collect()
            } else {
                Vec::new()
            },
            draining: self.is_draining(),
            sets: config.sets.clone(),
            omit_proto: false,
        }
    }

    /// One signed announce to one Elder.
    pub async fn announce(
        &self,
        elder: &[u8; 32],
        config: &HeartbeatConfig,
        route: &mut ElderRoute,
    ) -> Result<AnnounceOutcome, microtor::Error> {
        let service = self.service();
        let onion = service.onion();
        let nonce = hex_encode(&rand_array::<16>());
        let operator = config
            .operator
            .as_ref()
            .map(|(a, s)| (a.as_str(), s.as_str()));
        let body = build_announce(
            service.identity(),
            &onion,
            config.weight,
            now_unix(),
            &nonce,
            &self.caps(config),
            operator,
        );
        let elder_onion = onion_address(elder);
        let tor = service.tor();
        let cached = route
            .known
            .as_ref()
            .filter(|(_, _, at)| at.elapsed() < INTRO_CACHE);
        let conn = match cached {
            Some((intros, subcred, _)) => connect_with(tor, intros, subcred, ELDER_PORT).await,
            None => Err(microtor::Error::Unavailable("no cached route")),
        };
        let conn = match conn {
            Ok(conn) => conn,
            Err(_) => {
                // No route yet, or the cached one went stale: read the descriptor again.
                route.known = None;
                let (intros, subcred) = fetch_descriptor(tor, elder).await?;
                let conn = connect_with(tor, &intros, &subcred, ELDER_PORT).await?;
                route.known = Some((intros, subcred, std::time::Instant::now()));
                conn
            }
        };
        let request = format!(
            "POST /announce HTTP/1.1\r\nHost: {elder_onion}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        conn.stream.write_all(request.as_bytes()).await?;
        let mut reply = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = timeout(
                Duration::from_secs(30),
                "announce reply",
                conn.stream.read(&mut buf),
            )
            .await?;
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n]);
            if reply.len() > REPLY_LIMIT {
                return Err(microtor::Error::Parse("announce reply too large"));
            }
        }
        let split = reply
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(microtor::Error::Parse("announce reply"))?;
        let json: Value = serde_json::from_slice(&reply[split + 4..])
            .map_err(|_| microtor::Error::Parse("announce reply body"))?;
        if json["ok"] == Value::Bool(true) {
            Ok(AnnounceOutcome::Accepted {
                staked: json["staked"].as_bool().unwrap_or(false),
                ttl: json["ttl"].as_u64().unwrap_or(0),
            })
        } else {
            Ok(AnnounceOutcome::Rejected(
                json["err"].as_str().unwrap_or("(no reason)").to_string(),
            ))
        }
    }

    /// Announce to every Elder now and then once per interval, for as long as the node runs.
    pub fn start_heartbeat(&self, config: HeartbeatConfig) {
        let node = self.clone();
        spawn(async move {
            // Nothing to announce until clients could actually reach the onion.
            while !node.service().is_published() {
                sleep(Duration::from_secs(2)).await;
            }
            let mut failures = 0u32;
            let mut routes: Vec<ElderRoute> = config
                .elders
                .iter()
                .map(|_| ElderRoute::default())
                .collect();
            loop {
                let mut any_ok = false;
                for (elder, route) in config.elders.iter().zip(routes.iter_mut()) {
                    let name = onion_address(elder);
                    match node.announce(elder, &config, route).await {
                        Ok(AnnounceOutcome::Accepted { staked, ttl }) => {
                            any_ok = true;
                            log::info!("announced to {name}: staked={staked} ttl={ttl}s");
                        }
                        Ok(AnnounceOutcome::Rejected(reason)) => {
                            log::warn!("{name} refused the announce: {reason}");
                        }
                        Err(e) => log::warn!("announce to {name} failed: {e}"),
                    }
                }
                let wait = if any_ok {
                    failures = 0;
                    config.interval
                } else {
                    failures += 1;
                    backoff(failures.min(5))
                        .max(Duration::from_secs(30))
                        .min(config.interval)
                };
                // Announce again at once when the drain state flips, so clients hear it within
                // seconds instead of at the next beat.
                let draining = node.is_draining();
                let until = std::time::Instant::now() + wait;
                while std::time::Instant::now() < until && node.is_draining() == draining {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_message_matches_the_wire_spec() {
        assert_eq!(
            operator_auth_message("abc.onion", "0x000000000000000000000000000000000000dEaD"),
            "Shade Tree gateway operator authorization\nonion=abc.onion\noperator=0x000000000000000000000000000000000000dead"
        );
    }
}
