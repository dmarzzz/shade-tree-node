//! What an over-spend reveals and what the node does with it (`packages/node/lib/rln.mjs`
//! `reconstructSecret`, `resolveSlashLeaf`; `gateway.mjs` `makeSlasher`, `makeOnchainSlasher`,
//! `makeRoutingSlasher`). Two shares on the line `y = secret + a1*x` give the secret; the leaf
//! to slash is the tier whose rate commitment is in the admitted set, or whichever configured
//! contract reports holding one. The reply to the client never waits for the chain.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use ark_ff::Field;
use serde_json::{json, Value};
use shadenet::eth::{self, calldata, decode_uints, Address, Eip1559, Token, Wallet, U256};
use shadenet_rln::tree::{fr_to_dec, rate_commitment};

use crate::chain::Kind;
use crate::rpc::{Rpc, RpcError};
use crate::spent::Share;
use crate::verify::parse_field;

const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
const RECEIPT_POLL: Duration = Duration::from_secs(2);
const SLASH_PAYOUT_TOPIC: &str = "SlashPayout(uint256,address,uint256,uint256)";

pub(crate) struct Tier {
    pub(crate) commitment: String,
    pub(crate) limit: u64,
    pub(crate) resolved: bool,
}

pub(crate) fn reconstruct_secret(a: &Share, b: &Share) -> Result<Fr, String> {
    let (xa, ya) = (parse_field(&a.x)?, parse_field(&a.y)?);
    let (xb, yb) = (parse_field(&b.x)?, parse_field(&b.y)?);
    let dx = xb - xa;
    let slope = (yb - ya)
        * dx.inverse()
            .ok_or_else(|| "identical evaluation points".to_string())?;
    Ok(ya - slope * xa)
}

/// The leaf one secret could sit behind, one candidate per tier, preferring the one the
/// node admits; the default tier when none is.
pub(crate) fn resolve_tier(
    secret: Fr,
    tiers: &[u64],
    default: u64,
    has_leaf: impl Fn(&str) -> bool,
) -> Tier {
    let mut candidates: Vec<Tier> = tiers
        .iter()
        .map(|limit| Tier {
            commitment: fr_to_dec(&rate_commitment(secret, *limit)),
            limit: *limit,
            resolved: false,
        })
        .collect();
    if let Some(index) = candidates.iter().position(|c| has_leaf(&c.commitment)) {
        let mut found = candidates.swap_remove(index);
        found.resolved = true;
        return found;
    }
    let index = candidates
        .iter()
        .position(|c| c.limit == default)
        .unwrap_or(0);
    candidates.swap_remove(index)
}

fn prefix(commitment: &str) -> String {
    format!("{}..", commitment.chars().take(18).collect::<String>())
}

/// One contract a slash can be routed to.
struct Target {
    address: Address,
    kind: &'static str,
    /// `DEFAULT_LIMIT()` answered: the tiered `slash(commitment, secret, limit, receiver)` ABI.
    tiered: bool,
    tiers: Vec<u64>,
}

pub(crate) struct OnChain {
    rpc: Arc<Rpc>,
    wallet: Wallet,
    chain_id: u64,
    receiver: Address,
    targets: Vec<Target>,
    default_limit: u64,
}

pub(crate) enum Slasher {
    DryRun,
    OnChain(Arc<OnChain>),
}

/// How the slasher is configured (`SHADE_TREE_SLASH_KEY`, `SHADE_TREE_SLASH_CONTRACT`,
/// `SHADE_TREE_SLASH_RECEIVER`, plus the admitted root contracts).
pub(crate) struct SlashConfig {
    pub(crate) key: Option<String>,
    pub(crate) primary: Option<String>,
    pub(crate) receiver: Option<String>,
    pub(crate) admitted: Vec<(String, Kind)>,
    pub(crate) tiers: Vec<u64>,
    pub(crate) default_limit: u64,
}

impl Slasher {
    pub(crate) async fn setup(config: SlashConfig, rpc: Option<Arc<Rpc>>) -> Result<Self, String> {
        let mut targets: Vec<(String, &'static str)> = Vec::new();
        let mut push = |address: &str, kind: &'static str| {
            let lower = address.to_ascii_lowercase();
            if !targets.iter().any(|(a, _)| *a == lower) {
                targets.push((lower, kind));
            }
        };
        if let Some(primary) = &config.primary {
            push(primary, "primary");
        }
        for (address, kind) in &config.admitted {
            push(address, kind.label());
        }
        let (Some(key), Some(rpc)) = (&config.key, rpc) else {
            tracing::info!(
                "slash: DRY-RUN (set SHADE_TREE_SLASH_KEY and a slash contract to submit on chain)"
            );
            return Ok(Self::DryRun);
        };
        if targets.is_empty() {
            tracing::info!("slash: DRY-RUN (set SHADE_TREE_SLASH_CONTRACT, SHADE_TREE_GROUP_CONTRACT or SHADE_TREE_PAID_ACCESS_CONTRACT to submit on chain)");
            return Ok(Self::DryRun);
        }
        let wallet = Wallet::from_hex(key).map_err(|e| format!("SHADE_TREE_SLASH_KEY: {e}"))?;
        let receiver = match &config.receiver {
            Some(address) => address
                .parse::<Address>()
                .map_err(|e| format!("SHADE_TREE_SLASH_RECEIVER: {e}"))?,
            None => wallet.address,
        };
        let chain_id = rpc
            .call("eth_chainId", json!([]))
            .await
            .ok()
            .and_then(|v| U256::from_quantity(v.as_str()?)?.as_u64())
            .ok_or_else(|| "eth_chainId: no answer from any RPC endpoint".to_string())?;
        let mut probed = Vec::new();
        for (address, kind) in targets {
            let address = address
                .parse::<Address>()
                .map_err(|e| format!("slash contract {address}: {e}"))?;
            let tiered = view(&rpc, address, "DEFAULT_LIMIT()", &[]).await.is_ok();
            let mut tiers = config.tiers.clone();
            if tiered {
                if let Ok(words) = view(&rpc, address, "allowedLimits()", &[]).await {
                    for limit in decode_dynamic_uints(&words) {
                        if let Some(limit) = limit.as_u64() {
                            tiers.push(limit);
                        }
                    }
                }
            } else {
                tiers = vec![config.default_limit];
            }
            tiers.sort_unstable();
            tiers.dedup();
            tracing::info!(
                via = %address,
                receiver = %receiver,
                abi = if tiered { "rln-v4 tiered" } else { "rln-v3 (default tier only)" },
                ?tiers,
                "slash: on-chain"
            );
            probed.push(Target {
                address,
                kind,
                tiered,
                tiers,
            });
        }
        Ok(Self::OnChain(Arc::new(OnChain {
            rpc,
            wallet,
            chain_id,
            receiver,
            targets: probed,
            default_limit: config.default_limit,
        })))
    }

    /// Record the over-spend. On chain, the submission runs in the background; the reply to
    /// the client is not held for the transaction.
    pub(crate) fn submit(&self, secret: Fr, tier: Tier) {
        match self {
            Self::DryRun => tracing::info!(
                commitment = prefix(&tier.commitment),
                limit = tier.limit,
                resolved = tier.resolved,
                "SLASH (dry-run)"
            ),
            Self::OnChain(chain) => {
                let chain = Arc::clone(chain);
                tokio::spawn(async move {
                    if let Err(e) = chain.slash(secret, tier).await {
                        tracing::error!(reason = "slash-submit-failed", "slash failed: {e}");
                    }
                });
            }
        }
    }
}

/// Which live leaf of `secret` a target holds: `limitOf` over the candidates on a tiered set,
/// `isActive` of the default-tier leaf otherwise.
async fn holds(
    rpc: &Rpc,
    target: &Target,
    secret: Fr,
    tier: &Tier,
) -> Result<Option<(String, u64)>, RpcError> {
    let mut candidates: Vec<(String, u64)> = target
        .tiers
        .iter()
        .map(|limit| (fr_to_dec(&rate_commitment(secret, *limit)), *limit))
        .collect();
    if tier.resolved {
        candidates.sort_by_key(|(c, _)| c != &tier.commitment);
    }
    for (commitment, limit) in candidates {
        let leaf = U256::from_dec_str(&commitment).unwrap_or_else(U256::zero);
        if target.tiered {
            let words = view(
                rpc,
                target.address,
                "limitOf(uint256)",
                &[Token::Uint(leaf)],
            )
            .await?;
            if let Some(on_chain) = decode_uints(&words, 1).ok().and_then(|w| w[0].as_u64()) {
                if on_chain != 0 {
                    return Ok(Some((commitment, on_chain)));
                }
            }
        } else {
            let words = view(
                rpc,
                target.address,
                "isActive(uint256)",
                &[Token::Uint(leaf)],
            )
            .await?;
            if decode_uints(&words, 1)
                .ok()
                .is_some_and(|w| !w[0].is_zero())
            {
                return Ok(Some((commitment, limit)));
            }
        }
    }
    Ok(None)
}

async fn view(
    rpc: &Rpc,
    to: Address,
    signature: &str,
    args: &[Token],
) -> Result<Vec<u8>, RpcError> {
    let data = calldata(signature, args);
    let call = json!({"to": to.to_string(), "data": format!("0x{}", hex::encode(&data))});
    let result = rpc.call("eth_call", json!([call, "latest"])).await?;
    let raw = result.as_str().unwrap_or("").trim_start_matches("0x");
    hex::decode(raw).map_err(|_| RpcError::Transport {
        method: "eth_call".into(),
        message: "returned invalid hex data".into(),
    })
}

/// Decode `uint256[]` return data: offset, length, then the words.
fn decode_dynamic_uints(words: &[u8]) -> Vec<U256> {
    let Ok(head) = decode_uints(words, 2) else {
        return Vec::new();
    };
    let count = head[1].as_u64().unwrap_or(0) as usize;
    decode_uints(&words[64..], count).unwrap_or_default()
}

impl OnChain {
    async fn slash(&self, secret: Fr, tier: Tier) -> Result<(), String> {
        let mut chosen = None;
        for target in &self.targets {
            match holds(&self.rpc, target, secret, &tier).await {
                Ok(Some((leaf, limit))) => {
                    tracing::info!(
                        commitment = prefix(&leaf),
                        limit,
                        "slash: routed to {}({})",
                        target.kind,
                        target.address
                    );
                    chosen = Some((target, leaf, limit));
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(via = %target.address, "slash: holds() probe failed; skipping contract: {e}")
                }
            }
        }
        let (target, leaf, limit) = match chosen {
            Some(chosen) => chosen,
            None => {
                let primary = &self.targets[0];
                tracing::warn!(
                    primary = %primary.address,
                    "slash: no configured contract holds a live leaf of the over-spender; submitting the default claim to the primary"
                );
                let limit = if tier.resolved {
                    tier.limit
                } else {
                    self.default_limit
                };
                (primary, tier.commitment.clone(), limit)
            }
        };
        let leaf_word = U256::from_dec_str(&leaf).ok_or("leaf is not a decimal integer")?;
        let secret_word =
            U256::from_dec_str(&fr_to_dec(&secret)).ok_or("secret is not a field element")?;
        let data = if target.tiered {
            calldata(
                "slash(uint256,uint256,uint256,address)",
                &[
                    Token::Uint(leaf_word.clone()),
                    Token::Uint(secret_word),
                    Token::Uint(U256::from(limit)),
                    Token::Address(self.receiver),
                ],
            )
        } else {
            calldata(
                "slash(uint256,uint256,address)",
                &[
                    Token::Uint(leaf_word.clone()),
                    Token::Uint(secret_word),
                    Token::Address(self.receiver),
                ],
            )
        };
        let hash = self.send(target.address, data).await?;
        tracing::info!(
            commitment = prefix(&leaf),
            via = %target.address,
            limit,
            "SLASH tx {hash} (waiting)"
        );
        let receipt = self.wait(&hash).await?;
        let block = receipt["blockNumber"]
            .as_str()
            .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let payout_topic = format!(
            "0x{}",
            hex::encode(eth::keccak256(SLASH_PAYOUT_TOPIC.as_bytes()))
        );
        let payout = receipt["logs"]
            .as_array()
            .into_iter()
            .flatten()
            .find_map(|entry| {
                let same_contract = entry["address"]
                    .as_str()
                    .is_some_and(|a| a.eq_ignore_ascii_case(&target.address.to_string()));
                let topics = entry["topics"].as_array()?;
                if !same_contract || topics.first()?.as_str()? != payout_topic {
                    return None;
                }
                let commitment = U256::from_quantity(topics.get(1)?.as_str()?)?;
                if commitment != leaf_word {
                    return None;
                }
                let data = hex::decode(entry["data"].as_str()?.trim_start_matches("0x")).ok()?;
                let words = decode_uints(&data, 2).ok()?;
                Some((words[0].to_string(), words[1].to_string()))
            });
        match payout {
            Some((burned, reward)) => tracing::info!(
                commitment = prefix(&leaf),
                via = %target.address,
                limit,
                burned_wei = burned,
                reward_wei = reward,
                "SLASH mined block {block}"
            ),
            None => {
                tracing::info!(commitment = prefix(&leaf), via = %target.address, limit, "SLASH mined block {block}")
            }
        }
        Ok(())
    }

    /// Estimate, price, sign, broadcast. Errors never carry the calldata, which holds the secret.
    async fn send(&self, to: Address, data: Vec<u8>) -> Result<String, String> {
        let from = self.wallet.address.to_string();
        let call = json!({
            "from": from,
            "to": to.to_string(),
            "data": format!("0x{}", hex::encode(&data)),
        });
        let quantity = |value: Result<Value, RpcError>, what: &str| -> Result<U256, String> {
            let value = value.map_err(|e| format!("{what}: {}", bounded(&e)))?;
            value
                .as_str()
                .and_then(U256::from_quantity)
                .ok_or_else(|| format!("{what}: not a quantity"))
        };
        let estimated = quantity(
            self.rpc.call("eth_estimateGas", json!([call])).await,
            "eth_estimateGas",
        )?;
        let gas = estimated
            .checked_mul(&U256::from(120))
            .and_then(|v| U256::from_big_endian(&(v.as_biguint() / 100_u32).to_bytes_be()))
            .ok_or("eth_estimateGas returned an unsupported value")?;
        let nonce = quantity(
            self.rpc
                .call("eth_getTransactionCount", json!([from, "pending"]))
                .await,
            "eth_getTransactionCount",
        )?;
        let gas_price = quantity(
            self.rpc.call("eth_gasPrice", json!([])).await,
            "eth_gasPrice",
        )?;
        let block = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await
            .map_err(|e| format!("eth_getBlockByNumber: {}", bounded(&e)))?;
        let base_fee = block["baseFeePerGas"]
            .as_str()
            .and_then(U256::from_quantity)
            .ok_or("latest block has no baseFeePerGas; this signer requires EIP-1559")?;
        let priority = match self.rpc.call("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(value) => value.as_str().and_then(U256::from_quantity),
            Err(_) => None,
        }
        .or_else(|| gas_price.checked_sub(&base_fee).filter(|v| !v.is_zero()))
        .unwrap_or_else(|| gas_price.clone().min(U256::from(1_000_000_000)));
        let max_fee = base_fee
            .checked_mul(&U256::from(2))
            .and_then(|v| v.checked_add(&priority))
            .ok_or("fee terms overflow")?
            .max(gas_price);
        let raw = self.wallet.sign(&Eip1559 {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas: max_fee,
            gas,
            to,
            value: U256::zero(),
            data,
        })?;
        let hash = format!("0x{}", hex::encode(eth::keccak256(&raw)));
        self.rpc
            .call(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(&raw))]),
            )
            .await
            .map_err(|e| format!("eth_sendRawTransaction: {}", bounded(&e)))?;
        Ok(hash)
    }

    async fn wait(&self, hash: &str) -> Result<Value, String> {
        let started = Instant::now();
        loop {
            let receipt = self
                .rpc
                .call("eth_getTransactionReceipt", json!([hash]))
                .await
                .map_err(|e| format!("eth_getTransactionReceipt: {}", bounded(&e)))?;
            if !receipt.is_null() {
                if receipt["status"].as_str() != Some("0x1") {
                    return Err(format!("slash transaction {hash} reverted"));
                }
                return Ok(receipt);
            }
            if started.elapsed() >= RECEIPT_TIMEOUT {
                return Err(format!(
                    "slash transaction {hash} not mined within {}s; the outcome is unknown",
                    RECEIPT_TIMEOUT.as_secs()
                ));
            }
            tokio::time::sleep(RECEIPT_POLL).await;
        }
    }
}

/// An RPC error with any echoed calldata removed: provider messages may quote the transaction,
/// which carries the reconstructed secret.
fn bounded(error: &RpcError) -> String {
    let text = error.to_string();
    if text.contains("0x") && text.len() > 120 {
        return format!(
            "{}... [provider message truncated]",
            &text[..text.char_indices().nth(80).map_or(text.len(), |(i, _)| i)]
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_rln::tree::parse_fr;

    #[test]
    fn two_shares_give_back_the_secret() {
        let secret = parse_fr("111").unwrap();
        let slope = parse_fr("12345").unwrap();
        let at = |x: u64| {
            let x = Fr::from(x);
            Share {
                x: fr_to_dec(&x),
                y: fr_to_dec(&(secret + slope * x)),
            }
        };
        assert_eq!(reconstruct_secret(&at(3), &at(7)).unwrap(), secret);
        assert!(reconstruct_secret(&at(3), &at(3)).is_err());
    }

    #[test]
    fn the_tier_in_the_set_wins_else_the_default() {
        let secret = parse_fr("111").unwrap();
        let leaf32 = fr_to_dec(&rate_commitment(secret, 32));
        let tier = resolve_tier(secret, &[8, 32], 8, |leaf| leaf == leaf32);
        assert!(tier.resolved);
        assert_eq!(tier.limit, 32);
        let tier = resolve_tier(secret, &[8, 32], 8, |_| false);
        assert!(!tier.resolved);
        assert_eq!(tier.limit, 8);
        assert_eq!(tier.commitment, fr_to_dec(&rate_commitment(secret, 8)));
    }

    #[test]
    fn dynamic_uint_arrays_decode() {
        let mut words = Vec::new();
        words.extend_from_slice(&U256::from(32).to_big_endian());
        words.extend_from_slice(&U256::from(2).to_big_endian());
        words.extend_from_slice(&U256::from(8).to_big_endian());
        words.extend_from_slice(&U256::from(32).to_big_endian());
        let limits: Vec<u64> = decode_dynamic_uints(&words)
            .iter()
            .filter_map(U256::as_u64)
            .collect();
        assert_eq!(limits, [8, 32]);
        assert!(decode_dynamic_uints(&[]).is_empty());
    }
}
