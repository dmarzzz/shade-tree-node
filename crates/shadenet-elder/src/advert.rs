//! The registrar advert in `GET /health` (`payAdvertFromEnv`): where the operator's 402
//! registrar is and what it sells. Either a JSON object in `SHADE_TREE_REGISTRAR_ADVERTISE`
//! or `1` to compose it from the `SHADE_TREE_PAY_*` variables; anything incomplete yields no
//! advert at all, never a half one.

use serde_json::{json, Map, Value};

const DEFAULT_REGISTRAR_PORT: u64 = 8878;
const DEFAULT_CHAIN_ID: u64 = 11_155_111;
const PAY_PROTOCOLS: [&str; 2] = ["x402", "mpp"];

fn var(name: &str) -> Option<String> {
    std::env::var(format!("SHADENET_{name}"))
        .ok()
        .or_else(|| std::env::var(format!("SHADE_TREE_{name}")).ok())
}

/// `SHADE_TREE_PAY_PROTOCOLS` in the fixed protocol order; unset is both.
pub(crate) fn parse_protocols(spec: Option<&str>) -> Result<Vec<String>, String> {
    let raw = spec.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(PAY_PROTOCOLS.iter().map(|p| (*p).to_string()).collect());
    }
    let parts: Vec<String> = raw
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    for part in &parts {
        if !PAY_PROTOCOLS.contains(&part.as_str()) {
            return Err(format!(
                "SHADE_TREE_PAY_PROTOCOLS: unknown payment protocol \"{}\" (expected a comma list drawn from: x402, mpp)",
                part.chars().take(16).collect::<String>()
            ));
        }
    }
    if parts.is_empty() {
        return Err("SHADE_TREE_PAY_PROTOCOLS: no payment protocol selected (expected a comma list drawn from: x402, mpp)".into());
    }
    Ok(PAY_PROTOCOLS
        .iter()
        .filter(|p| parts.iter().any(|q| q == *p))
        .map(|p| (*p).to_string())
        .collect())
}

/// The advert from the environment, `None` when unset, `0` or unusable.
pub(crate) fn from_env() -> Result<Option<Value>, String> {
    compose(
        var("REGISTRAR_ADVERTISE").as_deref(),
        var("REGISTRAR_PORT").as_deref(),
        var("PAY_ASSET").as_deref(),
        var("PAY_PRICES").as_deref(),
        var("PAY_CHAIN_ID").as_deref(),
        var("PAY_PROTOCOLS").as_deref(),
    )
}

fn compose(
    advertise: Option<&str>,
    port: Option<&str>,
    asset: Option<&str>,
    prices: Option<&str>,
    chain_id: Option<&str>,
    protocols: Option<&str>,
) -> Result<Option<Value>, String> {
    let raw = advertise.map(str::trim).unwrap_or("");
    if raw.is_empty() || raw == "0" {
        return Ok(None);
    }
    if raw.starts_with('{') {
        return Ok(serde_json::from_str::<Value>(raw)
            .ok()
            .filter(Value::is_object));
    }
    let asset = asset.unwrap_or("");
    let valid_asset = asset.len() == 42
        && asset.starts_with("0x")
        && asset[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if !valid_asset {
        return Ok(None);
    }
    let mut tiers = Map::new();
    for part in prices
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let Some((limit, amount)) = part.split_once('=') else {
            return Ok(None);
        };
        let limit_ok = !limit.is_empty()
            && limit.len() <= 5
            && !limit.starts_with('0')
            && limit.bytes().all(|b| b.is_ascii_digit());
        let amount_ok = !amount.is_empty()
            && !amount.starts_with('0')
            && amount.bytes().all(|b| b.is_ascii_digit());
        if !limit_ok || !amount_ok {
            return Ok(None);
        }
        tiers.insert(limit.to_string(), Value::String(amount.to_string()));
    }
    if tiers.is_empty() {
        return Ok(None);
    }
    let chain = chain_id
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map_or(Ok(DEFAULT_CHAIN_ID), str::parse::<u64>)
        .map_err(|_| "SHADE_TREE_PAY_CHAIN_ID: expected a chain id".to_string())?;
    let Ok(protocols) = parse_protocols(protocols) else {
        return Ok(None);
    };
    let port = port
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REGISTRAR_PORT);
    Ok(Some(json!({
        "port": port,
        "protocols": protocols,
        "asset": asset,
        "chain": format!("eip155:{chain}"),
        "tiers": tiers,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advert_is_whole_or_absent() {
        assert_eq!(compose(None, None, None, None, None, None).unwrap(), None);
        assert_eq!(
            compose(Some("0"), None, None, None, None, None).unwrap(),
            None
        );
        let asset = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
        let adv = compose(
            Some("1"),
            None,
            Some(asset),
            Some("8=100000,32=400000"),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(adv["port"], 8878);
        assert_eq!(adv["protocols"], json!(["x402", "mpp"]));
        assert_eq!(adv["chain"], "eip155:11155111");
        assert_eq!(adv["tiers"]["32"], "400000");
        assert_eq!(adv["asset"], asset);
        assert_eq!(
            compose(Some("1"), None, Some("nope"), Some("8=1"), None, None).unwrap(),
            None
        );
        assert_eq!(
            compose(Some("1"), None, Some(asset), Some("8=x"), None, None).unwrap(),
            None
        );
        assert_eq!(
            compose(Some("{bad"), None, None, None, None, None).unwrap(),
            None
        );
        assert_eq!(
            compose(
                Some("{\"port\":9999,\"protocols\":[\"x402\"]}"),
                None,
                None,
                None,
                None,
                None
            )
            .unwrap()
            .unwrap()["port"],
            9999
        );
        assert_eq!(
            compose(Some("1"), None, Some(asset), Some("8=1"), None, Some("mpp"))
                .unwrap()
                .unwrap()["protocols"],
            json!(["mpp"])
        );
        assert_eq!(
            parse_protocols(Some("mpp, x402")).unwrap(),
            vec!["x402", "mpp"]
        );
        assert!(parse_protocols(Some("venmo")).is_err());
    }
}
