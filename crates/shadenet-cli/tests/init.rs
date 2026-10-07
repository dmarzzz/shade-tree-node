//! `shadenet init` must print the identity commitment `registerIdentity` takes, the leaf with
//! its tier, and a stake link that carries all three — never "stake this leaf" (task 2/66). The
//! link fragment is never sent to a server; the Get access page verifies Poseidon2(c, tier) ==
//! leaf locally, so this test proves the `c`/`leaf` the CLI prints satisfy exactly that.
#![cfg(feature = "live")]

use std::process::Command;

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "shadenet-init-test-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn init_json_carries_commitment_leaf_tier_and_a_verifiable_stake_link() {
    let dir = unique_dir("json");
    let out = Command::new(env!("CARGO_BIN_EXE_shadenet"))
        .args(["init", "--offline", "--json", "--dir"])
        .arg(&dir)
        .output()
        .expect("run shadenet init --json");
    assert!(
        out.status.success(),
        "init --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("init --json emits JSON");

    let idc = value["identityCommitment"]
        .as_str()
        .expect("identityCommitment is present as a decimal string");
    let leaf = value["leaf"].as_str().expect("leaf is present");
    let tier = value["tier"].as_u64().expect("tier is present");
    let link = value["stakeLink"].as_str().expect("stakeLink is present");

    // Decimal, non-empty.
    assert!(idc.bytes().all(|b| b.is_ascii_digit()) && !idc.is_empty());
    assert!(leaf.bytes().all(|b| b.is_ascii_digit()) && !leaf.is_empty());

    // Well-formed link on the stable domain, carrying c, limit and leaf.
    assert_eq!(
        link,
        format!("https://shadenet.xyz/stake/#c={idc}&limit={tier}&leaf={leaf}")
    );

    // The contract derives the leaf from the commitment: Poseidon2(c, tier) == leaf. This is the
    // check the Get access page runs on the fragment before it lets anyone stake.
    let derived =
        shadenet_rln::identity::rate_commitment_from_identity_commitment(idc, tier).unwrap();
    assert_eq!(
        derived, leaf,
        "the printed commitment and leaf must satisfy Poseidon2(c, tier) == leaf"
    );
    // And the commitment is NOT the leaf (the whole point: they are different values).
    assert_ne!(idc, leaf, "the commitment must not equal the leaf");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn init_human_output_names_the_commitment_and_link_not_the_leaf_to_stake() {
    let dir = unique_dir("human");
    let out = Command::new(env!("CARGO_BIN_EXE_shadenet"))
        .args(["init", "--offline", "--dir"])
        .arg(&dir)
        .output()
        .expect("run shadenet init");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    // Prints the identity commitment, and the budget in sessions or tunnels, never "tier N"
    // (the public record has one tier).
    assert!(
        text.contains("identity commitment "),
        "init prints the identity commitment:\n{text}"
    );
    assert!(
        !text.contains("tier"),
        "init human output names the budget, not a tier:\n{text}"
    );
    // Prints a stake link on the stable domain.
    assert!(
        text.contains("https://shadenet.xyz/stake/#c=")
            && text.contains("&limit=")
            && text.contains("&leaf="),
        "init prints a stake link:\n{text}"
    );
    // The leaf is shortened, so it cannot be pasted whole where the commitment belongs.
    let leaf_line = text
        .lines()
        .find(|l| l.trim_start().starts_with("leaf "))
        .expect("a leaf line");
    assert!(
        leaf_line.contains("..")
            && leaf_line.contains("not for staking")
            && !leaf_line
                .split_whitespace()
                .any(|w| w.len() > 20 && w.chars().all(|c| c.is_ascii_digit())),
        "init must not print the full leaf next to the commitment:\n{text}"
    );
    // The burn-a-bond phrasing is gone (task 66).
    assert!(
        !text.contains("stake this leaf"),
        "init must no longer say 'stake this leaf':\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
