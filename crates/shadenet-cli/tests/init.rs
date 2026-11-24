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

/// `shadenet` with every `SHADENET_*` variable cleared and HOME/XDG pointed into `home`, so a
/// test reads only the config file it names.
fn isolated(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_shadenet"));
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        if key.starts_with("SHADENET_") || key.starts_with("SHADE_TREE_") {
            command.env_remove(key);
        }
    }
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg-config"))
        .env("XDG_STATE_HOME", home.join("xdg-state"))
        .env("XDG_CACHE_HOME", home.join("xdg-cache"));
    command
}

/// `init --dir <relative>` must write a config that loads (#436). The loader resolves relative
/// paths against the config file's directory, so recording `.shadenet/identity.json` in
/// `.shadenet/config.toml` pointed every later command at `.shadenet/.shadenet/identity.json`.
#[test]
fn init_with_a_relative_dir_writes_a_config_that_loads_from_any_directory() {
    let root = unique_dir("relative");
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();

    let out = isolated(&root)
        .current_dir(&root)
        .args(["init", "--offline", "--dir", ".shadenet"])
        .output()
        .expect("run shadenet init --dir .shadenet");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let config = std::fs::read_to_string(root.join(".shadenet/config.toml")).unwrap();
    assert!(
        config.contains("identity = \"identity.json\"")
            && config.contains("proxy_token_file = \"proxy-token\""),
        "config.toml records paths relative to its own directory:\n{config}"
    );

    // The same config, named relative to the directory init ran in and by absolute path from
    // another directory: doctor finds the identity and the proxy token both times.
    let absolute = root.join(".shadenet/config.toml");
    for (cwd, config_arg) in [
        (&root, std::path::Path::new(".shadenet/config.toml")),
        (&elsewhere, absolute.as_path()),
    ] {
        let out = isolated(&root)
            .current_dir(cwd)
            .args(["doctor", "--offline", "--json", "--config"])
            .arg(config_arg)
            .output()
            .expect("run shadenet doctor --offline");
        let text = String::from_utf8_lossy(&out.stdout);
        let report: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("doctor --json emits JSON ({e}):\n{text}"));
        let level_of = |name: &str| {
            report["checks"]
                .as_array()
                .expect("a checks array")
                .iter()
                .find(|check| check["name"] == name)
                .unwrap_or_else(|| panic!("a {name:?} check:\n{text}"))["level"]
                .as_str()
                .map(str::to_string)
        };
        assert_eq!(level_of("identity").as_deref(), Some("ok"), "{text}");
        assert_eq!(level_of("proxy token").as_deref(), Some("ok"), "{text}");
        assert!(!text.contains(".shadenet/.shadenet"), "{text}");
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// A `--network` deployment record given as a relative path is recorded absolute, for the same
/// reason: the loader would otherwise look for it under the config directory.
#[test]
fn init_records_a_relative_network_record_path_as_absolute() {
    let root = unique_dir("network");
    std::fs::create_dir_all(&root).unwrap();
    let record = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../network/sepolia-staging/deployment.json"
    );
    // The staging record: one named `sepolia` is recorded by name, not by path.
    std::fs::copy(record, root.join("record.json")).expect("copy the staging record");

    let out = isolated(&root)
        .current_dir(&root)
        .args([
            "init",
            "--offline",
            "--network",
            "./record.json",
            "--dir",
            "cfg",
        ])
        .output()
        .expect("run shadenet init --network ./record.json");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let config = std::fs::read_to_string(root.join("cfg/config.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&config).expect("config.toml is TOML");
    let network = parsed["network"].as_str().expect("a network value");
    assert!(
        std::path::Path::new(network).is_absolute() && network.ends_with("record.json"),
        "the network record path is absolute:\n{config}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
