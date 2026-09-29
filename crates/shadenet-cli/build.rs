//! Stamp the source commit into the binary so `shadenet --version` names what it was built from
//! (launch gate: the commit in `shadenet --version`). Order: SHADENET_BUILD_COMMIT (packagers),
//! GITHUB_SHA (CI and release builds), `git rev-parse HEAD` (a checkout), else "unknown"
//! (a crates.io source build has no git).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SHADENET_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let commit = std::env::var("SHADENET_BUILD_COMMIT")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .or_else(git_head)
        .filter(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_hexdigit()))
        .map(|c| c.chars().take(12).collect::<String>())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=SHADENET_COMMIT={commit}");
}

fn git_head() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // Rebuild when HEAD moves (best effort; absent outside a checkout).
    if let Ok(dir) = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
    {
        let dir = String::from_utf8_lossy(&dir.stdout).trim().to_string();
        if !dir.is_empty() {
            println!("cargo:rerun-if-changed={dir}/HEAD");
            println!("cargo:rerun-if-changed={dir}/refs");
        }
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
