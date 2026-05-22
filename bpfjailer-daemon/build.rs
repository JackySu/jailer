use std::process::Command;

fn main() {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=ICB_SANDBOX_GIT_HASH={}", git_hash.trim());
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
