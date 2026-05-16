use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|s| s.len() == 7 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| "0000000".to_owned());

    println!("cargo:rustc-env=ARCANA_GIT_SHA={sha}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-env-changed=ARCANA_GIT_SHA");
}
