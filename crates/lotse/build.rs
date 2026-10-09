//! Records the build target and compiler for `info.build`, and passes a
//! `LOTSE_GIT_SHA` set by the release build through.
#![expect(
    clippy::disallowed_methods,
    reason = "a build script reads cargo's environment and runs the compiler it names; its stdout is how it talks to cargo"
)]

/// Emits the `cargo:rustc-env` lines the binary reads with `env!`.
fn main() {
    println!("cargo:rerun-if-env-changed=LOTSE_GIT_SHA");
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=LOTSE_TARGET={target}");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = std::process::Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .unwrap_or_default();
    println!("cargo:rustc-env=LOTSE_RUSTC={version}");
    if let Ok(sha) = std::env::var("LOTSE_GIT_SHA")
        && !sha.is_empty()
    {
        println!("cargo:rustc-env=LOTSE_GIT_SHA={sha}");
    }
}
