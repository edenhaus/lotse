//! Records the build target and compiler for `info.build`.
#![expect(
    clippy::disallowed_methods,
    reason = "a build script reads cargo's environment and runs the compiler it names; its stdout is how it talks to cargo"
)]

/// Emits the `cargo:rustc-env` lines the binary reads with `env!`.
fn main() {
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
}
