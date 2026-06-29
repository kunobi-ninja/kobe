// `BUILD_VERSION` stamping is package-local (cargo:rustc-env applies only to the
// crate being built), so the kobectl member needs its own copy — the
// operator's build.rs does not reach this binary. Without it, `kobe --version`
// would regress to CARGO_PKG_VERSION. Keep in sync with the root build.rs.
fn main() {
    println!("cargo:rerun-if-env-changed=BUILD_VERSION");

    let version = std::env::var("BUILD_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "dev".into()));

    println!("cargo:rustc-env=BUILD_VERSION={version}");
}
