fn main() {
    println!("cargo:rerun-if-env-changed=BUILD_VERSION");

    let version = std::env::var("BUILD_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "dev".into()));

    println!("cargo:rustc-env=BUILD_VERSION={version}");
}
