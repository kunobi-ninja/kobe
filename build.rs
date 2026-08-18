fn main() {
    println!("cargo:rerun-if-env-changed=BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=BUILD_COMMIT");

    let version = std::env::var("BUILD_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "dev".into()));

    println!("cargo:rustc-env=BUILD_VERSION={version}");

    // The commit is what makes a build identifiable when the version can't:
    // every image built from main carries the same `BUILD_VERSION`, so "which
    // main build is this?" has no answer without it. CI already computes it for
    // the `sha-<7>` image tag; this carries the same value into the binary so
    // the running process can state its own identity.
    //
    // `unknown` for local builds, matching the Dockerfile ARG default rather
    // than inventing a second sentinel. Deliberately NOT shelling out to git:
    // the value must describe the source that was compiled, and the container
    // build has no git tree.
    let commit = std::env::var("BUILD_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=BUILD_COMMIT={commit}");
}
