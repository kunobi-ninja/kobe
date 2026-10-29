{
  lib,
  rustPlatform,
  fetchurl,
  apple-sdk_15,
  cacert,
  stdenv,
}:
let
  cargoToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  # crates.io throttles the default nix user-agent; mirror kache's override.
  fetchurlWithCratesUserAgent = args:
    fetchurl (args
      // {
        curlOptsList = (args.curlOptsList or []) ++ ["-A" "kobe-nix"];
      });

  buildRustPackage = rustPlatform.buildRustPackage.override {
    importCargoLock = rustPlatform.importCargoLock.override {
      fetchurl = fetchurlWithCratesUserAgent;
    };
  };
in
buildRustPackage {
  pname = "kobe";
  # Version lives in [workspace.package] (inherited by both members).
  version = cargoToml.workspace.package.version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../build.rs
      ../crates
      ../src
    ];
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    # importCargoLock fetches the whole workspace, including this operator-only
    # dependency. Hash the source at the revision pinned in Cargo.lock.
    outputHashes = {
      "kunobi-reload-0.1.0" = "sha256-HMawWgFcIM2Tgi9JRkC1/c6QiD+3CW5uUcSHxe/RoRQ=";
    };
  };

  # Build/test ONLY the thin CLI crate — avoids the operator's heavy/unix deps
  # (kube, axum, sqlx, aws-sdk, otel) entirely, so no protoc/extra inputs needed.
  cargoBuildFlags = ["-p" "kobectl"];
  cargoTestFlags = ["-p" "kobectl"];

  buildInputs = lib.optionals stdenv.hostPlatform.isDarwin [
    apple-sdk_15
  ];

  # Don't let a kobe-wrapping rustc wrapper recurse during the build.
  env.RUSTC_WRAPPER = "";

  # reqwest (rustls) loads the system trust store when a client is constructed,
  # which the sandbox lacks — point it at the cacert bundle.
  env.SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";

  meta = {
    description = "CLI for the kobe cluster-pool operator: lease and manage instant CI/dev Kubernetes clusters";
    homepage = "https://github.com/kunobi-ninja/kobe";
    license = lib.licenses.asl20;
    mainProgram = "kobe";
  };
}
