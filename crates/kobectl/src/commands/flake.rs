//! `kobe flake` — write a sandbox flake, and install it into a Ready lease.
//!
//! The sandbox image already has Nix. This command does not change that image.
//! `kobe flake init` writes a `flake.nix` on the machine running the CLI, which
//! does not need Nix installed. `kobe lease --flake` waits until the sandbox is
//! Ready, then copies `flake.nix` and `flake.lock` (when it exists) to
//! `/home/agent/.kobe/flake` and runs `nix profile install`. The file bytes
//! travel on the execution's stdin. The exec argv is a URL the target
//! apiserver audit-logs, so the flake contents stay out of it.

use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::config::ResolvedConfig;
use super::sandbox::{self, exit_code_for};
use super::{OutputFormat, print_json};

/// Where a lease keeps the flake it was given.
pub(crate) const REMOTE_DIR: &str = "/home/agent/.kobe/flake";

/// `flake.nix` and `flake.lock` together. The CLI holds both in memory and
/// sends them as one execution stdin.
const MAX_FLAKE_BYTES: usize = 1024 * 1024;

/// Fixed header the install script slices with `cut` before reading file bytes.
///
/// `read` is not usable here. On a pipe, the shell buffers ahead of the line
/// it returns and would swallow the start of `flake.nix`. Lengths are
/// space-padded, not zero-padded: a leading zero would make `dd` read the
/// count as octal.
const HEADER_LEN: usize = 87;

const FLAKE_NIX: &str = r#"{
  description = "Tools for one Kobe sandbox lease";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      packages.${system}.default = pkgs.buildEnv {
        name = "lease-tools";
        paths = [
          pkgs.ripgrep
        ];
      };
    };
}
"#;

/// Remote install. Header layout, 1-based, is what `payload` writes:
/// `1-10` nix length, `12-21` lock length, `23-86` sha256, `87` newline.
const INSTALL_SCRIPT: &str = r#"set -eu
dest=/home/agent/.kobe/flake
mkdir -p "$dest"
header=$(dd bs=87 count=1 status=none)
nix_len=$(printf %s "$header" | cut -c1-10 | tr -d ' ')
lock_len=$(printf %s "$header" | cut -c12-21 | tr -d ' ')
hash=$(printf %s "$header" | cut -c23-86 | tr -d '[:space:]')
dd bs="$nix_len" count=1 of="$dest/flake.nix" status=none
if [ "$lock_len" -eq 0 ]; then
  rm -f "$dest/flake.lock"
else
  dd bs="$lock_len" count=1 of="$dest/flake.lock" status=none
fi
rm -f "$dest/.installed-hash"
nix profile install "path:$dest"
printf '%s\n' "$hash" > "$dest/.installed-hash"
"#;

/// `flake.nix` plus the optional lock, and the hash of those bytes.
#[derive(Clone, Debug)]
pub(crate) struct FlakeFiles {
    nix: Vec<u8>,
    lock: Option<Vec<u8>>,
    hash: String,
}

impl FlakeFiles {
    /// Bytes the install script reads on stdin.
    pub(crate) fn payload(&self) -> Vec<u8> {
        let lock = self.lock.as_deref().unwrap_or(b"");
        let mut out = Vec::with_capacity(HEADER_LEN + self.nix.len() + lock.len());
        writeln!(
            &mut out,
            "{:10} {:10} {}",
            self.nix.len(),
            lock.len(),
            self.hash
        )
        .expect("writing to a vec");
        debug_assert_eq!(out.len(), HEADER_LEN);
        out.extend_from_slice(&self.nix);
        out.extend_from_slice(lock);
        out
    }
}

/// Write `flake.nix` in `dir`. Refuses when that file is already there.
pub(crate) fn init(dir: &Path) -> Result<PathBuf> {
    let path = dir.join("flake.nix");
    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    std::fs::write(&path, FLAKE_NIX)
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(path)
}

/// Read a directory that contains `flake.nix`. `flake.lock` is included when
/// it is present.
pub(crate) fn load(dir: &Path) -> Result<FlakeFiles> {
    if !dir.is_dir() {
        anyhow::bail!("{} is not a directory", dir.display());
    }
    let nix_path = dir.join("flake.nix");
    let nix = std::fs::read(&nix_path)
        .with_context(|| format!("could not read {}", nix_path.display()))?;
    if nix.is_empty() {
        anyhow::bail!("{} is empty", nix_path.display());
    }
    let lock_path = dir.join("flake.lock");
    let lock = if lock_path.is_file() {
        let bytes = std::fs::read(&lock_path)
            .with_context(|| format!("could not read {}", lock_path.display()))?;
        Some(bytes)
    } else {
        None
    };
    let total = nix.len() + lock.as_ref().map_or(0, Vec::len);
    if total > MAX_FLAKE_BYTES {
        anyhow::bail!("flake.nix and flake.lock are {total} bytes; the limit is {MAX_FLAKE_BYTES}");
    }
    let hash = hash_parts(&nix, lock.as_deref());
    Ok(FlakeFiles { nix, lock, hash })
}

/// sha256 of `flake.nix`, a 0 byte, then `flake.lock` or nothing.
fn hash_parts(nix: &[u8], lock: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(nix);
    hasher.update([0]);
    if let Some(lock) = lock {
        hasher.update(lock);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// True when the marker file's contents are this flake's hash.
fn marker_is_current(marker: &str, hash: &str) -> bool {
    marker.trim() == hash
}

fn install_argv() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        INSTALL_SCRIPT.to_string(),
    ]
}

fn marker_argv() -> Vec<String> {
    vec![
        "/bin/cat".to_string(),
        format!("{REMOTE_DIR}/.installed-hash"),
    ]
}

fn list_argv() -> Vec<String> {
    vec!["nix".to_string(), "profile".to_string(), "list".to_string()]
}

/// Install `files` into an already Ready sandbox.
///
/// With `skip_if_unchanged`, a marker written by the last successful install
/// skips `nix profile install` when the files are the same. A missing marker
/// installs. `hint` is the retry line added when the install fails; the lease
/// is already up by then.
pub(crate) async fn install_flake(
    config: &ResolvedConfig,
    lease_id: &str,
    files: &FlakeFiles,
    skip_if_unchanged: bool,
    output: OutputFormat,
    hint: &str,
) -> Result<()> {
    if skip_if_unchanged && marker_matches(config, lease_id, &files.hash, output).await? {
        if output == OutputFormat::Text {
            eprintln!("Flake already installed on {lease_id}");
        }
        return Ok(());
    }
    if output == OutputFormat::Text {
        eprintln!("Installing flake on {lease_id}...");
    }
    let stdin = base64::engine::general_purpose::STANDARD.encode(files.payload());
    let argv = install_argv();
    let result = sandbox::exec_once(
        config,
        lease_id,
        &argv,
        None,
        None,
        Some(&stdin),
        &sandbox::new_idempotency_key(),
        false,
        output,
    )
    .await
    .with_context(|| hint.to_string())?;
    if output == OutputFormat::Text
        && let Some(stdout) = result.stdout.as_deref()
    {
        print!("{stdout}");
        let _ = std::io::stdout().flush();
    }
    if let Some(stderr) = result.stderr.as_deref()
        && !stderr.is_empty()
        && result.exit_code == Some(0)
    {
        eprint!("{stderr}");
        let _ = std::io::stderr().flush();
    }
    if result.truncated {
        eprintln!("kobe: flake install output was truncated at the server's limit");
    }
    let code = exit_code_for(&result);
    if code != 0 {
        let stderr = result.stderr.as_deref().unwrap_or("").trim();
        let detail = if stderr.is_empty() {
            format!("flake install on {lease_id} exited {code}")
        } else {
            format!("flake install on {lease_id} exited {code}: {stderr}")
        };
        anyhow::bail!("{detail}\n{hint}");
    }
    Ok(())
}

async fn marker_matches(
    config: &ResolvedConfig,
    lease_id: &str,
    hash: &str,
    output: OutputFormat,
) -> Result<bool> {
    let argv = marker_argv();
    let result = sandbox::exec_once(
        config,
        lease_id,
        &argv,
        None,
        None,
        None,
        &sandbox::new_idempotency_key(),
        false,
        output,
    )
    .await?;
    if exit_code_for(&result) != 0 {
        return Ok(false);
    }
    Ok(marker_is_current(
        result.stdout.as_deref().unwrap_or(""),
        hash,
    ))
}

/// Run `nix profile list` in `lease_id` and return the remote exit code.
pub(crate) async fn list(
    lease_id: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<i32> {
    let config = super::config::CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
    let argv = list_argv();
    let result = sandbox::exec_once(
        &config,
        lease_id,
        &argv,
        None,
        None,
        None,
        &sandbox::new_idempotency_key(),
        false,
        output,
    )
    .await?;
    let code = exit_code_for(&result);
    match output {
        OutputFormat::Text => {
            if let Some(stdout) = result.stdout.as_deref() {
                print!("{stdout}");
                let _ = std::io::stdout().flush();
            }
            if let Some(stderr) = result.stderr.as_deref() {
                eprint!("{stderr}");
                let _ = std::io::stderr().flush();
            }
        }
        OutputFormat::Json => {
            print_json(&ListOutput {
                lease: lease_id,
                exit_code: result.exit_code,
                stdout: result.stdout.as_deref().unwrap_or(""),
                stderr: result.stderr.as_deref().unwrap_or(""),
            })?;
        }
    }
    Ok(code)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ListOutput<'a> {
    lease: &'a str,
    exit_code: Option<i32>,
    stdout: &'a str,
    stderr: &'a str,
}

/// Sentence added when the install fails after the lease is already up.
pub(crate) fn retry_hint(pool: &str, name: Option<&str>, flake: &Path) -> String {
    match name {
        Some(name) => format!(
            "the lease is up; finish the install with kobe lease {pool} --name {name} --ensure --flake {}",
            flake.display()
        ),
        None => "the lease is up and has no --name, so running kobe lease --flake again would create another sandbox".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_the_template_and_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = init(dir.path()).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("github:NixOS/nixpkgs/nixos-26.05"));
        assert!(written.contains("x86_64-linux"));
        assert!(written.contains("pkgs.ripgrep"));
        let error = init(dir.path()).unwrap_err().to_string();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written);
    }

    #[test]
    fn payload_header_matches_the_install_script_slices() {
        let files = load_from(b"{ marker = 1; }\n", Some(b"{\"nodes\":{}}\n"));
        let payload = files.payload();
        let header = &payload[..HEADER_LEN];
        assert_eq!(header.len(), 87);
        assert_eq!(&header[86..], b"\n");
        let nix_len: usize = std::str::from_utf8(&header[0..10])
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let lock_len: usize = std::str::from_utf8(&header[11..21])
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let hash = std::str::from_utf8(&header[22..86]).unwrap();
        assert_eq!(nix_len, files.nix.len());
        assert_eq!(lock_len, files.lock.as_ref().unwrap().len());
        assert_eq!(hash, files.hash);
        assert_eq!(hash.len(), 64);
        let body = &payload[HEADER_LEN..];
        assert_eq!(&body[..nix_len], files.nix.as_slice());
        assert_eq!(&body[nix_len..], files.lock.as_ref().unwrap().as_slice());
    }

    #[test]
    fn payload_omits_a_missing_lock_and_keeps_the_header() {
        let files = load_from(b"{ }\n", None);
        let payload = files.payload();
        let lock_len: usize = std::str::from_utf8(&payload[11..21])
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(lock_len, 0);
        assert_eq!(&payload[HEADER_LEN..], files.nix.as_slice());
    }

    #[test]
    fn hash_changes_when_the_lock_appears() {
        let bare = load_from(b"{ }\n", None);
        let locked = load_from(b"{ }\n", Some(b"{}\n"));
        assert_ne!(bare.hash, locked.hash);
    }

    #[test]
    fn marker_matches_the_hash_with_or_without_a_newline() {
        assert!(marker_is_current("abc\n", "abc"));
        assert!(marker_is_current("abc", "abc"));
        assert!(!marker_is_current("abd\n", "abc"));
        assert!(!marker_is_current("", "abc"));
    }

    #[test]
    fn install_argv_does_not_carry_the_flake() {
        let files = load_from(b"{ marker = \"kobe-flake-marker-9f3a\"; }\n", None);
        let argv = install_argv().join(" ");
        assert!(!argv.contains("kobe-flake-marker-9f3a"));
        let stdin = files.payload();
        assert!(
            stdin
                .windows(22)
                .any(|window| window == b"kobe-flake-marker-9f3a")
        );
    }

    #[test]
    fn load_rejects_a_missing_flake_and_an_oversized_one() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_err());
        std::fs::write(
            dir.path().join("flake.nix"),
            vec![b'x'; MAX_FLAKE_BYTES + 1],
        )
        .unwrap();
        let error = load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("limit"), "{error}");
    }

    fn load_from(nix: &[u8], lock: Option<&[u8]>) -> FlakeFiles {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("flake.nix"), nix).unwrap();
        if let Some(lock) = lock {
            std::fs::write(dir.path().join("flake.lock"), lock).unwrap();
        }
        let files = load(dir.path()).unwrap();
        // Keep the bytes after the temp dir drops.
        FlakeFiles {
            nix: files.nix,
            lock: files.lock,
            hash: files.hash,
        }
    }
}
