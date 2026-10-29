#!/usr/bin/env bash
# Cargo.lock includes ssh-key's optional ECDSA implementations even when no
# build enables them. Check the resolved workspace graph for every target
# before allowing that lockfile-only crypto-bigint advisory in cargo audit.
set -euo pipefail

tree="$(cargo tree --locked --workspace --target all --prefix none --format '{p}')"
printf '%s\n' "$tree" | awk '
  $1 == "crypto-bigint" {
    version = $2
    sub(/^v/, "", version)
    split(version, parts, ".")
    if (parts[1] == 0 && (parts[2] < 7 || (parts[2] == 7 && parts[3] < 6))) {
      print "vulnerable crypto-bigint is enabled: " $0 > "/dev/stderr"
      failed = 1
    }
  }
  END { exit failed }
'
