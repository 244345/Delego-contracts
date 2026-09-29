#!/usr/bin/env bash
# Check that every contract's declared version is recorded in CHANGELOG.md.
#
# Versions are resolved from each contract's on-chain `version()` source
# (semver symbol, CONTRACT_SEMVER const), falling back to the crate version
# in Cargo.toml for contracts without a `version()` entry point.
#
# Usage: scripts/check-changelog.sh
# Exit code 1 with a helpful message if a version bump is not recorded.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"

fail() {
  echo "❌ $1" >&2
  exit 1
}

# resolve_version <contract-dir> — prints the normalized (x.y.z) version.
resolve_version() {
  local dir="$1"
  local lib="$REPO_ROOT/$dir/src/lib.rs"
  local version=""

  if [ -f "$lib" ]; then
    # escrow / marketplace: semver: symbol_short!("0_2_0")
    version="$(sed -n 's/.*semver: symbol_short!("\([0-9_]*\)").*/\1/p' "$lib" | head -n1)"
    # permissions: pub const CONTRACT_SEMVER: &str = "0_1_0";
    if [ -z "$version" ]; then
      version="$(sed -n 's/.*CONTRACT_SEMVER: &str = "\([0-9_]*\)".*/\1/p' "$lib" | head -n1)"
    fi
  fi

  # reputation / delegation_registry: no hardcoded semver -> crate version.
  if [ -z "$version" ]; then
    version="$(sed -n 's/^version = "\([0-9][0-9.]*\)".*/\1/p' "$REPO_ROOT/$dir/Cargo.toml" | head -n1)"
  fi

  [ -n "$version" ] || fail "could not resolve version for contract \"$dir\""
  echo "${version//_/.}"
}

# check_contract <name> <version> — verifies "## <name>" section has a "### <version>" entry.
check_contract() {
  local name="$1"
  local version="$2"

  local section
  section="$(awk -v name="$name" '
    $0 ~ "^## " name "( |$)" { in_sec = 1; next }
    in_sec && $0 ~ "^## " { in_sec = 0 }
    in_sec { print }
  ' "$CHANGELOG")"

  if [ -z "$section" ]; then
    fail "CHANGELOG.md has no section for contract \"$name\" (expected \"## $name\"). Add one with a \"### $version\" entry."
  fi
  if ! grep -q "^### $version" <<<"$section"; then
    fail "CHANGELOG.md section \"## $name\" has no entry for current version $version. Record the bump: add a \"### $version\" heading describing the change."
  fi
  echo "✓ $name @ $version"
}

[ -f "$CHANGELOG" ] || fail "CHANGELOG.md not found at $CHANGELOG"

# name dir
contracts=(
  "escrow escrow"
  "permissions permissions"
  "reputation reputation"
  "delegation_registry delegation_registry"
  "marketplace marketplace"
)

for entry in "${contracts[@]}"; do
  # shellcheck disable=SC2086
  set -- $entry
  name="$1"
  dir="$2"
  version="$(resolve_version "$dir")"
  check_contract "$name" "$version"
done

echo "✅ All contract versions are recorded in CHANGELOG.md"
