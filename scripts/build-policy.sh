#!/usr/bin/env bash
# Compile a Rego policy to wasm using OPA.
#
# OPA type-checks builtins, so host builtins implemented in Node must be
# declared in policy/capabilities.json or `opa build` rejects the policy with
# "undefined function". That file is the contract between the Rego policy and
# the Node host — keep them in sync.
#
# Usage: scripts/build-policy.sh <path/to/policy.rego> [entrypoint]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Prefer a vendored CLI, then one already on PATH. The binary is never shipped
# in the npm package — `toolwall fetch-opa` puts one in bin/.
OPA="${OPA_BIN:-$ROOT/bin/opa}"
if [ ! -x "$OPA" ] && command -v opa >/dev/null 2>&1; then
	OPA="$(command -v opa)"
fi
CAPS="$ROOT/policy/capabilities.json"

SRC="${1:?usage: build-policy.sh <policy.rego> [entrypoint]}"
# Compose with the bundled defaults so a custom file can just add rules
# instead of having to restate the entire policy. Set BASE_POLICY= (empty) to
# compile standalone — `:-` is wrong here, it treats empty as unset and would
# compose even when the caller explicitly opted out.
BASE_POLICY="${BASE_POLICY-$ROOT/policy/default.rego}"
EXTRA=()
if [ -n "$BASE_POLICY" ] && [ -f "$BASE_POLICY" ]; then
	src_abs="$(cd "$(dirname "$SRC")" && pwd)/$(basename "$SRC")"
	base_abs="$(cd "$(dirname "$BASE_POLICY")" && pwd)/$(basename "$BASE_POLICY")"
	if [ "$src_abs" != "$base_abs" ]; then
		EXTRA+=("$BASE_POLICY")
	fi
fi
ENTRYPOINT="${2:-firewall/decision}"
OUT="${OUT_DIR:-${OUT_WASM:-$ROOT/.build}}"

# The bundled policy ships precompiled, so most installs never compile Rego.
# Point people at the fetch command rather than a bare path error.
if [ ! -x "$OPA" ]; then
	cat >&2 <<EOF
build-policy: the OPA CLI is required to compile Rego, but it was not found at:
  $OPA

This is only needed when authoring custom .rego — installing and running
toolwall does not require it, because policy/default.wasm ships precompiled.

  npm run fetch:opa      # from a source checkout
  toolwall fetch-opa     # from an installed package
EOF
	exit 1
fi

mkdir -p "$OUT"
mkdir -p "$(dirname "$OUT")"

# Build to a scratch name and only replace the live policy once the build has
# succeeded. Removing the old wasm up front means a failed compile (a typo in
# the .rego) destroys a policy that was working a second ago.
TMP_BUNDLE="$OUT/.bundle.tmp.tar.gz"
TMP_WASM="$OUT/.policy.wasm.tmp"
rm -f "$TMP_BUNDLE" "$TMP_WASM"

if ! "$OPA" build -t wasm \
	--capabilities "$CAPS" \
	-e "$ENTRYPOINT" \
	-o "$TMP_BUNDLE" \
	"${EXTRA[@]+"${EXTRA[@]}"}" \
	"$SRC"; then
	echo "build failed; any previously built policy was left untouched" >&2
	exit 1
fi

# bundle members are absolute paths; strip the leading slash on extract
tar -xzf "$TMP_BUNDLE" -C "$OUT" 2>/dev/null || true

if [ ! -f "$OUT/policy.wasm" ]; then
	echo "build produced no policy.wasm" >&2
	exit 1
fi

mv -f "$OUT/policy.wasm" "$TMP_WASM"
mv -f "$TMP_WASM" "$OUT/policy.wasm"
rm -f "$TMP_BUNDLE"

echo "built $OUT/policy.wasm ($(du -h "$OUT/policy.wasm" | cut -f1))" >&2