#!/usr/bin/env bash
# Fetch and verify the OPA CLI used to compile Rego policies to wasm.
#
# OPA has no official npm distribution, so the binary is vendored into bin/ and
# gitignored. Checksums come from the official release.
set -euo pipefail

VERSION="${OPA_VERSION:-v1.21.1}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/bin/opa"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
	x86_64 | amd64) ARCH="amd64" ;;
	arm64 | aarch64) ARCH="arm64" ;;
	*) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

# The static linux build is the one known to include WebAssembly support;
# the v1.10.0 static build reported "WebAssembly: unavailable".
NAME="opa_${OS}_${ARCH}_static"

if [ -x "$DEST" ] && "$DEST" version 2>/dev/null | grep -q "Version: ${VERSION#v}"; then
	echo "opa $VERSION already present"
	exit 0
fi

mkdir -p "$ROOT/bin"
BASE="https://github.com/open-policy-agent/opa/releases/download/$VERSION"

echo "fetching $NAME ($VERSION)"
curl -fsSL --max-time 600 -o "$DEST" "$BASE/$NAME"
curl -fsSL --max-time 120 -o "$DEST.sha256" "$BASE/$NAME.sha256"

EXPECTED="$(cut -d' ' -f1 < "$DEST.sha256")"
ACTUAL="$(sha256sum "$DEST" | cut -d' ' -f1)"
if [ "$EXPECTED" != "$ACTUAL" ]; then
	rm -f "$DEST"
	echo "checksum mismatch: expected $EXPECTED got $ACTUAL" >&2
	exit 1
fi

chmod +x "$DEST"
"$DEST" version | grep -q "WebAssembly: available" || {
	echo "WARNING: this OPA build lacks WebAssembly support; policy compilation will fail" >&2
}
rm -f "$DEST.sha256"
echo "installed $DEST ($("$DEST" version | head -1))"