#!/usr/bin/env bash
# Exercise verification against signed candidate bytes before publication.
set -euo pipefail
assets=${1:-release-assets}
evidence=${2:-work/release-verification}
: "${GITHUB_REF_NAME:?version tag required}" "${GITHUB_SHA:?source SHA required}"
mkdir -p "$evidence"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
identity="https://github.com/ruohonej/dhcpv4-served/.github/workflows/release.yml@refs/tags/$GITHUB_REF_NAME"
printf 'source=%s\nref=refs/tags/%s\nidentity=%s\n' "$GITHUB_SHA" "$GITHUB_REF_NAME" "$identity" >"$evidence/policy.txt"
issuer=https://token.actions.githubusercontent.com
binary="$assets/dhcpv4-served-linux-amd64"
bundle="$binary.sigstore.json"
modified="$evidence/modified-binary"
cp "$binary" "$modified"
python3 - "$modified" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
if not data:
    raise SystemExit("empty binary")
data[0] ^= 1
p.write_bytes(data)
PY
# Retain verifier output and exit codes, not tokens or modified release files.
run_check() {
  local name=$1 expected=$2 status=0
  shift 2
  "$@" >"$evidence/$name.log" 2>&1 || status=$?
  printf '%s\n' "$status" >"$evidence/$name.exit"
  python3 "$script_dir/check_verification_result.py" "$name" "$expected" "$status" "$evidence/$name.log" "$identity"
}
trap 'rm -f "$modified"' EXIT
cosign_args=(--bundle "$bundle" --certificate-oidc-issuer "$issuer")
run_check cosign-original pass cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$binary"
run_check cosign-modified digest cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$modified"
run_check cosign-after-modified pass cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$binary"
run_check cosign-wrong-identity identity cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity-wrong" "$binary"
run_check cosign-after-wrong-identity pass cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$binary"
