#!/usr/bin/env bash
# Exercise verification against signed candidate bytes before publication.
set -euo pipefail
assets=${1:-release-assets}
evidence=${2:-work/release-verification}
: "${GITHUB_REF_NAME:?version tag required}" "${GITHUB_SHA:?source SHA required}"
: "${PROVENANCE_SIGNER_SHA:?signer workflow commit is required}"
[[ "$PROVENANCE_SIGNER_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Expected a full signer workflow SHA' >&2; exit 1; }
mkdir -p "$evidence"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
signer_workflow=ruohonej/dhcpv4-served/.github/workflows/release-build.yml
identity="https://github.com/$signer_workflow@$PROVENANCE_SIGNER_SHA"
printf 'source=%s\nref=refs/tags/%s\nidentity=%s\n' "$GITHUB_SHA" "$GITHUB_REF_NAME" "$identity" >"$evidence/policy.txt"
issuer=https://token.actions.githubusercontent.com
binary="$assets/dhcpv4-served-linux-amd64"
bundle="$binary.sigstore.json"
provenance="$assets/provenance.sigstore.jsonl"
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
# gh suppresses the verification stage diagnostic when stdout is redirected.
gh_verify=(env GH_FORCE_TTY=80 NO_COLOR=1 gh attestation verify
           --repo ruohonej/dhcpv4-served --bundle "$provenance"
           --cert-oidc-issuer "$issuer" --source-ref "refs/tags/$GITHUB_REF_NAME"
           --source-digest "$GITHUB_SHA" --deny-self-hosted-runners)
gh_signer=(--signer-workflow "$signer_workflow@$PROVENANCE_SIGNER_SHA" --signer-digest "$PROVENANCE_SIGNER_SHA")
wrong_signer_sha=0000000000000000000000000000000000000000
run_check cosign-original pass cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$binary"
run_check cosign-modified digest cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$modified"
run_check cosign-after-modified pass cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$binary"
run_check cosign-wrong-identity identity cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity-wrong" "$binary"
run_check cosign-after-wrong-identity pass cosign verify-blob "${cosign_args[@]}" --certificate-identity "$identity" "$binary"
run_check provenance-original pass "${gh_verify[@]}" "${gh_signer[@]}" "$binary"
run_check provenance-modified digest "${gh_verify[@]}" "${gh_signer[@]}" "$modified"
run_check provenance-after-modified pass "${gh_verify[@]}" "${gh_signer[@]}" "$binary"
run_check provenance-wrong-identity identity "${gh_verify[@]}" --signer-workflow "$signer_workflow-wrong@$PROVENANCE_SIGNER_SHA" --signer-digest "$PROVENANCE_SIGNER_SHA" "$binary"
run_check provenance-after-wrong-identity pass "${gh_verify[@]}" "${gh_signer[@]}" "$binary"
run_check provenance-wrong-signer-digest signer-digest "${gh_verify[@]}" --signer-workflow "$signer_workflow@$PROVENANCE_SIGNER_SHA" --signer-digest "$wrong_signer_sha" "$binary"
run_check provenance-after-wrong-signer-digest pass "${gh_verify[@]}" "${gh_signer[@]}" "$binary"

# NUL delimiters preserve filenames, and wait propagates manifest read errors.
mapfile -d '' -t artifact_names < <(python3 - "$assets/release-manifest.json" <<'PY'
import json
import os
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
entries = json.loads(manifest.read_text())["artifacts"]
for name in [entry["name"] for entry in entries] + [manifest.name]:
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise SystemExit(f"Invalid release artifact filename: {name!r}")
    sys.stdout.buffer.write(os.fsencode(name) + b"\0")
PY
)
wait "$!"
for name in "${artifact_names[@]}"; do
  asset="$assets/$name"
  [[ "$asset" != "$binary" ]] || continue
  run_check "provenance-artifact-$name" pass "${gh_verify[@]}" "${gh_signer[@]}" "$asset"
done
