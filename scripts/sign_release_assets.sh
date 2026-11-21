#!/usr/bin/env bash
# Sign the frozen staged files once and verify each resulting keyless bundle.
set -euo pipefail
shopt -s nullglob
assets=${1:-release-assets}
: "${GITHUB_REF_NAME:?version tag is required}"
case "$GITHUB_REF_NAME" in v*) ;; *) echo 'Expected a version tag' >&2; exit 1 ;; esac
identity="https://github.com/ruohonej/dhcpv4-served/.github/workflows/release.yml@refs/tags/$GITHUB_REF_NAME"
issuer=https://token.actions.githubusercontent.com
files=("$assets"/*)
[ "${#files[@]}" -gt 0 ] || { echo 'No release assets to sign' >&2; exit 1; }
for file in "${files[@]}"; do
  [ -f "$file" ] && [ ! -L "$file" ] && [[ "$file" != *.sigstore.json ]] && [ ! -e "$file.sigstore.json" ] || {
    echo "Unexpected file or existing signature: $file" >&2; exit 1;
  }
done
for file in "${files[@]}"; do
  cosign sign-blob --yes --bundle "$file.sigstore.json" "$file"
  cosign verify-blob --bundle "$file.sigstore.json" \
    --certificate-oidc-issuer "$issuer" --certificate-identity "$identity" "$file"
done
