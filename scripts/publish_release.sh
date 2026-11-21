#!/usr/bin/env bash
# Publish only while the remote tag points at the verified source commit.
set -euo pipefail
: "${GITHUB_REPOSITORY:?repository required}" "${GITHUB_REF_NAME:?version tag required}" "${GITHUB_SHA:?source SHA required}"

# The commits endpoint resolves both lightweight and annotated tags to commits.
remote_sha=$(gh api "repos/$GITHUB_REPOSITORY/commits/tags/$GITHUB_REF_NAME" --jq '.sha')
if [[ "$remote_sha" != "$GITHUB_SHA" ]]; then
  echo 'Remote release tag does not resolve to the verified source commit' >&2
  exit 1
fi

release_flags=(--repo "$GITHUB_REPOSITORY" --verify-tag --generate-notes)
if [[ "$GITHUB_REF_NAME" == *-* ]]; then
  release_flags+=(--prerelease)
fi
gh release create "$GITHUB_REF_NAME" release-assets/* "${release_flags[@]}"
