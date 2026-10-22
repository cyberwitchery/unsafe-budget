#!/usr/bin/env bash
set -euo pipefail

tag="${INPUT_VERSION}"
case "${tag}" in
    "")
        action_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
        version="$(awk -F '"' '
            /^\[package\]/ { in_package = 1; next }
            /^\[/ { in_package = 0 }
            in_package && /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
        ' "${action_dir}/Cargo.toml")"
        if [ -z "${version}" ]; then
            echo "failed to read package version from action manifest" >&2
            exit 1
        fi
        tag="v${version}"
        ;;
    latest)
        tag="$(gh api "repos/${INPUT_REPOSITORY}/releases/latest" --jq .tag_name)"
        ;;
esac

if [ -z "${tag}" ]; then
    echo "failed to resolve latest release tag of ${INPUT_REPOSITORY}" >&2
    exit 1
fi

echo "tag=${tag}" >> "${GITHUB_OUTPUT}"
