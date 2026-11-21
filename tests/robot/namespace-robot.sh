#!/bin/bash
# Namespace runners prepare a traversable, root-owned /tmp before calling this.
set -euo pipefail
source_worker=${1:?expected the worker executable}
shift
staged_worker=$(mktemp /tmp/dhcpv4-served.XXXXXXXX)
trap 'rm -f -- "$staged_worker"' EXIT
install -m 0755 -- "$source_worker" "$staged_worker"
work/venv/bin/python -m robot --pythonpath tests/robot --variable "WORKER:$staged_worker" "$@"
