#!/usr/bin/env python3
"""Classify verifier results; an arbitrary command failure is never evidence."""
import json
from pathlib import Path
import re
import sys


def classify(name, expected, status, output, identity):
    if expected == "pass":
        return status == 0
    if status != 1:
        return False
    if name.startswith("cosign-"):
        if expected == "digest":
            diagnostic = (r"failed to verify signature: could not verify message: "
                          r"invalid signature when validating (?:ASN\.1|IEEE_P1363) encoded signature")
        elif expected == "identity":
            diagnostic = (r"failed to verify certificate identity: no matching CertificateIdentity found, last error: "
                          + re.escape(f'expected SAN value "{identity}-wrong", got "{identity}"'))
        else:
            return False
        return re.search(diagnostic + r"\s*$", output) is not None
    if name.startswith("provenance-") and expected in ("digest", "identity"):
        # gh 2.103.3 discards the underlying Sigstore error. Both the specific
        # stage marker and public Sigstore issuer error are required.
        # TUF, network, credential, bundle-loading and argument errors differ.
        return ("✗ Sigstore verification failed" in output.splitlines()
                and re.search(r'Error: verifying with issuer "sigstore\.dev"\s*$', output)
                is not None)
    return False


if __name__ == "__main__":
    name, expected, raw_status, log, identity = sys.argv[1:]
    status = int(raw_status)
    accepted = classify(name, expected, status, Path(log).read_text(), identity)
    Path(log).with_suffix(".result.json").write_text(json.dumps({
        "check": name, "expected": expected, "exit": status,
        "accepted": accepted,
    }, indent=2) + "\n")
    if not accepted:
        raise SystemExit(f"Unexpected verification result: {name} (exit {status}); see {log}")
