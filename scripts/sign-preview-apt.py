#!/usr/bin/env python3
"""Sign an isolated preview APT repository with its dedicated key."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import tempfile
from pathlib import Path


def run(command: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=True, stdout=subprocess.PIPE if capture_output else None, stderr=subprocess.PIPE)


def secret_fingerprint(home: Path) -> str:
    listing = run(["gpg", "--homedir", str(home), "--batch", "--with-colons", "--list-secret-keys"]).stdout.decode()
    waiting_for_fingerprint = False
    for line in listing.splitlines():
        if line.startswith(("sec:", "ssb:")):
            waiting_for_fingerprint = True
        elif line.startswith("fpr:") and waiting_for_fingerprint:
            return line.split(":")[9].upper()
        elif line and not line.startswith("uid:"):
            waiting_for_fingerprint = False
    raise ValueError("preview signing key has no primary secret-key fingerprint")


def sign_repository(repository: Path, armored_key: str, expected_fingerprint: str) -> None:
    expected = expected_fingerprint.strip().upper()
    if not re.fullmatch(r"[A-F0-9]{40,64}", expected):
        raise ValueError("preview signing fingerprint must be a full hexadecimal fingerprint")
    release = repository / "dists" / "focal" / "Release"
    if not release.is_file() or release.stat().st_size == 0:
        raise ValueError("unsigned preview Release metadata is missing")
    keyring = repository / "getpatched-preview-archive-keyring.asc"
    with tempfile.TemporaryDirectory(prefix="getpatched-preview-gnupg-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        key_file = home / "preview-signing-key.asc"
        key_file.write_text(armored_key)
        key_file.chmod(0o600)
        run(["gpg", "--homedir", str(home), "--batch", "--import", str(key_file)])
        actual = secret_fingerprint(home)
        if actual != expected:
            raise ValueError("preview signing key does not match the configured full fingerprint")
        exported = run(["gpg", "--homedir", str(home), "--batch", "--armor", "--export", expected]).stdout
        if not exported:
            raise ValueError("preview signing key has no exportable public key")
        keyring.write_bytes(exported)
        run([
            "gpg", "--homedir", str(home), "--batch", "--yes", "--digest-algo", "SHA256",
            "--local-user", expected, "--armor", "--detach-sign", "--output",
            str(release.with_name("Release.gpg")), str(release),
        ])
        run([
            "gpg", "--homedir", str(home), "--batch", "--yes", "--digest-algo", "SHA256",
            "--local-user", expected, "--output", str(release.with_name("InRelease")),
            "--clearsign", str(release),
        ])
        run(["gpg", "--homedir", str(home), "--batch", "--verify", str(release.with_name("InRelease"))])
        run(["gpg", "--homedir", str(home), "--batch", "--verify", str(release.with_name("Release.gpg")), str(release)])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    arguments = parser.parse_args()
    armored_key = os.environ.get("GETPATCHED_PREVIEW_SIGNING_KEY_ARMORED", "")
    fingerprint = os.environ.get("GETPATCHED_PREVIEW_SIGNING_FINGERPRINT", "")
    if not armored_key or not fingerprint:
        raise SystemExit("preview signing key and fingerprint must be configured in the protected preview environment")
    sign_repository(arguments.repository.resolve(), armored_key, fingerprint)


if __name__ == "__main__":
    main()
