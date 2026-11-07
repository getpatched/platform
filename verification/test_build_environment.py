import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_environment import offline_resolver_config, runner_ca_bundle


class RunnerCaBundleTests(unittest.TestCase):
    def test_returns_buildkit_secret_reference_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "ca-certificates.crt"
            bundle.write_bytes(
                b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
            )
            expected_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            with patch.dict(os.environ, {"GETPATCHED_CA_BUNDLE": str(bundle)}):
                arguments, digest, source = runner_ca_bundle()
        self.assertEqual(arguments, ["--secret", "id=runner-ca,src=" + str(bundle.resolve())])
        self.assertEqual(digest, expected_digest)
        self.assertEqual(source, "explicit-override")

    def test_rejects_missing_or_empty_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "empty.crt"
            bundle.touch()
            with patch.dict(os.environ, {"GETPATCHED_CA_BUNDLE": str(bundle)}):
                with self.assertRaisesRegex(RuntimeError, "non-empty Linux CA bundle"):
                    runner_ca_bundle()

    def test_rejects_non_certificate_and_private_key_material(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "invalid.crt"
            for contents, message in (
                (b"not a certificate\n", "PEM-encoded certificates"),
                (b"-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n", "private key"),
            ):
                bundle.write_bytes(contents)
                with patch.dict(os.environ, {"GETPATCHED_CA_BUNDLE": str(bundle)}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        runner_ca_bundle()


class OfflineResolverConfigTests(unittest.TestCase):
    def test_configures_local_only_dns_and_returns_read_only_bind_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = offline_resolver_config(directory)
            config = (Path(directory) / "resolv.conf").read_text()
        self.assertEqual(config, "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
        self.assertEqual(mount[0], "--mount")
        self.assertIn("target=/etc/resolv.conf,readonly", mount[1])
        self.assertIn("/resolv.conf", mount[1])


class PinnedAptSourceTests(unittest.TestCase):
    def test_container_builds_remove_image_default_apt_sources(self):
        for name in ("packaging", "baseline", "patched-scan"):
            with self.subTest(container=name):
                containerfile = (ROOT / "build" / f"{name}.Containerfile").read_text()
                clear_sources = containerfile.index("rm -f /etc/apt/sources.list.d/*")
                configure_sources = containerfile.index("> /etc/apt/sources.list")
                self.assertLess(clear_sources, configure_sources)

    def test_packaging_disables_valid_until_only_for_immutable_debian_snapshots(self):
        containerfile = (ROOT / "build/packaging.Containerfile").read_text()
        snapshot_detection = "grep -Eq 'https?://snapshot(-fastly)?[.]debian[.]org/' /etc/apt/sources.list"
        self.assertIn(snapshot_detection, containerfile)
        apt_get = containerfile.split("    apt_get() {", 1)[1].split("    apt_retry()", 1)[0]
        snapshot_branch, live_branch = apt_get.split("      else \
", 1)
        self.assertIn('if [ "$snapshot_sources" = true ]; then', apt_get)
        self.assertIn("Acquire::Check-Valid-Until=false", snapshot_branch)
        self.assertNotIn("Acquire::Check-Valid-Until=false", live_branch)
        self.assertIn("Acquire::AllowInsecureRepositories=false", containerfile)
        self.assertIn("Acquire::AllowDowngradeToInsecureRepositories=false", containerfile)
        self.assertLess(containerfile.index("> /etc/apt/sources.list"), containerfile.index("snapshot_sources=false"))

    def test_baseline_disables_expiry_only_on_pinned_snapshot_source_lines(self):
        containerfile = (ROOT / "build/baseline.Containerfile").read_text()
        snapshot_option = (
            "sed -i -E '/^deb(-src)? \\[arch=[^]]+\\] "
            "https?:\\/\\/snapshot(-fastly)?[.]debian[.]org\\// "
            "s/\\]/ check-valid-until=no]/' /etc/apt/sources.list"
        )
        self.assertIn(snapshot_option, containerfile)
        self.assertNotIn("Acquire::Check-Valid-Until=false", containerfile)
        source_list = containerfile.index("> /etc/apt/sources.list")
        expiry_option = containerfile.index("check-valid-until=no")
        self.assertLess(source_list, expiry_option)
        self.assertLess(expiry_option, containerfile.index("apt-get update"))

    def test_patched_scan_disables_expiry_only_on_pinned_snapshot_source_lines(self):
        containerfile = (ROOT / "build/patched-scan.Containerfile").read_text()
        snapshot_option = (
            "sed -i -E '/^deb(-src)? \\[arch=[^]]+\\] "
            "https?:\\/\\/snapshot(-fastly)?[.]debian[.]org\\// "
            "s/\\]/ check-valid-until=no]/' /etc/apt/sources.list"
        )
        self.assertIn(snapshot_option, containerfile)
        self.assertNotIn("Acquire::Check-Valid-Until=false", containerfile)
        source_list = containerfile.index("> /etc/apt/sources.list")
        expiry_option = containerfile.index("check-valid-until=no")
        self.assertLess(source_list, expiry_option)
        self.assertLess(expiry_option, containerfile.index("apt-get update"))
        command = containerfile.split("sed -i -E '", 1)[1].split("' /etc/apt/sources.list", 1)[0]
        sources = (
            "deb [arch=amd64] https://snapshot-fastly.debian.org/archive/debian/20261030T000000Z/ trixie main\n"
            "deb [arch=amd64] https://deb.debian.org/debian/ trixie main\n"
            "deb-src [arch=amd64] https://snapshot.debian.org/archive/debian-security/20261030T000000Z/ trixie-security main\n"
        )
        transformed = subprocess.run(
            ["sed", "-E", command], input=sources, text=True, capture_output=True, check=True
        ).stdout
        self.assertEqual(
            transformed,
            "deb [arch=amd64 check-valid-until=no] https://snapshot-fastly.debian.org/archive/debian/20261030T000000Z/ trixie main\n"
            "deb [arch=amd64] https://deb.debian.org/debian/ trixie main\n"
            "deb-src [arch=amd64 check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261030T000000Z/ trixie-security main\n",
        )
