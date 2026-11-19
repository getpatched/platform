import importlib.util
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "build-preview-apt.py"
SPEC = importlib.util.spec_from_file_location("build_preview_apt", SCRIPT_PATH)
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class PreviewAptContract(unittest.TestCase):
    def test_release_metadata_hashes_each_focal_index_and_expires(self):
        instant = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
        with self.subTest("unsigned release metadata"):
            import tempfile

            with tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                focal = repository / "dists" / "focal"
                focal.mkdir(parents=True)
                index = focal / "main" / "binary-amd64" / "Packages.gz"
                index.parent.mkdir(parents=True)
                index.write_bytes(b"package-index\n")
                release = BUILD.write_release(repository, [index], now=instant).read_text()
        digest = hashlib.sha256(b"package-index\n").hexdigest()
        index_size = len(b"package-index\n")
        self.assertIn("Suite: focal\nCodename: focal\n", release)
        self.assertIn("Date: Thu, 19 Nov 2026 12:00:00 +0000\n", release)
        self.assertIn("Valid-Until: Thu, 26 Nov 2026 12:00:00 +0000\n", release)
        self.assertIn("Architectures: amd64\nComponents: main\n", release)
        self.assertIn(f"{digest} {index_size} main/binary-amd64/Packages.gz", release)

    def test_preview_version_rejects_non_native_or_path_like_values(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "valid native Debian version"):
                BUILD.build_package(Path(temporary), "../../etc/passwd")

    def test_builder_refuses_to_delete_existing_output_contents(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "repository"
            output.mkdir()
            sentinel = output / "keep-me"
            sentinel.write_text("preserve")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                BUILD.build_repository(output)
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_test_package_is_fixed_version_arch_all_and_has_no_maintainer_hooks(self):
        package = ROOT / "preview" / "getpatched-preview-smoke"
        control = (package / "debian" / "control").read_text()
        changelog = (package / "debian" / "changelog").read_text()
        self.assertEqual(BUILD.package_version(), "0.1.0+preview1")
        self.assertIn("Architecture: all", control)
        self.assertIn("Rules-Requires-Root: no", control)
        self.assertFalse(any((package / "debian" / name).exists() for name in ("preinst", "postinst", "prerm", "postrm")))
        self.assertIn("harmless package", control.lower())
        self.assertIn("focal; urgency=low", changelog)

    def test_workflow_versions_package_paths_uniquely_for_each_run(self):
        workflow = (ROOT / ".github" / "workflows" / "preview-apt-smoke.yml").read_text()
        self.assertIn("0.1.0+preview1.${{ github.run_id }}.${{ github.run_attempt }}", workflow)
        self.assertIn("--version \"$GETPATCHED_PREVIEW_VERSION\"", workflow)
        self.assertIn("getpatched-preview-smoke=$GETPATCHED_PREVIEW_VERSION", workflow)

    def test_preview_worker_has_only_the_dedicated_custom_domain_and_bucket(self):
        config = json.loads((ROOT / "worker" / "wrangler.preview.jsonc").read_text())
        self.assertEqual(config["name"], "getpatched-apt-preview")
        self.assertFalse(config["workers_dev"])
        self.assertEqual(config["routes"], [{"pattern": "preview.getpatched.dev", "custom_domain": True}])
        self.assertEqual(config["r2_buckets"], [{"binding": "PREVIEW", "bucket_name": "getpatched-apt-preview"}])

    def test_preview_publish_workflow_is_manual_main_only_and_isolated(self):
        workflow = (ROOT / ".github" / "workflows" / "preview-apt-smoke.yml").read_text()
        self.assertIn("pull_request:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertEqual(workflow.count("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"), 3)
        self.assertIn("if: github.event_name == 'pull_request' || github.ref == 'refs/heads/main'", workflow)
        self.assertIn("environment: getpatched-apt-preview", workflow)
        self.assertIn("secrets.GETPATCHED_PREVIEW_SIGNING_KEY_ARMORED", workflow)
        self.assertIn("secrets.GETPATCHED_PREVIEW_R2_SECRET_ACCESS_KEY", workflow)
        self.assertIn("secrets.CLOUDFLARE_PREVIEW_DEPLOY_TOKEN", workflow)
        self.assertIn("https://preview.getpatched.dev", workflow)
        self.assertNotIn("https://repo.getpatched.dev", workflow)
        self.assertNotIn("GETPATCHED_SIGNING_KEY_ARMORED", workflow)
        self.assertIn("--exclude 'dists/focal/InRelease'", workflow)
        self.assertIn('repository_prefix="$bucket/runs/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}"', workflow)
        self.assertIn('"$repository_prefix/dists/focal/InRelease"', workflow)
        self.assertIn("GETPATCHED_PREVIEW_REPOSITORY_BASE: https://preview.getpatched.dev/runs/${{ github.run_id }}/${{ github.run_attempt }}", workflow)
        self.assertIn("$GETPATCHED_PREVIEW_REPOSITORY_BASE focal main", workflow)
        self.assertNotRegex(workflow, r'"\$bucket/(?:dists|pool)/')


if __name__ == "__main__":
    unittest.main()
