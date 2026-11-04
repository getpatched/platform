import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import importlib.util

sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import apt_source_list, package_target_policy, target_profile, target_source_branch
_SCAN_SPEC = importlib.util.spec_from_file_location("getpatched_scan", ROOT / "scripts/getpatched-scan.py")
_SCAN = importlib.util.module_from_spec(_SCAN_SPEC)
_SCAN_SPEC.loader.exec_module(_SCAN)
debian_version_compare = _SCAN.debian_version_compare


class PublicCatalogueContract(unittest.TestCase):
    def test_expat_records_match_verified_policy_and_osv_package_scope(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        catalogue = json.loads((ROOT / "site/catalogue.json").read_text())
        feed = json.loads((ROOT / "advisories/getpatched-osv.json").read_text())
        policy = platform["packages"]["expat"]["targets"]
        record = next(item for item in catalogue["packages"] if item["source"] == "expat")
        advisory = next(item for item in feed["vulns"] if item["id"] == "CVE-2026-117610")
        self.assertEqual(advisory["database_specific"]["verification_status"],
                         "development-verified-production-release-pending")

        expected_runs = {
            "debian-bookworm-amd64": "41543751522",
            "debian-trixie-amd64": "41546270294",
        }
        for target_id, target_policy in policy.items():
            with self.subTest(target=target_id):
                self.assertEqual(target_policy["candidateStatus"],
                                 "development-verified-production-release-pending")
                target_record = record["targets"][target_id]
                self.assertEqual(target_record["baseVersion"], target_policy["baselineVersion"])
                self.assertEqual(target_record["version"], target_policy["packageVersion"])
                self.assertEqual(target_record["cves"], target_policy["targetCves"])
                self.assertEqual(target_record["status"], target_policy["candidateStatus"])
                self.assertEqual(target_record["verification"],
                                 f"https://github.com/getpatched/platform/actions/runs/{expected_runs[target_id]}")
                self.assertEqual(target_record["access"], "public")
                self.assertEqual(target_record["delayHours"], 0)
                self.assertEqual(len(target_record["patches"]), 1)
                patch = target_record["patches"][0]
                self.assertEqual(patch["sha256"],
                                 "365988ba0fb36bf8fde4792a4288e0f5bc466411b50b888de960bb6aa3a6a5a9")
                self.assertEqual(patch["upstream"]["commit"],
                                 "bfc28346fa3efeb8ca56c17437d24a7344e5feab")
                affected = [item for item in advisory["affected"]
                            if item["ecosystem_specific"].get("target_id") == target_id]
                self.assertEqual({item["package"]["name"] for item in affected},
                                 set(target_policy["advisoryPackages"]))
                for item in affected:
                    self.assertEqual(item["versions"], [target_policy["baselineVersion"]])
                    self.assertEqual(item["database_specific"]["candidate_version"],
                                     target_policy["packageVersion"])
                    self.assertEqual(item["database_specific"]["getpatched_fixed_version"],
                                     target_policy["packageVersion"])
                    self.assertEqual(item["database_specific"]["candidate_status"],
                                     target_policy["candidateStatus"])

    def test_ubuntu_snapshot_source_list_emits_one_suite_per_apt_line(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        profile = target_profile(platform, "ubuntu-focal-amd64")
        self.assertEqual(target_source_branch(platform, "ubuntu-focal-amd64"), "getpatched/focal")
        lines = apt_source_list(profile).splitlines()
        self.assertEqual(len(lines), 6)
        for suite in ("focal", "focal-updates", "focal-security"):
            for kind in ("deb", "deb-src"):
                self.assertIn(
                    f"{kind} [arch=amd64] https://snapshot.ubuntu.com/ubuntu/20261025T000000Z/ {suite} main universe restricted multiverse",
                    lines,
                )

    def test_debian_arm64_target_profile_generates_architecture_scoped_sources_without_enabling_publication(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        target_id = "debian-bookworm-arm64"
        platform["targets"][target_id] = {
            "distribution": "Debian", "releaseVersion": "12", "codename": "bookworm",
            "architecture": "arm64", "sourceBranch": "getpatched/bookworm",
            "advisoryEcosystem": "Debian:12", "packageEcosystem": "Debian",
            "build": {"runner": "ubuntu-24.04-arm", "containerPlatform": "linux/arm64"},
            "repository": {"enabled": False}, "archiveSnapshot": "20261025T000000Z",
            "baseImage": "debian:12@sha256:" + "a" * 64,
            "aptSources": [{"type": "both", "uri": "https://snapshot.debian.org/archive/debian/20261025T000000Z/",
                            "suites": ["bookworm", "bookworm-updates", "bookworm-security"], "components": ["main"]}],
        }
        profile = target_profile(platform, target_id)
        self.assertFalse(profile["repository"]["enabled"])
        self.assertIn("[arch=arm64] https://snapshot.debian.org/archive/debian/20261025T000000Z/", apt_source_list(profile))

    def test_debian_fastly_snapshot_mirror_is_allowed_and_keeps_snapshot_pinned(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        profile = platform["targets"]["debian-trixie-amd64"]
        profile["aptSources"][0]["uri"] = profile["aptSources"][0]["uri"].replace(
            "snapshot.debian.org", "snapshot-fastly.debian.org"
        )
        resolved = target_profile(platform, "debian-trixie-amd64")
        self.assertTrue(all("20261030T000000Z" in source["uri"] for source in resolved["aptSources"]))
        self.assertIn("snapshot-fastly.debian.org", apt_source_list(resolved))

        profile["aptSources"][0]["uri"] = profile["aptSources"][0]["uri"].replace(
            "20261030T000000Z", "20261031T000000Z"
        )
        with self.assertRaises(ValueError):
            target_profile(platform, "debian-trixie-amd64")

    def test_all_distribution_snapshot_sources_require_https(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        for target_id in platform["targets"]:
            sources = apt_source_list(target_profile(platform, target_id))
            self.assertNotIn("http://", sources, target_id)
            self.assertIn("https://", sources, target_id)
        for filename in ("packaging.Containerfile", "baseline.Containerfile", "patched-scan.Containerfile"):
            containerfile = (ROOT / "build" / filename).read_text()
            self.assertIn("# syntax=docker/dockerfile:1.7", containerfile)
            self.assertIn("RUN --mount=type=secret,id=runner-ca", containerfile)
            self.assertIn("/etc/ssl/certs/ca-certificates.crt", containerfile)
            self.assertIn("chmod 0644 /etc/ssl/certs/ca-certificates.crt", containerfile)
            self.assertIn('Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt"', containerfile)
        build_script = (ROOT / "scripts/build-package.py").read_text()
        self.assertIn("ca_secret_args, ca_bundle_sha256, ca_bundle_source = runner_ca_bundle()", build_script)
        self.assertIn("*ca_secret_args", build_script)
        self.assertIn('"runnerCaBundleSha256": ca_bundle_sha256', build_script)

        baseline_script = (ROOT / "scripts/run-baseline.py").read_text()
        self.assertIn("*ca_secret_args", baseline_script)
        self.assertIn('"runnerCaBundleSource": ca_bundle_source', baseline_script)
        self.assertIn('"runnerCaBundleSha256": ca_bundle_sha256', baseline_script)

        client_script = (ROOT / "scripts/test-apt-repository.py").read_text()
        self.assertIn("*ca_secret_args", client_script)
        self.assertIn('"runnerCaBundleSource": ca_bundle_source', client_script)
        self.assertIn('"runnerCaBundleSha256": ca_bundle_sha256', client_script)
        self.assertIn('Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt"', client_script)
        self.assertIn("chmod 0644 /etc/ssl/certs/ca-certificates.crt", client_script)

        untrusted_debian = json.loads(json.dumps(platform))
        untrusted_debian["targets"]["debian-trixie-amd64"]["aptSources"][0]["uri"] = (
            "http://mirror.example.invalid/debian/20261030T000000Z/"
        )
        with self.assertRaises(ValueError):
            target_profile(untrusted_debian, "debian-trixie-amd64")

        insecure_ubuntu = json.loads(json.dumps(platform))
        insecure_ubuntu["targets"]["ubuntu-focal-amd64"]["aptSources"][0]["uri"] = (
            "http://snapshot.ubuntu.com/ubuntu/20261025T000000Z/"
        )
        with self.assertRaises(ValueError):
            target_profile(insecure_ubuntu, "ubuntu-focal-amd64")

    def test_tiff_verified_candidate_uses_declared_source_branch(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        self.assertEqual(target_source_branch(platform, "debian-bookworm-amd64", "tiff"),
                         "getpatched/debian-bookworm")
        self.assertEqual(target_source_branch(platform, "debian-bookworm-amd64"),
                         "getpatched/debian-bookworm")
        self.assertEqual(target_source_branch(platform, "debian-bookworm-amd64", "libxml2"),
                         "getpatched/debian-bookworm")

    def test_cares_verified_candidate_uses_maintenance_branch_and_advisory_scope(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        self.assertEqual(
            target_source_branch(platform, "debian-trixie-amd64", "c-ares"),
            "getpatched/debian-trixie",
        )
        policy = package_target_policy(platform, "c-ares", "debian-trixie-amd64")
        self.assertEqual(policy["candidateStatus"], "development-verified-sponsor-flow-pending")
        self.assertEqual(policy["targetCves"], ["CVE-2026-69184", "CVE-2026-69186"])
        self.assertEqual(policy["advisoryPackagesByCve"], {
            "CVE-2026-69184": ["libcares2"],
            "CVE-2026-69186": ["libcares2"],
        })
        self.assertFalse(set(policy["binaryPackages"]) & set(policy["builderPackages"]))
        self.assertEqual(policy["builderPackages"], ["libc-ares-dev"])

    def test_tiff_verified_candidate_replaces_previous_verified_release(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        target = package_target_policy(platform, "tiff", "debian-bookworm-amd64")
        self.assertEqual(target["candidateStatus"], "development-verified-production-release-pending")
        self.assertEqual(target["packageVersion"], "4.5.0-6+deb12u4+getpatched5")
        self.assertEqual(target["advisoryPackagesByCve"], {
            "CVE-2025-61144": ["libtiff-tools"],
            "CVE-2026-52490": ["libtiff-tools"],
            "CVE-2026-12912": ["libtiff6"],
            "CVE-2026-18495": ["libtiff-tools"],
        })
        self.assertEqual(target["verifiedReleases"][-1]["version"], "4.5.0-6+deb12u4+getpatched4")
        self.assertEqual(target["verifiedReleases"][-1]["targetCves"], [
            "CVE-2025-61144", "CVE-2026-52490", "CVE-2026-12912",
        ])
        invalid = json.loads(json.dumps(platform))
        invalid["packages"]["tiff"]["targets"]["debian-bookworm-amd64"]["advisoryPackagesByCve"]["CVE-2026-12912"] = ["libtiff-tools"]
        with self.assertRaisesRegex(ValueError, "per-CVE advisory package scope"):
            package_target_policy(invalid, "tiff", "debian-bookworm-amd64")

    def test_build_and_baseline_images_use_target_scoped_binary_package_names(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        jammy = package_target_policy(platform, "libgit2", "ubuntu-jammy-amd64")
        self.assertEqual(jammy["binaryPackages"][0], "libgit2-1.1")
        self.assertEqual(package_target_policy(platform, "libxml2", "ubuntu-focal-amd64")["builderPackages"], ["libxml2-dev"])
        self.assertEqual(package_target_policy(platform, "libarchive", "ubuntu-focal-amd64")["builderPackages"], ["libarchive-dev"])
        for filename in ("packaging.Containerfile", "baseline.Containerfile", "patched-scan.Containerfile"):
            containerfile = (ROOT / "build" / filename).read_text()
            self.assertIn("ARG BINARY_PACKAGES", containerfile)
            self.assertNotIn('case "$SOURCE_PACKAGE" in', containerfile)
            if filename == "packaging.Containerfile":
                self.assertIn("ARG BUILDER_PACKAGES", containerfile)
                self.assertIn('install_packages="$BINARY_PACKAGES $BUILDER_PACKAGES"', containerfile)
                self.assertIn("for binary in $install_packages; do", containerfile)
            else:
                self.assertIn("for binary in $BINARY_PACKAGES; do", containerfile)
        build_script = (ROOT / "scripts/build-package.py").read_text()
        baseline_script = (ROOT / "scripts/run-baseline.py").read_text()
        self.assertIn('"BINARY_PACKAGES=" + " ".join(policy["binaryPackages"])', build_script)
        self.assertIn('"BUILDER_PACKAGES=" + " ".join(policy["builderPackages"])', build_script)
        self.assertEqual(
            build_script.count('"BINARY_PACKAGES=" + " ".join(expected["binaryPackages"])'),
            2,
        )
        self.assertIn('"BINARY_PACKAGES=" + " ".join(package["binaryPackages"])', baseline_script)
        regression = (ROOT / "verification/regression.py").read_text()
        self.assertIn('installed_name = binary_packages[0]', regression)
        self.assertNotIn('"libgit2": "libgit2-28"', regression)
        invalid = deepcopy(platform)
        invalid["packages"]["libgit2"]["targets"]["ubuntu-jammy-amd64"]["builderPackages"] = ["bad package"]
        with self.assertRaisesRegex(ValueError, "invalid builder package scope"):
            package_target_policy(invalid, "libgit2", "ubuntu-jammy-amd64")

    def test_patched_scan_uses_candidate_built_headers_when_runtime_version_is_patched(self):
        build_script = (ROOT / "scripts/build-package.py").read_text()
        scan_containerfile = (ROOT / "build/patched-scan.Containerfile").read_text()
        policy = json.loads((ROOT / "packages.json").read_text())
        tiff = package_target_policy(policy, "tiff", "debian-bookworm-amd64")
        self.assertEqual(set(tiff["builderPackages"]), {"libtiff-dev", "libtiffxx6"})
        trixie_tiff = package_target_policy(policy, "tiff", "debian-trixie-amd64")
        self.assertTrue({"libtiff-dev", "libtiff6", "libtiffxx6"}.issubset(
            set(trixie_tiff["builderPackages"])))
        self.assertIn('builder_names = set(expected["builderPackages"])', build_script)
        self.assertIn('"--build-arg", "BUILDER_DEB_PACKAGES=" + " ".join(builder_deb_names)', build_script)
        self.assertIn("COPY builder-debs/ /tmp/getpatched-builder/", scan_containerfile)
        self.assertIn("apt-get install -y --no-install-recommends $builder_debs", scan_containerfile)
        self.assertIn("for binary in $BUILDER_PACKAGES; do", scan_containerfile)
        self.assertIn("builder package version differs from the candidate version", build_script)

    def test_target_recipe_branch_rejects_untrusted_ref_syntax(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        platform["targets"]["ubuntu-focal-amd64"]["sourceBranch"] = "getpatched/../main"
        with self.assertRaisesRegex(ValueError, "valid getpatched/\\* source branch"):
            target_profile(platform, "ubuntu-focal-amd64")

    def test_package_ecosystem_override_must_match_target_distribution_and_release(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        target = "ubuntu-focal-amd64"
        policy = platform["packages"]["libpng1.6"]["targets"][target]
        policy["packageEcosystem"] = "Ubuntu:20.04:LTS"
        self.assertEqual(package_target_policy(platform, "libpng1.6", target)["packageEcosystem"], "Ubuntu:20.04:LTS")

        policy["packageEcosystem"] = "Ubuntu:22.04:LTS"
        with self.assertRaisesRegex(ValueError, "valid package ecosystem"):
            package_target_policy(platform, "libpng1.6", target)

    def test_libpng_followup_assessment_records_nonaffected_baseline_and_scan_policy(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        target_id = "ubuntu-focal-amd64"
        policy = platform["packages"]["libpng1.6"]["targets"][target_id]
        assessment = policy["followUpAssessments"]["CVE-2026-22695"]
        self.assertEqual(assessment["baselineApplicability"], "not-affected")
        self.assertEqual(assessment["candidateDisposition"], "fixed-in-backport")
        self.assertEqual(assessment["introducedBy"], "218612ddd6b17944e21eda56caf8b4bf7779d1ea")
        self.assertEqual(assessment["fixedBy"], "e4f7ad4ea2a471776c81dda4846b7691925d9786")
        self.assertIn("scanner absence alone is not remediation evidence", assessment["scannerTreatment"])
        self.assertEqual(package_target_policy(platform, "libpng1.6", target_id)["followUpAssessments"],
                         policy["followUpAssessments"])
        policy["followUpAssessments"]["CVE-2026-22695"]["fixedBy"] = "not-a-commit"
        with self.assertRaisesRegex(ValueError, "invalid follow-up CVE assessment"):
            package_target_policy(platform, "libpng1.6", target_id)

        policy["followUpAssessments"] = {}
        policy["packageEcosystem"] = "Untrusted:Canary"
        with self.assertRaisesRegex(ValueError, "valid package ecosystem"):
            package_target_policy(platform, "libpng1.6", target_id)

    def test_catalogue_matches_release_policy_without_claiming_public_downloads(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        catalogue = json.loads((ROOT / "site/catalogue.json").read_text())
        feed = json.loads((ROOT / "advisories/getpatched-osv.json").read_text())
        entries = {item["source"]: item for item in catalogue["packages"]}
        expected_catalogue = {
            source for source, record in platform["packages"].items()
            if any(target.get("candidateStatus", "").startswith("development-verified")
                   for target in record["targets"].values())
        }
        self.assertEqual(set(entries), expected_catalogue)
        self.assertEqual(expected_catalogue, {"libxml2", "libarchive", "libgit2", "poppler", "c-ares", "brotli", "expat", "tiff", "imagemagick"})
        self.assertIn("libpng1.6", set(platform["packages"]) - set(entries))
        self.assertNotIn("libgit2", set(platform["packages"]) - set(entries))
        self.assertIn("ubuntu-jammy-amd64", entries["libgit2"]["targets"])
        jammy = entries["libgit2"]["targets"]["ubuntu-jammy-amd64"]
        self.assertEqual(jammy["verification"], "https://github.com/getpatched/platform/actions/runs/41167536831")
        self.assertEqual(
            {patch["slug"] for patch in jammy["patches"]},
            {"cve-2026-53584-jammy", "cve-2026-53585-jammy", "cve-2026-53586-jammy"},
        )
        self.assertEqual(
            {vulnerability["slug"] for vulnerability in jammy["vulnerabilities"]},
            {"cve-2026-53584", "cve-2026-53585", "cve-2026-53586"},
        )
        self.assertNotIn("poppler", set(platform["packages"]) - set(entries))
        self.assertEqual(
            set(entries["expat"]["targets"]),
            {"debian-bookworm-amd64", "debian-trixie-amd64"},
        )
        self.assertEqual(catalogue["schemaVersion"], 3)
        libxml2_trixie = entries["libxml2"]["targets"]["debian-trixie-amd64"]
        self.assertEqual(
            libxml2_trixie["cves"],
            ["CVE-2026-6653", "CVE-2026-86144", "CVE-2026-76781", "CVE-2026-86141"],
        )
        self.assertEqual(libxml2_trixie["version"],
                         "2.12.7+dfsg+really2.9.14-2.1+deb13u3+getpatched4")
        self.assertEqual(libxml2_trixie["status"],
                         "development-verified-production-release-pending")
        self.assertEqual({item["slug"] for item in libxml2_trixie["vulnerabilities"]},
                         {"cve-2026-6653", "cve-2026-86144", "cve-2026-76781", "cve-2026-86141"})
        self.assertEqual({item["slug"] for item in libxml2_trixie["patches"]},
                         {"cve-2026-6653-debian", "cve-2026-86144-debian-trixie",
                          "cve-2026-76781-debian-trixie", "cve-2026-86141-debian-trixie"})
        self.assertEqual(libxml2_trixie["verification"],
                         "https://github.com/getpatched/platform/actions/runs/41690376263")
        libarchive_trixie = entries["libarchive"]["targets"]["debian-trixie-amd64"]
        self.assertEqual(libarchive_trixie["cves"], ["CVE-2026-16517"])
        self.assertEqual(libarchive_trixie["version"], "3.7.4-4+deb13u1+getpatched1")
        self.assertEqual({item["slug"] for item in libarchive_trixie["vulnerabilities"]},
                         {"cve-2026-16517"})
        self.assertEqual({item["slug"] for item in libarchive_trixie["patches"]},
                         {"cve-2026-16517-trixie"})
        imagemagick = entries["imagemagick"]["targets"]["debian-trixie-amd64"]
        imagemagick_policy = package_target_policy(platform, "imagemagick", "debian-trixie-amd64")
        self.assertEqual(imagemagick_policy["candidateStatus"],
                         "development-verified-production-release-pending")
        self.assertEqual(imagemagick["baseVersion"], imagemagick_policy["baselineVersion"])
        self.assertEqual(imagemagick["version"], imagemagick_policy["packageVersion"])
        self.assertEqual(imagemagick["cves"], ["CVE-2026-119124"])
        self.assertEqual(imagemagick["status"], imagemagick_policy["candidateStatus"])
        self.assertEqual(imagemagick["access"], "public")
        self.assertEqual(imagemagick["delayHours"], 0)
        self.assertEqual(imagemagick["verification"],
                         "https://github.com/getpatched/platform/actions/runs/41793654256")
        self.assertEqual(imagemagick["releaseStatus"], "No production release")
        self.assertEqual({item["slug"] for item in imagemagick["vulnerabilities"]},
                         {"cve-2026-119124"})
        self.assertEqual({item["slug"] for item in imagemagick["patches"]},
                         {"cve-2026-119124-trixie"})
        imagemagick_patch = imagemagick["patches"][0]
        self.assertEqual(imagemagick_patch["sha256"],
                         "088d417d715c83a15e4bd3ba7fdd41fc2a1d22e551b7b48c4d6cb02f962b8c4a")
        self.assertEqual(imagemagick_patch["upstream"]["commit"],
                         "270f70f609f659a01aaa2a8ed7bd887f79722d45")
        advisory = next(item for item in feed["vulns"] if item["id"] == "CVE-2026-119124")
        self.assertEqual(advisory["database_specific"]["verification_status"],
                         imagemagick_policy["candidateStatus"])
        self.assertEqual({item["package"]["name"] for item in advisory["affected"]},
                         {"libmagickcore-7.q16-10"})
        self.assertEqual(advisory["affected"][0]["versions"],
                         [imagemagick_policy["baselineVersion"]])
        self.assertEqual(advisory["affected"][0]["database_specific"]["candidate_version"],
                         imagemagick_policy["packageVersion"])
        cares_trixie = entries["c-ares"]["targets"]["debian-trixie-amd64"]
        self.assertEqual(cares_trixie["version"], "1.34.5-1+deb13u1+getpatched2")
        self.assertEqual(cares_trixie["cves"], ["CVE-2026-69184", "CVE-2026-69186"])
        self.assertEqual(cares_trixie["status"], "development-verified-sponsor-flow-pending")
        self.assertEqual(cares_trixie["verification"],
                         "https://github.com/getpatched/platform/actions/runs/41703193562")
        self.assertIn("cve-2026-69186", {v["slug"] for v in cares_trixie["vulnerabilities"]})
        self.assertIn("cve-2026-69186-record-count-allocation",
                      {p["slug"] for p in cares_trixie["patches"]})
        self.assertEqual(
            set(entries["tiff"]["targets"]),
            {"debian-bookworm-amd64", "debian-trixie-amd64"},
        )
        expected_tiff_cves = {
            "debian-bookworm-amd64": ["CVE-2025-61144", "CVE-2026-52490", "CVE-2026-12912", "CVE-2026-18495"],
            "debian-trixie-amd64": ["CVE-2025-61144", "CVE-2026-52490"],
        }
        for target_id, target in entries["tiff"]["targets"].items():
            self.assertEqual(target["cves"], expected_tiff_cves[target_id])
            self.assertEqual(
                {v["slug"] for v in target["vulnerabilities"]},
                {cve.lower() for cve in expected_tiff_cves[target_id]},
            )
            self.assertEqual(target["status"], "development-verified-production-release-pending")
        self.assertEqual(set(catalogue["targets"]), set(platform["targets"]))
        for target_id, target in platform["targets"].items():
            profile = target_profile(platform, target_id)
            self.assertEqual(catalogue["targets"][target_id]["codename"], profile["codename"])
            self.assertEqual(catalogue["targets"][target_id]["architecture"], profile["architecture"])
        for source, entry_package in entries.items():
            package = platform["packages"][source]
            expected_targets = {
                target_id for target_id, policy in package["targets"].items()
                if (policy.get("candidateStatus", "").startswith("development-verified")
                    or policy.get("verifiedReleases"))
            }
            self.assertEqual(set(entry_package["targets"]), expected_targets)
            for target_id, entry in entry_package["targets"].items():
                policy = package["targets"][target_id]
                access = policy["releaseAccess"]
                if policy.get("candidateStatus") == "unverified-development-candidate":
                    history = policy.get("verifiedReleases", [])
                    self.assertTrue(history)
                    prior = history[-1]
                    self.assertEqual(entry["version"], prior["version"])
                    self.assertEqual(entry["cves"], prior["targetCves"])
                    self.assertLess(debian_version_compare(entry["version"], policy["packageVersion"]), 0)
                    continue
                self.assertEqual(entry["version"], policy["packageVersion"])
                old_version = policy["baselineVersion"]
                self.assertLess(debian_version_compare(old_version, entry["version"]), 0)
                self.assertEqual(entry["cves"], policy["targetCves"])
                self.assertEqual(entry["delayHours"], access["sponsorDelayHours"])
                self.assertEqual(entry["access"], "sponsor" if access["sponsorDelayHours"] else "public")
                self.assertEqual(entry["sponsorEligibility"], access["sponsorEligibility"])
                if access["sponsorDelayHours"] == 168:
                    self.assertEqual(access["sponsorEligibility"], "any-active-individual-github-sponsorship-tier")
                self.assertEqual(entry["publicContributionSpdx"], "MIT")
                self.assertEqual(access["earlyUse"], ["private", "commercial"])
                self.assertFalse(access["earlyRedistributionAllowed"])
                self.assertEqual(access["publicLicenseScope"], "getpatched-authored-contributions-only")
                self.assertEqual(entry["earlyUse"], access["earlyUse"])
                self.assertEqual(entry["earlyRedistributionAllowed"], access["earlyRedistributionAllowed"])
                self.assertEqual(entry["earlyBinaryLicenseId"], access["earlyBinaryLicenseId"])
                self.assertEqual(entry["publicLicenseScope"], access["publicLicenseScope"])
                self.assertEqual(entry["earlyRedistributionAllowed"], False)
                self.assertEqual(entry["status"], policy["candidateStatus"])
                expected_run = {
                    ("libxml2", "ubuntu-focal-amd64"): "40899705050",
                    ("libxml2", "debian-bookworm-amd64"): "41575270372",
                    ("libxml2", "debian-trixie-amd64"): "41690376263",
                    ("libarchive", "ubuntu-focal-amd64"): "40899709850",
                    ("libarchive", "debian-trixie-amd64"): "41756486947",
                    ("libgit2", "ubuntu-focal-amd64"): "41162605227",
                    ("libgit2", "ubuntu-jammy-amd64"): "41167536831",
                    ("poppler", "ubuntu-focal-amd64"): "41149614570",
                    ("poppler", "debian-bookworm-amd64"): "41518910177",
                    ("poppler", "debian-trixie-amd64"): "41531130479",
                    ("c-ares", "ubuntu-focal-amd64"): "41492142682",
                    ("c-ares", "debian-trixie-amd64"): "41703193562",
                    ("brotli", "ubuntu-focal-amd64"): "41492184315",
                    ("expat", "debian-bookworm-amd64"): "41543751522",
                    ("expat", "debian-trixie-amd64"): "41546270294",
                    ("tiff", "debian-bookworm-amd64"): "41604393283",
                    ("tiff", "debian-trixie-amd64"): "41554198692",
                    ("imagemagick", "debian-trixie-amd64"): "41793654256",
                }[(source, target_id)]
                self.assertEqual(entry["verification"], f"https://github.com/getpatched/platform/actions/runs/{expected_run}")
                self.assertEqual(
                    entry.get("ubuntuProEsmCompatibility", "not-applicable" if target_id.startswith("debian-") else "not-tested-out-of-scope"),
                    policy.get("ubuntuProEsmCompatibility", "not-applicable" if target_id.startswith("debian-") else "not-tested-out-of-scope"),
                )
                self.assertNotIn("verificationUrl", entry)
                self.assertTrue(entry["sourceUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/tree/"))
                self.assertTrue(entry["patchUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/blob/"))
                branch = target_profile(platform, target_id)["sourceBranch"]
                if source == "tiff" and target_id in {"debian-bookworm-amd64", "debian-trixie-amd64"}:
                    patch_file = "CVE-2026-18495.patch" if target_id == "debian-bookworm-amd64" else "CVE-2026-52490-trixie.patch"
                    expected_branch = "getpatched/debian-bookworm" if target_id == "debian-bookworm-amd64" else "getpatched/debian-trixie"
                    self.assertEqual(entry["patchUrl"], f"https://github.com/getpatched/packaging-tiff/blob/{expected_branch}/patches/{patch_file}")
                    self.assertEqual(entry["testsUrl"], f"https://github.com/getpatched/packaging-tiff/blob/{expected_branch}/patches/metadata.json")
                else:
                    self.assertEqual(entry["testsUrl"], f"https://github.com/getpatched/packaging-{source}/tree/{branch}/tests")
                self.assertEqual(entry["releasesUrl"], f"https://github.com/getpatched/packaging-{source}/releases")
                if policy["candidateStatus"] == "development-verified-sponsor-flow-pending":
                    self.assertEqual(entry["releaseStatus"], "No production release; sponsor flow verification pending")
                else:
                    self.assertEqual(entry["releaseStatus"], "No production release")

        page = (ROOT / "site/index.html").read_text()
        self.assertIn("Hosted development verification passed.", page)
        self.assertIn("Six Focal candidates, two Debian Expat targets, two Debian libxml2 targets, one Debian Trixie c-ares target, two Debian Poppler targets, one Jammy libgit2 target and two Debian TIFF targets have hosted builds", page)
        self.assertIn("Live package publication and downloads remain disabled", page)
        self.assertIn("no production package release has been published", page)
        self.assertIn("Hosted development verification has passed for six Focal candidates, two Debian Expat targets, two Debian libxml2 targets", page)
        self.assertIn("Ubuntu Pro/ESM compatibility is not tested or supported", page)
        self.assertIn("Each row links to its source, patch, regression tests and release history", page)
        self.assertIn("Any sponsor delay starts only after sponsor publication", page)
        self.assertIn("temporary signed APT client smoke test", page)
        app = (ROOT / "site/catalogue.js").read_text()
        self.assertIn("Hosted build, CVE scans, installed regressions and signed-client checks required", app)
        self.assertIn("Development checks passed", app)
        self.assertNotIn("item.verificationUrl", app)
        for label in ("Source", "Patch", "Tests", "Releases"):
            self.assertIn(f">{label} ↗</a>", app)
        for field in ("patchUrl", "testsUrl", "releasesUrl", "releaseStatus"):
            self.assertIn(f"item.{field}", app)
        self.assertIn("Any active individual GitHub Sponsors tier, no minimum · public ${escapeHtml(item.delayHours)} hours later", app)
        self.assertNotIn("Public 168 hours after sponsor release", app)
        self.assertIn("open the public package source repositories on GitHub", page)
        self.assertNotIn("browse the public package repositories directly", page)
        self.assertIn('all: packages.length', app)
        self.assertIn('sponsor: packages.filter((item) => item.access === "sponsor").length', app)
        self.assertIn('public: packages.filter((item) => item.access === "public").length', app)
        self.assertNotIn('"02"', page)
        self.assertNotIn('"01"', page)


if __name__ == "__main__":
    unittest.main()
