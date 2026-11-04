"""Protect classification of the real focal Schematron baseline crash."""
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from regression import (imagemagick_cdl_check_succeeded, imagemagick_morph_check_succeeded, LIBPNG_CVE_2025_65018_FIXTURE, pixarlog_baseline_reproduced, pixarlog_patched_succeeded, libpng_followup_read_is_clean, libpng_output_buffer_result, libpng_overwrite_reproduced, libpng_stride_read_reproduced, memcheck_has_no_errors,
                        libpng_patched_checks_succeeded, tiff_patched_regression_succeeded,
                        brotli_baseline_reproduced, brotli_patched_succeeded,
                        cares_record_count_regression_succeeded, cares_regression_succeeded,
                        msgpack_unpacker_reuse_regression_succeeded,
                        massif_peak_heap_bytes,
                        consumer_version_succeeded, expat_consumer_succeeded, expat_regression_succeeded,
                        libxml2_catalog_baseline_reproduced, libxml2_catalog_patched_succeeded,
                        libxml2_regexp_alloc_failure_baseline_reproduced,
                        libxml2_regexp_alloc_failure_patched_succeeded,
                        libxml2_check_cardinality_valid,
                        libxml2_parameter_entity_baseline_reproduced, libxml2_parameter_entity_patched_succeeded,
                        libxml2_xinclude_nonet_result, libxml2_xinclude_checks_succeeded,
                        poppler_uaf_reproduced, schematron_baseline_reproduced,
                        validate_recipe_regression_fixture_hashes,

cares_regression_succeeded, consumer_version_succeeded, poppler_revision6_password_overflow_reproduced, poppler_uaf_reproduced, poppler_revision6_probe_command, schematron_baseline_reproduced,
                        tiff_baseline_reproduced, tiff_null_output_baseline_reproduced,
                        tiff_null_output_patched_succeeded, parse_callback_url,
                        libgit2_redirect_reproduced, tiff_cve_required,
                        tiff_bigstrip_baseline_reproduced, tiff_bigstrip_patched_succeeded,
                        tiff_subdivision_baseline_reproduced, tiff_subdivision_patched_succeeded, execute)


class PythonMsgpackRegression(unittest.TestCase):
    def test_accepts_only_reproduced_segfault_and_clean_patched_reuse(self):
        base = {
            "cve": "CVE-2026-57585",
            "testId": "python-msgpack-unpacker-error-reuse",
            "timedOut": False,
            "command": ["python3", "/recipe/tests/fixtures/cve-2026-57585-unpacker-reuse.py"],
        }
        identity = (
            "module_path=/usr/lib/python3/dist-packages/msgpack/__init__.py\n"
            "debian_package=python3-msgpack\n"
            "module_owner=python3-msgpack\n"
        )
        baseline = {
            **base,
            "returncode": -signal.SIGSEGV,
            "stdout": identity + "debian_package_version=1.0.3-2+b1\n"
            "caught expected ValueError\n",
        }
        self.assertTrue(msgpack_unpacker_reuse_regression_succeeded(
            baseline, "debian-bookworm-amd64", "baseline", "1.0.3-2+b1"
        ))
        self.assertFalse(msgpack_unpacker_reuse_regression_succeeded(
            {**baseline, "returncode": 0}, "debian-bookworm-amd64", "baseline", "1.0.3-2+b1"
        ))
        patched = {
            **base,
            "returncode": 0,
            "stdout": identity + "debian_package_version=1.0.3-3+getpatched1\n"
            "caught expected ValueError\nafter-error skip completed without process crash\n",
        }
        self.assertTrue(msgpack_unpacker_reuse_regression_succeeded(
            patched, "debian-trixie-amd64", "patched", "1.0.3-3+getpatched1"
        ))
        self.assertFalse(msgpack_unpacker_reuse_regression_succeeded(
            {**patched, "command": ["python3", "/tmp/other.py"]},
            "debian-trixie-amd64", "patched", "1.0.3-3+getpatched1"
        ))
        self.assertFalse(msgpack_unpacker_reuse_regression_succeeded(
            patched, "debian-trixie-amd64", "patched", "1.0.3-3+getpatched2"
        ))
        self.assertFalse(msgpack_unpacker_reuse_regression_succeeded(
            {**patched, "stdout": patched["stdout"].replace(
                "/usr/lib/python3/dist-packages/msgpack/", "/usr/local/lib/python3/dist-packages/msgpack/"
            )},
            "debian-trixie-amd64", "patched", "1.0.3-3+getpatched1"
        ))


class Libxml2ParameterEntityRegression(unittest.TestCase):
    def test_catalog_missing_attribute_regression_classifier(self):
        log_path = "/tmp/cve-2026-76781.valgrind"
        base = {
            "cve": "CVE-2026-76781",
            "timedOut": False,
            "memoryLogPath": log_path,
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + log_path,
                "/tmp/libxml2-cve-2026-76781", "/recipe/tests/fixtures/cve-2026-76781-catalog.xml",
            ],
        }
        baseline = {
            **base,
            "returncode": -11,
            "memoryLog": (
                "==123== Invalid read of size 8\n"
                "==123==    at 0x123: ??? (in /usr/lib/libxml2.so.2.9.14)\n"
                "==123==    by 0x456: xmlCatalogResolveSystem (in /usr/lib/libxml2.so.2.9.14)\n"
                "==123==  Address 0x30 is not stack'd, malloc'd or (recently) free'd\n"
                "==123== Process terminating with default action of signal 11 (SIGSEGV)\n"
                "==123== ERROR SUMMARY: 1 errors from 1 contexts\n"
            ),
        }
        patched = {**base, "returncode": 0, "memoryLog": "==123== ERROR SUMMARY: 0 errors from 0 contexts\n"}
        self.assertTrue(libxml2_catalog_baseline_reproduced(baseline))
        self.assertFalse(libxml2_catalog_baseline_reproduced({**baseline, "memoryLog": ""}))
        self.assertFalse(libxml2_catalog_baseline_reproduced({
            **baseline,
            "memoryLog": baseline["memoryLog"].replace("Address 0x30", "Address 0x38"),
        }))
        self.assertFalse(libxml2_catalog_baseline_reproduced({
            **baseline,
            "memoryLog": baseline["memoryLog"].replace("xmlCatalogResolveSystem", "unrelated"),
        }))
        self.assertTrue(libxml2_catalog_patched_succeeded(patched))
        self.assertFalse(libxml2_catalog_patched_succeeded({**patched, "returncode": 97}))

    def test_libxml2_report_cardinality_requires_one_check_per_cve_and_both_xinclude_apis(self):
        target = ["CVE-2026-6653", "CVE-2026-86144", "CVE-2026-76781", "CVE-2026-86141"]
        checks = [
            {"cve": "CVE-2026-6653"},
            {"cve": "CVE-2026-86144", "testId": "document"},
            {"cve": "CVE-2026-86144", "testId": "tree"},
            {"cve": "CVE-2026-76781"},
            {"cve": "CVE-2026-86141"},
        ]
        self.assertTrue(libxml2_check_cardinality_valid(checks, target))
        self.assertFalse(libxml2_check_cardinality_valid(checks[:-1], target))
        self.assertFalse(libxml2_check_cardinality_valid(checks + [checks[0]], target))

    def test_regexp_allocation_failure_classifier_requires_crash_or_clean_rejection(self):
        log_path = "/tmp/cve-2026-86141.valgrind"
        memory_log = (
            "==123== Invalid read of size 1\n"
            "==123==    at 0x123: ??? (in /usr/lib/libxml2.so.2.9.14)\n"
            "==123==    by 0x456: ??? (in /usr/lib/libxml2.so.2.9.14)\n"
            "==123==    by 0x789: xmlRegexpCompile (in /usr/lib/libxml2.so.2.9.14)\n"
            "==123==  Address 0x0 is not stack'd, malloc'd or (recently) free'd\n"
            "==123== Process terminating with default action of signal 11 (SIGSEGV)\n"
            "==123== ERROR SUMMARY: 1 errors from 1 contexts\n"
        )
        baseline = {
            "cve": "CVE-2026-86141",
            "testId": "regexp-allocation-failure-null-check",
            "timedOut": False,
            "returncode": 97,
            "command": [
                "/usr/bin/valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + log_path,
                "/tmp/libxml2-cve-2026-86141",
            ],
            "injection": "xmlMemSetup:test_malloc:sizeof-regexp",
            "stderr": "GETPATCHED_REGEXP_COPY_ALLOCATION_FAILURE_INJECTED\n",
            "memoryLogPath": log_path,
            "memoryLog": memory_log,
        }
        self.assertTrue(libxml2_regexp_alloc_failure_baseline_reproduced(baseline))
        self.assertTrue(libxml2_regexp_alloc_failure_baseline_reproduced({
            **baseline, "returncode": -signal.SIGSEGV
        }))
        self.assertFalse(libxml2_regexp_alloc_failure_baseline_reproduced({**baseline, "returncode": 0}))
        self.assertFalse(libxml2_regexp_alloc_failure_baseline_reproduced({
            **baseline, "stderr": "unrelated crash\n"
        }))
        self.assertFalse(libxml2_regexp_alloc_failure_baseline_reproduced({
            **baseline, "memoryLog": memory_log.replace("xmlRegexpCompile", "unrelated_crash")
        }))
        patched = {
            **baseline,
            "returncode": 0,
            "stdout": "XML_REGEXP_COMPILE_REJECTED_ALLOCATION_FAILURE\n",
            "memoryLog": "==123== ERROR SUMMARY: 0 errors from 0 contexts\n",
        }
        self.assertTrue(libxml2_regexp_alloc_failure_patched_succeeded(patched))
        self.assertFalse(libxml2_regexp_alloc_failure_patched_succeeded({
            **patched, "stdout": ""
        }))

    def test_xinclude_scanner_requires_one_passing_result_per_api(self):
        def check(api, mode, returncode):
            return {
                "cve": "CVE-2026-86144",
                "timedOut": False,
                "returncode": returncode,
                "command": ["/tmp/libxml2-cve-2026-86144", "/recipe/tests/fixtures/cve-2026-86144-xinclude.xml", api, mode],
            }

        baseline = [check("document", "expect-network", 10), check("tree", "expect-network", 10)]
        patched = [check("document", "expect-blocked", 0), check("tree", "expect-blocked", 0)]
        self.assertTrue(libxml2_xinclude_checks_succeeded(baseline, "baseline"))
        self.assertTrue(libxml2_xinclude_checks_succeeded(patched, "patched"))
        self.assertFalse(libxml2_xinclude_checks_succeeded([check("document", "expect-blocked", 10), patched[1]], "patched"))
        self.assertFalse(libxml2_xinclude_checks_succeeded(patched[:1], "patched"))
        self.assertFalse(libxml2_xinclude_checks_succeeded([patched[0], patched[0]], "patched"))

    def test_xinclude_nonet_classifier_requires_expected_behavior(self):
        baseline = {
            "timedOut": False,
            "command": ["/tmp/libxml2-cve-2026-86144", "/recipe/tests/fixtures/cve-2026-86144-xinclude.xml", "document", "expect-network"],
            "returncode": 10,
        }
        self.assertTrue(libxml2_xinclude_nonet_result(baseline, "baseline"))
        self.assertFalse(libxml2_xinclude_nonet_result({**baseline, "returncode": 0}, "baseline"))
        patched = {**baseline, "command": [*baseline["command"][:-1], "expect-blocked"], "returncode": 0}
        self.assertTrue(libxml2_xinclude_nonet_result(patched, "patched"))
        self.assertFalse(libxml2_xinclude_nonet_result({**patched, "returncode": 10}, "patched"))

    def test_baseline_requires_invalid_read_after_entity_stream_is_freed(self):
        log_path = "/tmp/cve-2026-6653.valgrind"
        check = {
            "cve": "CVE-2026-6653",
            "returncode": 97,
            "timedOut": False,
            "memoryLogPath": log_path,
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + log_path,
                "/tmp/libxml2-cve-2026-6653", "/recipe/tests/fixtures/cve-2026-6653.xml",
            ],
            "memoryLog": (
                "==123== Invalid read of size 8\n"
                "==123==    at 0x123: ??? (in /usr/lib/libxml2.so.2)\n"
                "==123==    by 0x456: xmlReadMemory (in /usr/lib/libxml2.so.2)\n"
                "==123== Address 0x1 is 0 bytes inside a block of size 32 free'd\n"
                "==123==  Block was alloc'd at\n"
                "==123==    at 0x789: xmlNewEntityInputStream (in /usr/lib/libxml2.so.2)\n"
                "==123== ERROR SUMMARY: 1 errors from 1 contexts\n"
            ),
        }
        self.assertTrue(libxml2_parameter_entity_baseline_reproduced(check))
        self.assertFalse(libxml2_parameter_entity_baseline_reproduced({**check, "returncode": 0}))
        self.assertFalse(libxml2_parameter_entity_baseline_reproduced({
            **check, "memoryLog": (
                check["memoryLog"].replace("xmlNewEntityInputStream", "unrelated")
                + "==123== Invalid write of size 1\n"
                + "==123==    at 0xAAA: xmlNewEntityInputStream (in /usr/lib/libxml2.so.2)\n"
                + "==123== ERROR SUMMARY: 1 errors from 1 contexts\n"
            )
        }))

    def test_regression_runner_rejects_modified_hash_declared_fixtures(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-regression-fixture-hash-") as directory:
            root = Path(directory)
            fixture = root / "tests/fixtures/cve.xml"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("<root/>")
            import hashlib
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
            metadata = root / "patches/metadata.json"
            metadata.parent.mkdir()
            metadata.write_text(json.dumps({"patches": [{"referenceFiles": [], "tests": [{
                "fixtures": [{"path": "tests/fixtures/cve.xml", "sha256": digest}]
            }]}]}))
            manifest = {"patchMetadata": "patches/metadata.json"}
            validate_recipe_regression_fixture_hashes(root, manifest)
            fixture.write_text("<modified/>")
            with self.assertRaisesRegex(RuntimeError, "fixture hash does not match"):
                validate_recipe_regression_fixture_hashes(root, manifest)

    def test_patched_requires_clean_memcheck_for_same_probe(self):
        log_path = "/tmp/cve-2026-6653.valgrind"
        check = {
            "cve": "CVE-2026-6653",
            "returncode": 0,
            "timedOut": False,
            "memoryLogPath": log_path,
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + log_path,
                "/tmp/libxml2-cve-2026-6653", "/recipe/tests/fixtures/cve-2026-6653.xml",
            ],
            "memoryLog": "==123== ERROR SUMMARY: 0 errors from 0 contexts\n",
        }
        self.assertTrue(libxml2_parameter_entity_patched_succeeded(check))
        self.assertFalse(libxml2_parameter_entity_patched_succeeded({
            **check, "memoryLog": "==123== Invalid read of size 8\n==123== ERROR SUMMARY: 1 errors\n"
        }))


class ImageMagickMorphRegression(unittest.TestCase):
    def check(self, log, rc, frames=None):
        version = "8:7.1.1.43+dfsg1-1+deb13u13"
        report = {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--track-origins=yes", "--log-file=/tmp/CVE-2026-119124.valgrind",
                        "/usr/bin/magick", "/recipe/tests/fixtures/first-graya.png",
                        "/recipe/tests/fixtures/second-srgb.png", "-morph", "1", "/tmp/morph.miff"],
            "returncode": rc, "timedOut": False, "memoryLog": log,
            "memoryLogPath": "/tmp/CVE-2026-119124.valgrind",
            "cve": "CVE-2026-119124", "testId": "imagemagick-morph-channel-bounds",
            "expectedPackageVersion": version,
            "installedPackageVersions": {
                name: version for name in ("imagemagick-7.q16", "libmagickcore-7.q16-10", "libmagickwand-7.q16-10")
            },
            "magickBinaryOwner": "imagemagick-7.q16",
            "magickBinaryPath": "/usr/bin/magick-im7.q16",
        }
        if frames is not None:
            report["outputFrames"] = frames
            report["outputInspectReturncode"] = 0
        return report

    def test_baseline_requires_invalid_write_stack_to_include_morphimages(self):
        log = ("==1== Invalid write of size 4\n==1==    by 0x123: MorphImages (visual-effects.c:1)\n"
               "==1==  Address 0x100 is 0 bytes after a block of size 16 alloc'd\n"
               "==1== ERROR SUMMARY: 1 errors from 1 contexts\n")
        self.assertTrue(imagemagick_morph_check_succeeded(self.check(log, 97), "baseline"))
        unrelated = ("==1== Invalid write of size 4\n==1==    by 0x123: unrelated_function (other.c:1)\n"
                     "==1== ERROR SUMMARY: 1 errors from 1 contexts\n==1== MorphImages was mentioned elsewhere\n")
        self.assertFalse(imagemagick_morph_check_succeeded(self.check(unrelated, 97), "baseline"))
        without_bounds_evidence = log.replace(
            "==1==  Address 0x100 is 0 bytes after a block of size 16 alloc'd\n", ""
        )
        self.assertFalse(imagemagick_morph_check_succeeded(
            self.check(without_bounds_evidence, 97), "baseline"
        ))
        unprefixed_address = log.replace(
            "==1==  Address 0x100 is 0 bytes after a block of size 16 alloc'd\n",
            "==1==\nAddress 0x100 is 0 bytes after a block of size 16 alloc'd\n",
        )
        self.assertFalse(imagemagick_morph_check_succeeded(
            self.check(unprefixed_address, 97), "baseline"
        ))

    def test_patched_requires_three_frames_and_clean_memcheck(self):
        clean = "==1== ERROR SUMMARY: 0 errors from 0 contexts\n"
        self.assertTrue(imagemagick_morph_check_succeeded(self.check(clean, 0, 3), "patched"))
        self.assertFalse(imagemagick_morph_check_succeeded(self.check(clean, 0, 2), "patched"))


class ImageMagickCdlRegression(unittest.TestCase):
    def check(self, phase):
        version = "8:7.1.1.43+dfsg1-1+deb13u13" + ("+getpatched2" if phase == "patched" else "")
        leaked = "==1== definitely lost: 16 bytes in 1 blocks\n==1== ERROR SUMMARY: 1 errors from 1 contexts\n"
        clean = "==1== definitely lost: 0 bytes in 0 blocks\n==1== ERROR SUMMARY: 0 errors from 0 contexts\n"
        return {
            "cve": "CVE-2026-116159", "testId": "imagemagick-cdl-memory-release",
            "expectedPackageVersion": version,
            "installedPackageVersions": {name: version for name in (
                "imagemagick-7.q16", "libmagickcore-7.q16-10", "libmagickwand-7.q16-10")},
            "magickBinaryOwner": "imagemagick-7.q16",
            "subchecks": [{
                "testId": test_id,
                "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=full",
                            "--show-leak-kinds=definite", "--errors-for-leak-kinds=definite",
                            "--log-file=/tmp/test.valgrind", binary, "-cdl",
                            "/recipe/tests/fixtures/cve-2026-116159.cdl.xml",
                            "/recipe/tests/fixtures/cve-2026-116159-input.ppm"],
                "returncode": 0 if phase == "patched" else 97,
                "timedOut": False, "memoryLog": clean if phase == "patched" else leaked,
                "outputInspectReturncode": 0,
            } for test_id, binary in (("imagemagick-cdl-cli", "/usr/bin/magick"),
                                      ("imagemagick-cdl-mogrify", "/usr/bin/mogrify"))],
        }

    def test_requires_leak_in_both_baseline_entry_points(self):
        self.assertTrue(imagemagick_cdl_check_succeeded(self.check("baseline"), "baseline"))
        missing_second_leak = self.check("baseline")
        missing_second_leak["subchecks"][1]["memoryLog"] = (
            "==1== definitely lost: 0 bytes in 0 blocks\n==1== ERROR SUMMARY: 0 errors from 0 contexts\n")
        missing_second_leak["subchecks"][1]["returncode"] = 0
        self.assertFalse(imagemagick_cdl_check_succeeded(missing_second_leak, "baseline"))

    def test_requires_both_patched_entry_points_to_be_memcheck_clean(self):
        self.assertTrue(imagemagick_cdl_check_succeeded(self.check("patched"), "patched"))
        regressed = self.check("patched")
        regressed["subchecks"][0]["memoryLog"] = (
            "==1== definitely lost: 16 bytes in 1 blocks\n==1== ERROR SUMMARY: 1 errors from 1 contexts\n")
        self.assertFalse(imagemagick_cdl_check_succeeded(regressed, "patched"))


class TiffPolicySelection(unittest.TestCase):
    def test_only_configured_target_cves_require_installed_checks(self):
        policy = {"targetCves": ["CVE-2025-61144"]}
        self.assertTrue(tiff_cve_required(policy, "CVE-2025-61144"))
        self.assertTrue(tiff_cve_required({"targetCves": ["CVE-2026-52490"]}, "CVE-2026-52490"))
        self.assertFalse(tiff_cve_required(policy, "CVE-2025-61143"))
        self.assertFalse(tiff_cve_required({}, "CVE-2025-61143"))
        self.assertFalse(tiff_cve_required({"targetCves": "CVE-2025-61143"}, "CVE-2025-61143"))


class ExpatRegressionEvidence(unittest.TestCase):
    def test_only_exact_sigsegv_is_accepted_for_vulnerable_baseline(self):
        check = {"cve": "CVE-2026-117610", "testId": "CVE-2026-117610-empty-nonfinal-subparser",
                 "returncode": -signal.SIGSEGV, "timedOut": False}
        self.assertTrue(expat_regression_succeeded(check, "baseline"))
        self.assertFalse(expat_regression_succeeded({**check, "returncode": 139}, "baseline"))
        self.assertFalse(expat_regression_succeeded({**check, "returncode": -signal.SIGABRT}, "baseline"))
        self.assertFalse(expat_regression_succeeded({**check, "timedOut": True}, "baseline"))
        self.assertFalse(expat_regression_succeeded({**check, "cve": "CVE-2026-999999"}, "baseline"))

    def test_consumer_version_check_accepts_only_the_matching_installed_version(self):
        consumer = {"testId": "expat-xmlwf-version", "returncode": 0, "timedOut": False,
                    "stdout": "xmlwf using expat_2.5.0\n"}
        self.assertTrue(expat_consumer_succeeded(consumer, "2.5.0"))
        self.assertFalse(expat_consumer_succeeded(consumer, "2.9.0"))

    def test_patched_probe_and_matching_xmlwf_consumer_are_required(self):
        probe = {"cve": "CVE-2026-117610", "testId": "CVE-2026-117610-empty-nonfinal-subparser",
                 "returncode": 0, "timedOut": False}
        self.assertTrue(expat_regression_succeeded(probe, "patched"))
        consumer = {"testId": "expat-xmlwf-version", "returncode": 0, "timedOut": False,
                    "stdout": "xmlwf using expat_2.5.0\n"}
        self.assertTrue(expat_consumer_succeeded(consumer, "2.5.0"))
        self.assertFalse(expat_consumer_succeeded({**consumer, "timedOut": True}, "2.5.0"))


class TiffSubdivisionOverflowRegression(unittest.TestCase):
    command = ["tiffcrop", "-S", "134217729:32", "-h"]

    def test_exact_baseline_accepts_wrapped_count_and_prints_help(self):
        check = {
            "cve": "CVE-2026-52490", "testId": "tiffcrop-subdivision-overflow-check",
            "command": self.command, "returncode": 0, "timedOut": False,
            "stdout": "TIFF 4.5.0\\nusage: tiffcrop [options] source1 destination\\n", "stderr": "",
        }
        self.assertTrue(tiff_subdivision_baseline_reproduced(check))
        self.assertFalse(tiff_subdivision_baseline_reproduced({**check, "command": [*self.command, "extra"]}))
        self.assertFalse(tiff_subdivision_baseline_reproduced({**check, "stdout": "usage missing"}))
        self.assertFalse(tiff_subdivision_baseline_reproduced({**check, "timedOut": True}))

    def test_patched_package_rejects_wrapped_count_before_help(self):
        check = {
            "cve": "CVE-2026-52490", "testId": "tiffcrop-subdivision-overflow-check",
            "command": self.command, "returncode": 1, "timedOut": False,
            "stdout": "", "stderr": "Limit for subdivisions, ie rows x columns, exceeded: 32\\n",
        }
        self.assertTrue(tiff_subdivision_patched_succeeded(check))
        self.assertFalse(tiff_subdivision_patched_succeeded({**check, "returncode": 0}))
        self.assertFalse(tiff_subdivision_patched_succeeded({**check, "stderr": "usage: tiffcrop"}))
        self.assertFalse(tiff_subdivision_patched_succeeded({**check, "command": ["other"]}))


class CaresTargetRegression(unittest.TestCase):
    def test_massif_peak_parser_returns_largest_heap_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-cares-massif-") as directory:
            path = Path(directory) / "massif.out"
            path.write_text("mem_heap_B=128\nmem_heap_B=16777216\nmem_heap_B=4096\n")
            self.assertEqual(massif_peak_heap_bytes(path), 16 * 1024 * 1024)
            path.write_text("no heap snapshots\n")
            self.assertIsNone(massif_peak_heap_bytes(path))

    def test_focal_requires_overlong_name_reproduction_and_valid_boundary(self):
        baseline = {
            "cve": "CVE-2026-69184", "testId": "c-ares-overlong-expanded-name-focal",
            "returncode": 0, "timedOut": False, "vulnerabilityReproduced": True,
            "stdout": "overlong_status=0 rejected=no\nmaximum_name_accepted=yes\n",
        }
        patched = {
            **baseline, "vulnerabilityReproduced": False, "patchedBehavior": True,
            "stdout": "overlong_status=8 rejected=yes\nmaximum_name_accepted=yes\n",
        }
        self.assertTrue(cares_regression_succeeded(baseline, "ubuntu-focal-amd64", "baseline"))
        self.assertTrue(cares_regression_succeeded(patched, "ubuntu-focal-amd64", "patched"))
        self.assertFalse(cares_regression_succeeded({**patched, "stdout": "overlong_status=8 rejected=yes\n"}, "ubuntu-focal-amd64", "patched"))
        self.assertFalse(cares_regression_succeeded(baseline, "debian-trixie-amd64", "baseline"))

    def test_trixie_requires_pointer_chain_reproduction_and_valid_record(self):
        check = {
            "cve": "CVE-2026-69184", "testId": "c-ares-unbounded-pointer-chain",
            "returncode": 0, "timedOut": False, "vulnerabilityReproduced": True,
            "stdout": "status=0 record=present\nvalid_status=0 valid_record=present\n",
        }
        self.assertTrue(cares_regression_succeeded(check, "debian-trixie-amd64", "baseline"))
        self.assertFalse(cares_regression_succeeded(check, "ubuntu-focal-amd64", "baseline"))

    def test_trixie_record_count_requires_large_baseline_heap_and_small_patched_heap(self):
        base = {
            "cve": "CVE-2026-69186",
            "testId": "c-ares-malformed-record-count-allocation",
            "command": [
                "valgrind", "--tool=massif", "--time-unit=B", "--stacks=no",
                "--massif-out-file=/tmp/c-ares-record-count.massif",
                "/tmp/c-ares-record-count",
            ],
            "returncode": 0,
            "timedOut": False,
            "stdout": "malformed_rejected=yes\nvalid_status=0 valid_record=present\n",
        }
        baseline = {
            **base,
            "peakHeapBytes": 16 * 1024 * 1024,
            "vulnerabilityReproduced": True,
        }
        patched = {
            **base,
            "peakHeapBytes": 1024 * 1024,
            "patchedBehavior": True,
        }
        self.assertTrue(cares_record_count_regression_succeeded(
            baseline, "debian-trixie-amd64", "baseline"
        ))
        self.assertTrue(cares_record_count_regression_succeeded(
            patched, "debian-trixie-amd64", "patched"
        ))
        self.assertFalse(cares_record_count_regression_succeeded(
            {**baseline, "peakHeapBytes": 1024 * 1024},
            "debian-trixie-amd64", "baseline"
        ))
        self.assertFalse(cares_record_count_regression_succeeded(
            {**patched, "peakHeapBytes": 16 * 1024 * 1024},
            "debian-trixie-amd64", "patched"
        ))
        self.assertFalse(cares_record_count_regression_succeeded(
            baseline, "ubuntu-focal-amd64", "baseline"
        ))


class BrotliRegression(unittest.TestCase):
    def test_baseline_requires_the_block_length_error_after_16_mib_signature(self):
        check = {
            "cve": "CVE-2026-111497", "testId": "brotli-invalid-block-switch",
            "timedOut": False, "returncode": 0, "decoderResult": 0,
            "decoderError": -9, "formatBlockSwitchError": -17,
            "inputRemaining": 3, "decoderOutputBytes": 16 * 1024 * 1024,
            "decoderCalls": 4096,
            "normalStreamCompatible": True,
        }
        self.assertTrue(brotli_baseline_reproduced(check))
        self.assertFalse(brotli_baseline_reproduced({**check, "decoderError": -15}))
        self.assertFalse(brotli_baseline_reproduced({**check, "decoderOutputBytes": 4096}))
        self.assertFalse(brotli_baseline_reproduced({**check, "decoderResult": 3}))

    def test_patched_requires_the_specific_format_error_and_compatibility(self):
        check = {
            "cve": "CVE-2026-111497", "testId": "brotli-invalid-block-switch",
            "timedOut": False, "returncode": 0, "decoderResult": 0,
            "decoderError": -17, "formatBlockSwitchError": -17,
            "decoderOutputBytes": 16 * 1024 * 1024, "decoderCalls": 4096,
            "normalStreamCompatible": True,
        }
        self.assertTrue(brotli_patched_succeeded(check))
        self.assertFalse(brotli_patched_succeeded({**check, "decoderResult": 3}))
        self.assertFalse(brotli_patched_succeeded({**check, "normalStreamCompatible": False}))
        self.assertFalse(brotli_patched_succeeded({**check, "decoderOutputBytes": 33 * 1024 * 1024}))
        self.assertFalse(brotli_patched_succeeded({**check, "decoderCalls": 8193}))
        self.assertFalse(brotli_patched_succeeded({key: value for key, value in check.items() if key != "decoderOutputBytes"}))


class PixarLogCVERegressionClassification(unittest.TestCase):
    def fixture(self, patched):
        root = Path("/tmp/pixarlog-probe")
        log = "==123== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n"
        result = -1 if patched else 24576
        return {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes", f"--log-file={root / 'CVE-2026-12912.valgrind'}",
                        str(root / "pixarlog-abgr"), "decode", str(root / "pixarlog-abgr.tif")],
            "cve": "CVE-2026-12912", "testId": "pixarlog-abgr-rgb-multirow-strip-overflow",
            "returncode": 0 if patched else 97, "timedOut": False,
            "stdout": f"decode_called=1 result={result} strip_size=24576\n",
            "stderr": "Output buffer too small for PixarLog ABGR data" if patched else "",
            "memoryLog": log if patched else (
                "==123== Invalid write of size 1\n"
                "==123==    at 0x123: ??? (in /usr/lib/x86_64-linux-gnu/libtiff.so.6.4.0)\n"
                "==123== ERROR SUMMARY: 8192 errors from 1 contexts\n"),
        }

    def test_baseline_requires_invalid_write_in_the_exact_multirow_probe(self):
        result = pixarlog_baseline_reproduced(self.fixture(False))
        self.assertIs(type(result), bool)
        self.assertTrue(result)
        check = self.fixture(False)
        check["command"][7] = "generate"
        self.assertFalse(pixarlog_baseline_reproduced(check))
        check = self.fixture(False)
        check["memoryLog"] = "==123== ERROR SUMMARY: 0 errors from 0 contexts\n"
        self.assertFalse(pixarlog_baseline_reproduced(check))

    def test_candidate_must_reject_the_strip_buffer_and_have_zero_memcheck_errors(self):
        self.assertTrue(pixarlog_patched_succeeded(self.fixture(True)))
        check = self.fixture(True)
        check["stderr"] = ""
        self.assertFalse(pixarlog_patched_succeeded(check))
        check = self.fixture(True)
        check["memoryLog"] = "==123== Invalid write of size 1\n==123== ERROR SUMMARY: 1 errors\n"
        self.assertFalse(pixarlog_patched_succeeded(check))


class ExecuteTimeout(unittest.TestCase):
    def test_timeout_preserves_partial_output(self):
        result = execute([
            sys.executable, "-c",
            "import time; print('partial output', flush=True); time.sleep(1)",
        ], timeout=0.05)
        self.assertTrue(result["timedOut"])
        self.assertIsNone(result["returncode"])
        self.assertIsInstance(result["stdout"], str)


def libpng_memcheck(test_id, executable, arguments, cve, returncode=0,
                    memory_log="==123== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n"):
    root = Path("/tmp/getpatched-regression-fixture")
    return {
        "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", f"--log-file={root / (executable + '.valgrind')}",
                    str(root / executable), *(str(root / argument) for argument in arguments)],
        "testId": test_id,
        "cve": cve,
        "returncode": returncode,
        "timedOut": False,
        "memoryLog": memory_log,
        "passed": returncode == 0 and "ERROR SUMMARY: 0 errors" in memory_log,
    }


class BaselineClassification(unittest.TestCase):
    def test_recorded_native_crashes_are_reproductions(self):
        fixture = Path(__file__).resolve().parents[1] / "evidence/build-first-libxml2/baseline-regression.json"
        report = json.loads(fixture.read_text())
        self.assertEqual(len(report["checks"]), 2)
        for check in report["checks"]:
            self.assertEqual(check["returncode"], -11)
            self.assertTrue(schematron_baseline_reproduced(check))

    def test_unrelated_crash_is_not_a_reproduction(self):
        self.assertFalse(schematron_baseline_reproduced({"returncode": -11, "timedOut": False, "memoryLog": "Invalid read in unrelated library"}))

    def test_timeout_cannot_be_accepted_as_schematron_proof(self):
        self.assertFalse(schematron_baseline_reproduced({"returncode": None, "timedOut": True, "memoryLog": "Invalid read xmlSchematronValidateDoc libxml2.so.2"}))


class TiffBaselineClassification(unittest.TestCase):
    TIFF_STACK = ["0x114980", "0x116FB2", "0x10AC12"]

    def test_generic_tiffcrop_debug_dump_sigsegv_is_not_proof(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": -signal.SIGSEGV,
            "timedOut": False,
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_sigsegv_outside_exact_tiffcrop_debug_dump_is_not_a_reproduction(self):
        unrelated_command = {
            "command": ["tiffinfo", "/fixture/multisample.tif"],
            "returncode": -signal.SIGSEGV,
            "timedOut": False,
        }
        wrong_debug_level = {
            "command": ["tiffcrop", "-D", "format:txt,level:1,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": -signal.SIGSEGV,
            "timedOut": False,
        }
        self.assertFalse(tiff_baseline_reproduced(unrelated_command, self.TIFF_STACK))
        self.assertFalse(tiff_baseline_reproduced(wrong_debug_level, self.TIFF_STACK))

    def test_target_specific_stripped_tiffcrop_stack_signature_is_a_reproduction(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123==    at 0x114980: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x116FB2: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x10AC12: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x491CCA7: (below main) (libc_start_call_main.h:58)\n==123== ERROR SUMMARY: 134 errors from 22 contexts\n",
        }
        self.assertTrue(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_malformed_tiff_stack_signatures_cannot_weaken_baseline_proof(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123==    at 0x114980: ??? (in /usr/bin/tiffcrop)\n==123== ERROR SUMMARY: 1 errors from 1 contexts\n",
        }
        for malformed in (["0x114980"], ["0x114980", "0x116FB2"],
                          ["0x114980", "not-an-offset", "0x10AC12"],
                          ["0x114980", "0x114980", "0x10AC12"],
                          ["0x114980", 123, "0x10AC12"]):
            with self.subTest(signature=malformed):
                self.assertFalse(tiff_baseline_reproduced(check, malformed))

    def test_unrelated_uninitialised_value_in_same_binary_is_not_a_reproduction(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123==    at 0x1149B2: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x114B0B: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x116E48: ??? (in /usr/bin/tiffcrop)\n==123== ERROR SUMMARY: 134 errors from 22 contexts\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_expected_offsets_must_be_contiguous_in_the_stack(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123==    at 0x114980: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x123456: unrelated (in /usr/lib/libother.so)\n==123==    by 0x116FB2: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x10AC12: ??? (in /usr/bin/tiffcrop)\n==123== ERROR SUMMARY: 134 errors from 22 contexts\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_baseline_reproduction_requires_expected_target_signature_and_memcheck_options(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123==    at 0x114980: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x116FB2: ??? (in /usr/bin/tiffcrop)\n==123==    by 0x10AC12: ??? (in /usr/bin/tiffcrop)\n==123== ERROR SUMMARY: 134 errors from 22 contexts\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))
        self.assertFalse(tiff_baseline_reproduced(check, None))

    def test_generic_uninitialised_value_or_clean_memcheck_is_not_a_reproduction(self):
        command = ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"]
        unrelated = {
            "command": command, "returncode": 97, "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123==    at 0x123: foo (in /usr/bin/other-tool)\n==123== ERROR SUMMARY: 1 errors\n",
        }
        clean = {
            "command": command, "returncode": 97, "timedOut": False,
            "memoryLog": "==123== Use of uninitialised value of size 8\n==123== ERROR SUMMARY: 0 errors\n",
        }
        self.assertFalse(tiff_baseline_reproduced(unrelated, self.TIFF_STACK))
        self.assertFalse(tiff_baseline_reproduced(clean, self.TIFF_STACK))

    def test_uninitialised_value_without_tiffcrop_stack_is_not_a_reproduction(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": (
                "==123== Use of uninitialised value of size 8\n"
                "==123==    at 0x123: unrelated_function (in /usr/bin/other-tool)\n"
                "==123== ERROR SUMMARY: 1 errors\n"
            ),
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_unrelated_stack_read_size_does_not_match_the_sample_pointer_array(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Use of uninitialised value of size 8\nat 0x123: unrelated_function (in /usr/bin/other-tool)\nERROR SUMMARY: 1 errors\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_tiffcrop_unrelated_read_is_not_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Use of uninitialised value of size 8\nat 0x123: TIFFReadDirectory (in /usr/bin/tiffcrop)\nERROR SUMMARY: 1 errors\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_other_loadimage_read_boundary_is_not_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Use of uninitialised value of size 8\nat 0x123: loadImage (in /usr/bin/tiffcrop)\nERROR SUMMARY: 1 errors\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_generic_loadimage_read_without_sample_pointer_context_is_not_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Use of uninitialised value of size 8\nat 0x123: loadImage (in /usr/bin/tiffcrop)\nERROR SUMMARY: 1 errors\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check, self.TIFF_STACK))

    def test_generic_crash_warning_and_timeout_are_not_reproductions(self):
        warning_only = {
            "returncode": -11,
            "timedOut": False,
            "stderr": "Sum of Photometric type-related color channels",
        }
        timed_out = {
            "returncode": None,
            "timedOut": True,
            "memoryLog": "Invalid read of size 8\n0 bytes after a block of size 64 alloc'd",
        }
        self.assertFalse(tiff_baseline_reproduced(warning_only, self.TIFF_STACK))
        self.assertFalse(tiff_baseline_reproduced(timed_out, self.TIFF_STACK))


class Tiff61143Classification(unittest.TestCase):
    def test_null_output_failure_requires_the_exact_debug_probe_and_TIFFFileName_fault(self):
        command = ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                   "--read-var-info=yes", "--log-file=/tmp/probe.log", "tiffcrop", "-U", "px", "-m", "0,2,0,2", "-D",
                   "format:txt,level:2,output:/tmp/tiffcrop-null-output", "/recipe/tests/fixtures/multisample.tif",
                   "/tmp/tiffcrop-output.tif"]
        check = {
            "command": command, "returncode": 97, "timedOut": False,
            "memoryLogPath": "/tmp/probe.log",
            "memoryLog": "==123== Invalid read of size 8\n==123==    at 0x123: TIFFFileName (in /usr/lib/libtiff.so.5)\n==123== Address 0x0 is not stack'd, malloc'd or (recently) free'd\n==123== ERROR SUMMARY: 1 errors from 1 contexts\n",
        }
        self.assertTrue(tiff_null_output_baseline_reproduced(check))
        unrelated = dict(check, memoryLog="==123== Invalid read of size 8\n==123==    at 0x123: unrelated (in /usr/lib/libother.so)\n==123== Address 0x0 is not stack'd, malloc'd or (recently) free'd\n==123== ERROR SUMMARY: 1 errors from 1 contexts\n")
        self.assertFalse(tiff_null_output_baseline_reproduced(unrelated))
        generic_tiffcrop = dict(check, memoryLog="==123== Invalid read of size 8\n==123==    at 0x123: unrelated (in /usr/bin/tiffcrop)\n==123== Address 0x0 is not stack'd, malloc'd or (recently) free'd\n==123== ERROR SUMMARY: 1 errors from 1 contexts\n")
        self.assertFalse(tiff_null_output_baseline_reproduced(generic_tiffcrop))
        wrong_library = dict(check, memoryLog=check["memoryLog"].replace("libtiff.so.5", "libother.so"))
        self.assertFalse(tiff_null_output_baseline_reproduced(wrong_library))
        wrong_address = dict(check, memoryLog="==123== Invalid read of size 8\n==123==    at 0x123: TIFFFileName (in /usr/lib/libtiff.so.5)\n==123== Address 0x10 is not stack'd, malloc'd or (recently) free'd\n==123== ERROR SUMMARY: 1 errors from 1 contexts\n")
        self.assertFalse(tiff_null_output_baseline_reproduced(wrong_address))
        self.assertFalse(tiff_null_output_baseline_reproduced(dict(check, memoryLogPath="/tmp/other.log")))
        self.assertFalse(tiff_null_output_baseline_reproduced(dict(check, memoryLog=check["memoryLog"].replace("Address 0x0", "Address 0x8"))))
        split_contexts = dict(check, memoryLog=(
            "==123== Invalid read of size 8\n==123==    at 0x123: unrelated (in /usr/lib/libother.so)\n"
            "==123== Address 0x0 is not stack'd, malloc'd or (recently) free'd\n"
            "==123== Invalid read of size 8\n==123==    at 0x123: TIFFFileName (in /usr/lib/libtiff.so.5)\n"
            "==123== ERROR SUMMARY: 2 errors from 2 contexts\n"))
        self.assertFalse(tiff_null_output_baseline_reproduced(split_contexts))
        self.assertFalse(tiff_null_output_baseline_reproduced(dict(check, command=[*command[:-1], "/tmp/output.tif"])))

    def test_patched_null_output_failure_is_clean(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes", "--log-file=/tmp/probe.log", "tiffcrop", "-U", "px", "-m", "0,2,0,2", "-D",
                        "format:txt,level:2,output:/tmp/tiffcrop-null-output", "/recipe/multisample.tif",
                        "/tmp/tiffcrop-output.tif"],
            "returncode": 1, "timedOut": False,
            "memoryLogPath": "/tmp/probe.log",
            "stderr": "computeInputPixelOffsets: Combined left and right margins exceed image width.\ngetCropOffsets: Unable to compute crop margins.\nmain: Unable to define crop regions.\n",
            "debugOutputPath": "/tmp/tiffcrop-null-output-write-001.txt",
            "debugOutputFiles": ["tiffcrop-null-output-write-001.txt"],
            "debugOutput": "Writing image 1 from /recipe/multisample.tif\n Completed run for (not opened)\n",
            "memoryLog": "==1== ERROR SUMMARY: 0 errors from 0 contexts\n",
        }
        self.assertTrue(tiff_null_output_patched_succeeded(check))
        self.assertFalse(tiff_null_output_patched_succeeded(dict(check, stderr="unexpected success\n")))
        self.assertFalse(tiff_null_output_patched_succeeded(dict(check, returncode=0)))
        altered_probe = dict(check, command=[*check["command"]])
        altered_probe["command"][12] = "format:txt,level:0,output:/tmp/tiffcrop-null-output"
        self.assertFalse(tiff_null_output_patched_succeeded(altered_probe))
        self.assertFalse(tiff_null_output_patched_succeeded(dict(check, debugOutput="")))
        altered_log = dict(check, command=[*check["command"]])
        altered_log["command"][5] = "--other-log=/tmp/probe.log"
        self.assertFalse(tiff_null_output_patched_succeeded(altered_log))
        self.assertFalse(tiff_null_output_patched_succeeded(dict(check, memoryLogPath="/tmp/other.log")))
        self.assertFalse(tiff_null_output_patched_succeeded(dict(check, debugOutputPath="/tmp/other-write-001.txt")))
        self.assertFalse(tiff_null_output_patched_succeeded(dict(check, debugOutputFiles=["other-write-001.txt"])))
        prefix_spoof = dict(check, command=[*check["command"]])
        prefix_spoof["command"][12] = "format:txt,level:2,output:/tmp/other/tiffcrop-null-output"
        self.assertFalse(tiff_null_output_patched_succeeded(prefix_spoof))
        appended_option = dict(check, command=[*check["command"]])
        appended_option["command"][12] += ",input:/tmp/unexpected"
        self.assertFalse(tiff_null_output_patched_succeeded(appended_option))
        mismatched_directory = dict(check, command=[*check["command"]])
        mismatched_directory["command"][12] = "format:txt,level:2,output:/tmp/other/tiffcrop-null-output"
        mismatched_directory["debugOutputPath"] = "/tmp/other/tiffcrop-null-output-write-001.txt"
        self.assertFalse(tiff_null_output_patched_succeeded(mismatched_directory))

class LibpngBaselineClassification(unittest.TestCase):
    def test_clean_memcheck_requires_one_unambiguous_zero_error_summary(self):
        clean = "==12== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)\n"
        self.assertTrue(memcheck_has_no_errors(clean))
        self.assertFalse(memcheck_has_no_errors(clean + "==13== ERROR SUMMARY: 1 errors from 1 contexts\n"))
        self.assertFalse(memcheck_has_no_errors("==12== ERROR SUMMARY: 1 errors from 1 contexts\n"))

    def test_padded_stride_followup_requires_a_clean_memcheck_result(self):
        clean = {"returncode": 0, "timedOut": False, "memoryLog": "ERROR SUMMARY: 0 errors"}
        error = {"returncode": 97, "timedOut": False, "memoryLog": "ERROR SUMMARY: 1 errors"}
        self.assertTrue(libpng_followup_read_is_clean(clean))
        self.assertFalse(libpng_followup_read_is_clean(error))

    def test_specific_simplified_read_overwrite_is_a_reproduction(self):
        check = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE],
                                "CVE-2025-65018", 0, "ERROR SUMMARY: 0 errors")
        check["stdout"] = "result=overrun:output-buffer\n"
        self.assertTrue(libpng_overwrite_reproduced(check))

    def test_overwrite_cannot_be_mislabeled_as_another_cve(self):
        check = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE],
                                "CVE-2025-65018", 0, "ERROR SUMMARY: 0 errors")
        check["stdout"] = "result=overrun:output-buffer\n"
        check["cve"] = "CVE-2026-22801"
        self.assertFalse(libpng_overwrite_reproduced(check))

    def test_patched_read_requires_intact_output_buffer(self):
        check = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE],
                                "CVE-2025-65018", 0, "ERROR SUMMARY: 0 errors")
        check["stdout"] = "result=within-output-buffer\n"
        self.assertTrue(libpng_output_buffer_result(check, "result=within-output-buffer"))
        check["stdout"] = "result=overrun:output-buffer\n"
        self.assertFalse(libpng_output_buffer_result(check, "result=within-output-buffer"))

    def test_no_reported_overrun_does_not_match(self):
        check = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE],
                                "CVE-2025-65018", 0, "ERROR SUMMARY: 0 errors")
        self.assertFalse(libpng_overwrite_reproduced(check))

    def test_nonzero_memcheck_result_does_not_match_redzone_reproduction(self):
        check = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE],
                                "CVE-2025-65018", 97, "ERROR SUMMARY: 1 errors")
        check["stdout"] = "result=overrun:output-buffer\n"
        self.assertFalse(libpng_overwrite_reproduced(check))

    def test_specific_negative_stride_read_is_a_reproduction(self):
        check = libpng_memcheck("write-negative-stride.c", "write-negative-stride", [],
                                "CVE-2026-22801", 97,
                                "Invalid read of size 4\nat png_image_write_to_file\nlibpng16.so.16")
        self.assertTrue(libpng_stride_read_reproduced(check))

    def test_cve_named_valgrind_log_matches_its_probe(self):
        overwrite = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba",
                                    [LIBPNG_CVE_2025_65018_FIXTURE], "CVE-2025-65018", 0,
                                    "ERROR SUMMARY: 0 errors")
        overwrite["command"][5] = "--log-file=/tmp/getpatched-regression-fixture/CVE-2025-65018.valgrind"
        overwrite["stdout"] = "result=overrun:output-buffer\n"
        self.assertTrue(libpng_overwrite_reproduced(overwrite))

        stride = libpng_memcheck("write-negative-stride.c", "write-negative-stride", [],
                                 "CVE-2026-22801", 97,
                                 "Invalid read of size 2\npng_image_write_to_file\nlibpng16.so.16")
        stride["command"][5] = "--log-file=/tmp/getpatched-regression-fixture/CVE-2026-22801.valgrind"
        self.assertTrue(libpng_stride_read_reproduced(stride))
        stride["command"][5] = "--log-file=/tmp/getpatched-regression-fixture/CVE-2025-65018.valgrind"
        self.assertFalse(libpng_stride_read_reproduced(stride))

        wrong_cve = libpng_memcheck("write-negative-stride.c", "write-negative-stride", [],
                                    "CVE-2025-65018", 97,
                                    "Invalid read of size 2\npng_image_write_to_file\nlibpng16.so.16")
        wrong_cve["command"][5] = "--log-file=/tmp/getpatched-regression-fixture/CVE-2025-65018.valgrind"
        self.assertFalse(libpng_stride_read_reproduced(wrong_cve))

    def test_passing_exit_cannot_be_counted_as_baseline_reproduction(self):
        check = libpng_memcheck("write-negative-stride.c", "write-negative-stride", [],
                                "CVE-2026-22801", 0,
                                "Invalid read png_image_write_to_file libpng16.so.16")
        self.assertFalse(libpng_stride_read_reproduced(check))

    def test_mislabeled_probe_or_missing_fixture_cannot_reproduce_libpng_cve(self):
        wrong_probe = libpng_memcheck("read-interlaced-rgba.c", "unrelated", [LIBPNG_CVE_2025_65018_FIXTURE],
                                      "CVE-2025-65018", 97,
                                      "Invalid write png_image_finish_read libpng16.so.16")
        wrong_fixture = libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", ["flat.png"],
                                        "CVE-2025-65018", 97,
                                        "Invalid write png_image_finish_read libpng16.so.16")
        self.assertFalse(libpng_overwrite_reproduced(wrong_probe))
        self.assertFalse(libpng_overwrite_reproduced(wrong_fixture))

    def test_patched_libpng_gate_binds_all_cve_checks_and_adam7_comparison(self):
        checks = [
            libpng_memcheck("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE], "CVE-2025-65018"),
            libpng_memcheck("CVE-2026-22695-padded-stride-follow-up", "read-padded-stride", ["adam7.png"], "CVE-2026-22695"),
            libpng_memcheck("write-negative-stride.c", "write-negative-stride", [], "CVE-2026-22801"),
            {"testId": "adam7-pixel-equality", "command": [
                "/tmp/getpatched-regression-fixture/compare-interlaced-read",
                "/tmp/getpatched-regression-fixture/adam7.png",
                "/tmp/getpatched-regression-fixture/flat.png",
            ], "returncode": 0, "timedOut": False, "passed": True,
                "stdout": "differing channels: 0 / 3072\n"},
        ]
        checks[0]["stdout"] = "result=within-output-buffer\n"
        self.assertTrue(libpng_patched_checks_succeeded(checks))
        wrong_probe = json.loads(json.dumps(checks))
        wrong_probe[0]["command"][6] = "/tmp/getpatched-regression-fixture/unrelated"
        self.assertFalse(libpng_patched_checks_succeeded(wrong_probe))
        wrong_fixture = json.loads(json.dumps(checks))
        wrong_fixture[1]["command"][7] = "/tmp/getpatched-regression-fixture/flat.png"
        self.assertFalse(libpng_patched_checks_succeeded(wrong_fixture))
        duplicate = checks + [checks[0]]
        self.assertFalse(libpng_patched_checks_succeeded(duplicate))


class TiffPatchedClassification(unittest.TestCase):
    def valid_check(self):
        return {
            "command": ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes", "--log-file=/tmp/tiffcrop-valgrind.log", "tiffcrop", "-D",
                        "format:txt,level:2,input:/tmp/tiffcrop-debug", "/tmp/multisample.tif", "/tmp/output.tif"],
            "returncode": 0,
            "timedOut": False,
            "memoryLog": "==1== ERROR SUMMARY: 0 errors from 0 contexts\n",
            "baselineStackFrames": ["0x100", "0x200", "0x300"],
        }

    def test_patched_tiff_requires_expected_probe_and_no_invalid_access(self):
        self.assertTrue(tiff_patched_regression_succeeded(self.valid_check()))
        bad_exit = self.valid_check()
        bad_exit["returncode"] = 1
        self.assertFalse(tiff_patched_regression_succeeded(bad_exit))
        memory_error = self.valid_check()
        memory_error["memoryLog"] = "==1== ERROR SUMMARY: 1 errors from 1 contexts\n"
        memory_error["returncode"] = 97
        self.assertTrue(tiff_patched_regression_succeeded(memory_error))

    def test_unrelated_uninitialised_values_are_allowed_but_target_signature_is_not(self):
        check = self.valid_check()
        check["returncode"] = 97
        check["memoryLog"] = (
            "==1== Use of uninitialised value of size 8\n"
            "==1==    at 0x999: unrelated (in /usr/bin/tiffcrop)\n"
            "==1== ERROR SUMMARY: 1 errors from 1 contexts\n"
        )
        self.assertTrue(tiff_patched_regression_succeeded(check))
        check["memoryLog"] = (
            "==1== Use of uninitialised value of size 8\n"
            "==1==    at 0x100: vulnerable (in /usr/bin/tiffcrop)\n"
            "==1==    by 0x200: caller (in /usr/bin/tiffcrop)\n"
            "==1==    by 0x300: main (in /usr/bin/tiffcrop)\n"
            "==1== ERROR SUMMARY: 1 errors from 1 contexts\n"
        )
        self.assertFalse(tiff_patched_regression_succeeded(check))

    def test_any_invalid_memory_access_fails_patched_probe(self):
        check = self.valid_check()
        check["returncode"] = 97
        check["memoryLog"] = (
            "==1== Invalid read of size 8\n"
            "==1==    at 0x999: unrelated (in /usr/bin/tiffcrop)\n"
            "==1== ERROR SUMMARY: 1 errors from 1 contexts\n"
        )
        self.assertFalse(tiff_patched_regression_succeeded(check))

    def test_unrelated_tiff_command_is_not_patched_evidence(self):
        check = self.valid_check()
        check["command"][6] = "tiffinfo"
        self.assertFalse(tiff_patched_regression_succeeded(check))


class TiffBigStripRegressionClassification(unittest.TestCase):
    def baseline_check(self):
        fixture = "/tmp/CVE-2026-18495-bigstrip.tif"
        return {
            "cve": "CVE-2026-18495",
            "testId": "tiff2pdf-bigtiff-strip-length-truncation",
            "returncode": 97,
            "timedOut": False,
            "fixtureSizeBytes": 304,
            "declaredStripBytes": 4294967301,
            "allocationCapEnabled": False,
            "memoryMappingDisabled": True,
            "stderr": (
                "GETPATCHED_TIFF_MMAP_DISABLED\n"
                "GETPATCHED_TIFF_SCRATCH_ALLOC_BOUNDED requested=4294967311 cap=65536\n"
                "GETPATCHED_TIFF_SCRATCH_INIT_BOUNDED requested=4294967311 cap=65536\n"
                "GETPATCHED_TIFF_READ_BOUNDED requested=4294967301 cap=16\n"
                "GETPATCHED_TIFF_READ_COMPLETED requested=4294967301 bytes=16\n"
            ),
            "memoryLog": (
                "==1== Syscall param read(buf) points to unaddressable byte(s)\n"
                "==1==    at 0xabc: read (read.c:26)\n"
                "==1==    by 0xdef: ??? (in /usr/lib/x86_64-linux-gnu/libtiff.so.6.0.0)\n"
                "==1==    by 0x123: ??? (in /usr/bin/tiff2pdf)\n"
                "==1==  Address 0x123 is 0 bytes after a block of size 5 alloc'd\n"
                "==1==    at 0xaaa: malloc\n"
                "==1==    by 0xbbb: _TIFFmalloc (in /tmp/test-shim.so)\n"
                "==1==    by 0xccc: ??? (in /usr/bin/tiff2pdf)\n"
                "==1== ERROR SUMMARY: 59 errors from 1 contexts\n"
            ),
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=/tmp/CVE-2026-18495.valgrind",
                "tiff2pdf", "-m", "0", "-o", "/tmp/CVE-2026-18495-output.pdf", fixture,
            ],
        }

    def test_baseline_requires_real_short_read_and_five_byte_overflow(self):
        check = self.baseline_check()
        self.assertTrue(tiff_bigstrip_baseline_reproduced(check))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(dict(check, stderr="")))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(
            dict(check, stderr=check["stderr"].replace("GETPATCHED_TIFF_SCRATCH_INIT_BOUNDED", "UNEXPECTED"))))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(
            dict(check, stderr=check["stderr"].replace("GETPATCHED_TIFF_READ_BOUNDED requested=4294967301 cap=16\n", ""))))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(
            dict(check, stderr=check["stderr"].replace("requested=4294967301", "requested=16"))))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(
            dict(check, memoryLog=check["memoryLog"].replace("libtiff.so.6.0.0", "unrelated.so"))))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(
            dict(check, memoryLog=check["memoryLog"].replace("block of size 5 alloc'd", "block of size 6 alloc'd"))))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(dict(check, memoryMappingDisabled=False)))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(
            dict(check, memoryLog="==1== ERROR SUMMARY: 0 errors from 0 contexts\n")))
        self.assertFalse(tiff_bigstrip_baseline_reproduced(dict(check, fixtureSizeBytes=4_294_967_301)))

    def test_patched_requires_allocator_cap_and_clean_memcheck(self):
        check = self.baseline_check()
        check.update({
            "returncode": 1,
            "allocationCapEnabled": True,
            "stderr": (
                "GETPATCHED_TIFF_MMAP_DISABLED\n"
                "GETPATCHED_TIFF_SCRATCH_ALLOC_BOUNDED requested=4294967311 cap=65536\n"
                "GETPATCHED_TIFF_SCRATCH_INIT_BOUNDED requested=4294967311 cap=65536\n"
                "GETPATCHED_TIFF_ALLOCATION_REJECTED size=4294967301 cap=67108864\n"
                "Can't allocate 4294967301 bytes\n"
                "Can't allocate 4294967301 bytes\n"
            ),
            "memoryLog": "==1== ERROR SUMMARY: 0 errors from 0 contexts\n",
        })
        self.assertTrue(tiff_bigstrip_patched_succeeded(check))
        self.assertFalse(tiff_bigstrip_patched_succeeded(
            dict(check, stderr=check["stderr"].replace("GETPATCHED_TIFF_SCRATCH_INIT_BOUNDED", "UNEXPECTED"))))
        self.assertFalse(tiff_bigstrip_patched_succeeded(
            dict(check, stderr=check["stderr"] + "GETPATCHED_TIFF_READ_COMPLETED requested=123 bytes=16\n")))
        self.assertFalse(tiff_bigstrip_patched_succeeded(
            dict(check, stderr="Can't allocate 4294967301 bytes\n")))
        self.assertFalse(tiff_bigstrip_patched_succeeded(
            dict(check, memoryLog="==1== Invalid write of size 1\n==1== ERROR SUMMARY: 1 errors\n")))


class PopplerBaselineClassification(unittest.TestCase):
    def test_structtree_parent_uaf_is_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid write of size 8\nAddress is 0 bytes inside a freed block\nStructTreeRoot::parentTreeAdd\n",
        }
        self.assertTrue(poppler_uaf_reproduced(check))

    def test_unrelated_invalid_access_is_not_a_poppler_reproduction(self):
        check = {"returncode": 97, "timedOut": False,
                 "memoryLog": "Invalid write of size 8\nUnrelatedFunction\n"}
        self.assertFalse(poppler_uaf_reproduced(check))

    def test_timeout_or_success_is_not_a_baseline_reproduction(self):
        timed_out = {"returncode": None, "timedOut": True,
                     "memoryLog": "Invalid write StructTreeRoot::parentTreeAdd"}
        success = {"returncode": 0, "timedOut": False,
                   "memoryLog": "Invalid write StructTreeRoot::parentTreeAdd"}
        self.assertFalse(poppler_uaf_reproduced(timed_out))
        self.assertFalse(poppler_uaf_reproduced(success))

    def test_revision6_long_password_requires_invalid_write_in_libpoppler(self):
        check = {
            "cve": "CVE-2026-107705",
            "testId": "CVE-2026-107705-revision6-long-owner-password",
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=/tmp/revision6-password.valgrind",
                "/tmp/poppler-revision6-password", "/recipe/tests/fixtures/CVE-2026-107705-r6-encrypted.pdf",
            ],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": (
                "==123== Invalid write of size 8\n"
                "==123==    at 0x1234: revision6Hash (Decrypt.cc:1767) (in /usr/lib/x86_64-linux-gnu/libpoppler.so.126)\n"
                "==123== ERROR SUMMARY: 4 errors from 2 contexts\n"
            ),
        }
        self.assertTrue(poppler_revision6_probe_command(check))
        self.assertTrue(poppler_revision6_password_overflow_reproduced(check))
        self.assertFalse(poppler_revision6_probe_command({**check, "command": ["valgrind"]}))

    def test_revision6_rejects_unrelated_or_clean_memcheck_output(self):
        unrelated = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid write\n==123== ERROR SUMMARY: 1 errors from 1 contexts\n",
        }
        clean = {
            "returncode": 0,
            "timedOut": False,
            "memoryLog": "==123== ERROR SUMMARY: 0 errors from 0 contexts\n",
        }
        self.assertFalse(poppler_revision6_password_overflow_reproduced(unrelated))
        self.assertFalse(poppler_revision6_password_overflow_reproduced(clean))

    def test_revision6_rejects_unrelated_libpoppler_write(self):
        check = {
            "cve": "CVE-2026-107705",
            "testId": "CVE-2026-107705-revision6-long-owner-password",
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=/tmp/revision6-password.valgrind",
                "/tmp/poppler-revision6-password", "/recipe/tests/fixtures/CVE-2026-107705-r6-encrypted.pdf",
            ],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": (
                "==123== Invalid write of size 8\n"
                "==123==    at 0x1234: unrelated (in /usr/lib/x86_64-linux-gnu/libpoppler.so.126)\n"
                "==123== ERROR SUMMARY: 1 errors from 1 contexts\n"
            ),
        }
        self.assertFalse(poppler_revision6_password_overflow_reproduced(check))

    def test_revision6_accepts_exact_stack_canary_overflow_from_stripped_poppler(self):
        check = {
            "cve": "CVE-2026-107705",
            "testId": "CVE-2026-107705-revision6-long-owner-password",
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=/tmp/revision6-password.valgrind",
                "/tmp/poppler-revision6-password", "/recipe/tests/fixtures/CVE-2026-107705-r6-encrypted.pdf",
            ],
            "returncode": -6,
            "timedOut": False,
            "stderr": "*** stack smashing detected ***: terminated\n",
            "memoryLog": (
                "==41== Process terminating with default action of signal 6 (SIGABRT)\n"
                "==41==    by 0x4FDF92F: __stack_chk_fail (fortify_fail.c:24)\n"
                "==41==    by 0x499A747: ??? (in /usr/lib/x86_64-linux-gnu/libpoppler.so.147.0.0)\n"
                "==41== ERROR SUMMARY: 0 errors from 0 contexts\n"
            ),
        }
        self.assertTrue(poppler_revision6_password_overflow_reproduced(check))

    def test_revision6_rejects_unrelated_stack_smash(self):
        check = {
            "cve": "CVE-2026-107705",
            "testId": "CVE-2026-107705-revision6-long-owner-password",
            "command": [
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=/tmp/revision6-password.valgrind",
                "/tmp/poppler-revision6-password", "/recipe/tests/fixtures/CVE-2026-107705-r6-encrypted.pdf",
            ],
            "returncode": -6,
            "timedOut": False,
            "stderr": "Aborted\n",
            "memoryLog": (
                "==41== Process terminating with default action of signal 6 (SIGABRT)\n"
                "==41==    by 0x4FDF92F: __stack_chk_fail (fortify_fail.c:24)\n"
                "==41==    by 0x499A747: ??? (in /usr/lib/x86_64-linux-gnu/libpoppler.so.147.0.0)\n"
                "==41== ERROR SUMMARY: 0 errors from 0 contexts\n"
            ),
        }
        self.assertFalse(poppler_revision6_password_overflow_reproduced(check))


class ConsumerVersionCheck(unittest.TestCase):
    def test_version_banner_on_stdout_or_stderr_is_accepted(self):
        self.assertTrue(consumer_version_succeeded(
            {"returncode": 0, "timedOut": False, "stderr": "pdfinfo version 0.86.1"},
            "pdfinfo version"))
        self.assertTrue(consumer_version_succeeded(
            {"returncode": 0, "timedOut": False, "stdout": "pdfinfo version 0.86.1"},
            "pdfinfo version"))

    def test_missing_banner_failure_and_timeout_are_rejected(self):
        self.assertFalse(consumer_version_succeeded(
            {"returncode": 0, "timedOut": False, "stdout": "no version here"}, "pdfinfo version"))
        self.assertFalse(consumer_version_succeeded(
            {"returncode": 1, "timedOut": False, "stderr": "pdfinfo version 0.86.1"}, "pdfinfo version"))
        self.assertFalse(consumer_version_succeeded(
            {"returncode": None, "timedOut": True, "stderr": "pdfinfo version 0.86.1"}, "pdfinfo version"))


class CallbackUrlParsing(unittest.TestCase):
    def test_extracts_single_callback_line_without_python_39_string_methods(self):
        self.assertEqual(parse_callback_url("other output\ncallback_url=http://127.0.0.1:8080/repo\n"),
                         "http://127.0.0.1:8080/repo")

    def test_rejects_missing_or_ambiguous_callback_lines(self):
        self.assertIsNone(parse_callback_url("no callback"))
        self.assertIsNone(parse_callback_url("callback_url=first\ncallback_url=second\n"))


class Libgit2RedirectEvidence(unittest.TestCase):
    def test_baseline_requires_fixture_credential_to_reach_redirected_origin(self):
        check = {
            "returncode": 0, "timedOut": False,
            "initialOrigin": "http://127.0.0.1:8001",
            "redirectedOrigin": "http://127.0.0.1:8002",
            "callbackUrls": ["http://127.0.0.1:8001/repository"],
            "redirectedHostReceivedFixtureCredential": True,
        }
        self.assertTrue(libgit2_redirect_reproduced(check, "baseline"))
        check["redirectedHostReceivedFixtureCredential"] = False
        self.assertFalse(libgit2_redirect_reproduced(check, "baseline"))

    def test_patched_run_requires_redirect_origin_and_no_authorization_header(self):
        check = {
            "returncode": 0, "timedOut": False,
            "initialOrigin": "http://127.0.0.1:8001",
            "redirectedOrigin": "http://127.0.0.1:8002",
            "callbackUrls": ["http://127.0.0.1:8002/repository"],
            "redirectedHostAuthorizationHeaderPresent": False,
        }
        self.assertTrue(libgit2_redirect_reproduced(check, "patched"))
        check["redirectedHostAuthorizationHeaderPresent"] = True
        self.assertFalse(libgit2_redirect_reproduced(check, "patched"))

    def test_wrong_callback_origin_and_timeout_are_not_evidence(self):
        check = {
            "returncode": 0, "timedOut": False,
            "initialOrigin": "http://127.0.0.1:8001",
            "redirectedOrigin": "http://127.0.0.1:8002",
            "callbackUrls": ["http://127.0.0.1:8003/repository"],
            "redirectedHostReceivedFixtureCredential": True,
        }
        self.assertFalse(libgit2_redirect_reproduced(check, "baseline"))
        check["callbackUrls"] = ["http://127.0.0.1:8002/repository"]
        check["redirectedHostAuthorizationHeaderPresent"] = False
        check["timedOut"] = True
        self.assertFalse(libgit2_redirect_reproduced(check, "patched"))


if __name__ == "__main__":
    unittest.main()
