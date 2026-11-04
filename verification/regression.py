#!/usr/bin/env python3
"""Verify bounded regressions against installed focal packages, before and after."""
import argparse
import base64
import binascii
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import threading
import tempfile
from urllib.parse import urlsplit

LIBPNG_CVE_2025_65018_FIXTURE = "cve-2025-65018-advisory-adam7-rgb16.png"
LIBPNG_CVE_2025_65018_FIXTURE_SHA256 = "9deb34ada9b550df50181e4cd8c947303fd7b2881f61f3f16efa249d845e9905"
BROTLI_MAX_PROBE_OUTPUT = 32 * 1024 * 1024
BROTLI_MAX_PROBE_CALLS = 8192
CARES_RECORD_COUNT_HEAP_LIMIT = 8 * 1024 * 1024


def execute(command, timeout=30, env=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
        return {"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timedOut": False}
    except subprocess.TimeoutExpired as error:
        def partial_output(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            if value is None:
                return ""
            return str(value)

        return {
            "command": command,
            "returncode": None,
            "stdout": partial_output(error.stdout),
            "stderr": partial_output(error.stderr),
            "timedOut": True,
        }


def validate_recipe_regression_fixture_hashes(recipe, manifest):
    """Verify regression inputs declared by the packaging recipe before use."""
    root = Path(recipe).resolve()
    metadata_name = manifest.get("patchMetadata")
    if not isinstance(metadata_name, str):
        raise RuntimeError("Recipe patch metadata path is missing")
    metadata_path = (root / metadata_name).resolve()
    if not metadata_path.is_relative_to(root) or not metadata_path.is_file():
        raise RuntimeError("Recipe patch metadata path is invalid")
    metadata = json.loads(metadata_path.read_text())
    patches = metadata.get("patches")
    if not isinstance(patches, list) or not patches:
        raise RuntimeError("Recipe patch metadata has no patches")
    for patch in patches:
        if not isinstance(patch, dict):
            raise RuntimeError("Recipe patch metadata entry is invalid")
        declared_files = patch.get("referenceFiles", [])
        if not isinstance(declared_files, list):
            raise RuntimeError("Recipe reference file declarations are invalid")
        declared_files = list(declared_files)
        tests = patch.get("tests", [])
        if not isinstance(tests, list):
            raise RuntimeError("Recipe regression test declarations are invalid")
        for test in tests:
            if not isinstance(test, dict) or not isinstance(test.get("fixtures", []), list):
                raise RuntimeError("Recipe regression test fixture declaration is invalid")
            declared_files.extend(test.get("fixtures", []))
        for declared in declared_files:
            if (not isinstance(declared, dict) or not isinstance(declared.get("path"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", str(declared.get("sha256", "")))):
                raise RuntimeError("Recipe regression files must declare a path and SHA-256")
            fixture = (root / declared["path"]).resolve()
            if (not fixture.is_relative_to(root) or not fixture.is_file()
                    or hashlib.sha256(fixture.read_bytes()).hexdigest() != declared["sha256"]):
                raise RuntimeError("Recipe regression fixture hash does not match patch metadata")


def schematron_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check["timedOut"]
        and check["returncode"] in (97, -signal.SIGSEGV)
        and "Invalid read" in log
        and "xmlSchematronValidateDoc" in log
        and "libxml2.so." in log
    )


def libxml2_parameter_entity_command(check):
    command = check.get("command", [])
    return (
        len(command) == 8
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "libxml2-cve-2026-6653"
        and Path(command[7]).name == "cve-2026-6653.xml"
    )


def libxml2_parameter_entity_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return bool(
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and libxml2_parameter_entity_command(check)
        and any(
            block.group("kind").startswith("Invalid read")
            and "xmlReadMemory" in block.group("body")
            and "free'd" in block.group("body")
            and "libxml2.so." in block.group("body")
            and "xmlNewEntityInputStream" in block.group("body").partition("Block was alloc'd at")[2]
            for block in valgrind_invalid_access_blocks(log)
        )
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log) is not None
    )


def libxml2_parameter_entity_patched_succeeded(check):
    log = check.get("memoryLog", "")
    return bool(
        not check.get("timedOut", False)
        and check.get("returncode") == 0
        and libxml2_parameter_entity_command(check)
        and not valgrind_invalid_access_blocks(log)
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: 0 errors?", log)
    )


def libxml2_catalog_command(check):
    command = check.get("command", [])
    return bool(
        len(command) == 8
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "libxml2-cve-2026-76781"
        and Path(command[7]).name == "cve-2026-76781-catalog.xml"
    )


def libxml2_catalog_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return bool(
        not check.get("timedOut", False)
        and check.get("returncode") in (97, -signal.SIGSEGV)
        and libxml2_catalog_command(check)
        and any(
            block.group("kind").startswith("Invalid read")
            and "xmlCatalogResolveSystem" in block.group("body")
            and "libxml2.so." in block.group("body")
            and re.search(r"(?m)^==\d+==\s+(?:Address|at) 0x30\b", block.group("body")) is not None
            for block in valgrind_invalid_access_blocks(log)
        )
        and "Process terminating with default action of signal 11 (SIGSEGV)" in log
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log) is not None
    )


def libxml2_catalog_patched_succeeded(check):
    log = check.get("memoryLog", "")
    return bool(
        not check.get("timedOut", False)
        and check.get("returncode") == 0
        and libxml2_catalog_command(check)
        and not valgrind_invalid_access_blocks(log)
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: 0 errors?", log)
    )


def libxml2_regexp_alloc_failure_command(check):
    command = check.get("command", [])
    return bool(
        len(command) == 7
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "libxml2-cve-2026-86141"
        and check.get("testId") == "regexp-allocation-failure-null-check"
        and check.get("injection") == "xmlMemSetup:test_malloc:sizeof-regexp"
    )


def libxml2_regexp_alloc_failure_baseline_reproduced(check):
    return bool(
        not check.get("timedOut", False)
        and check.get("returncode") in (97, -signal.SIGSEGV)
        and libxml2_regexp_alloc_failure_command(check)
        and "GETPATCHED_REGEXP_COPY_ALLOCATION_FAILURE_INJECTED" in check.get("stderr", "")
        and any(
            block.group("kind") == "Invalid read of size 1"
            and re.search(r"(?m)^==\d+==\s+at .*\(in .*/libxml2\.so\.", block.group("body"))
            and "xmlRegexpCompile" in block.group("body")
            and "libxml2.so." in block.group("body")
            and re.search(r"(?m)^==\d+==\s+Address 0x0\b", block.group("body"))
            for block in valgrind_invalid_access_blocks(check.get("memoryLog", ""))
        )
        and "Process terminating with default action of signal 11 (SIGSEGV)" in check.get("memoryLog", "")
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", check.get("memoryLog", ""))
    )


def libxml2_regexp_alloc_failure_patched_succeeded(check):
    return bool(
        not check.get("timedOut", False)
        and check.get("returncode") == 0
        and libxml2_regexp_alloc_failure_command(check)
        and "GETPATCHED_REGEXP_COPY_ALLOCATION_FAILURE_INJECTED" in check.get("stderr", "")
        and "XML_REGEXP_COMPILE_REJECTED_ALLOCATION_FAILURE" in check.get("stdout", "")
        and not valgrind_invalid_access_blocks(check.get("memoryLog", ""))
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: 0 errors?", check.get("memoryLog", ""))
    )


def libxml2_xinclude_nonet_result(check, phase):
    command = check.get("command", [])
    expected_mode = "expect-network" if phase == "baseline" else "expect-blocked"
    expected_code = 10 if phase == "baseline" else 0
    return bool(
        not check.get("timedOut", False)
        and len(command) == 4
        and Path(command[0]).name == "libxml2-cve-2026-86144"
        and Path(command[1]).name == "cve-2026-86144-xinclude.xml"
        and command[2] in ("document", "tree")
        and command[3] == expected_mode
        and check.get("returncode") == expected_code
    )


def libxml2_xinclude_checks_succeeded(checks, phase):
    candidates = [check for check in checks if check.get("cve") == "CVE-2026-86144"]
    apis = [check.get("command", [None, None, None])[2] for check in candidates]
    return bool(
        len(candidates) == 2
        and sorted(apis) == ["document", "tree"]
        and all(libxml2_xinclude_nonet_result(check, phase) for check in candidates)
    )


def libxml2_baseline_check_succeeded(check):
    cve = check.get("cve")
    if cve == "CVE-2026-6653":
        return libxml2_parameter_entity_baseline_reproduced(check)
    if cve == "CVE-2026-76781":
        return libxml2_catalog_baseline_reproduced(check)
    if cve == "CVE-2026-86141":
        return libxml2_regexp_alloc_failure_baseline_reproduced(check)
    return schematron_baseline_reproduced(check)


def libxml2_patched_check_succeeded(check):
    cve = check.get("cve")
    if cve == "CVE-2026-6653":
        return libxml2_parameter_entity_patched_succeeded(check)
    if cve == "CVE-2026-76781":
        return libxml2_catalog_patched_succeeded(check)
    if cve == "CVE-2026-86141":
        return libxml2_regexp_alloc_failure_patched_succeeded(check)
    return check.get("returncode") == 3 and "ERROR SUMMARY: 0 errors" in check.get("memoryLog", "")


def libxml2_check_cardinality_valid(checks, target_cves):
    return all(
        sum(check.get("cve") == cve for check in checks) == (2 if cve == "CVE-2026-86144" else 1)
        for cve in target_cves
    )


def valid_tiff_baseline_stack_signature(expected_stack_frames):
    return (
        isinstance(expected_stack_frames, list)
        and len(expected_stack_frames) == 3
        and all(isinstance(offset, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", offset)
                for offset in expected_stack_frames)
        and len(set(expected_stack_frames)) == 3
    )


def tiff_baseline_reproduced(check, expected_stack_frames):
    log = check.get("memoryLog", "")
    command = check.get("command", [])
    debug_dump = next((command[i + 1] for i, arg in enumerate(command[:-1]) if arg == "-D"), "")
    memcheck_options = ("--tool=memcheck", "--error-exitcode=97", "--read-var-info=yes")
    exact_probe = (
        command
        and Path(command[0]).name == "valgrind"
        and all(option in command for option in memcheck_options)
        and "tiffcrop" in command
        and "format:txt" in debug_dump
        and "level:2" in debug_dump
        and any(Path(arg).name == "multisample.tif" for arg in command)
    )
    if (check.get("timedOut", False) or check.get("returncode") != 97 or not exact_probe
            or not valid_tiff_baseline_stack_signature(expected_stack_frames)):
        return False

    error_blocks = re.finditer(
        r"(?ms)^==\d+== Use of uninitialised value of size 8\n(?P<body>.*?)(?=^==\d+== "
        r"(?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)",
        log,
    )
    def matches_expected_stack(block):
        frames = re.findall(r"(?m)^==\d+==\s+(?:at|by) .*?$", block.group("body"))
        return len(frames) >= len(expected_stack_frames) and all(
            re.match(
                rf"^==\d+==\s+(?:at|by) {re.escape(offset)}:.*\(in /usr/bin/tiffcrop\)$",
                frame,
            )
            for frame, offset in zip(frames, expected_stack_frames)
        )

    has_expected_tiffcrop_stack = any(matches_expected_stack(block) for block in error_blocks)
    has_memcheck_errors = re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log)
    return has_expected_tiffcrop_stack and bool(has_memcheck_errors)


def tiff_patched_regression_succeeded(check):
    command = check.get("command", [])
    log = check.get("memoryLog", "")
    expected_stack_frames = check.get("baselineStackFrames")
    error_summary = re.search(r"(?m)^==\d+== ERROR SUMMARY: (\d+) errors?", log)
    vulnerable_stack_present = False
    if valid_tiff_baseline_stack_signature(expected_stack_frames):
        error_blocks = re.finditer(
            r"(?ms)^==\d+== Use of uninitialised value of size 8\n(?P<body>.*?)(?=^==\d+== "
            r"(?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)",
            log,
        )
        for block in error_blocks:
            frames = re.findall(r"(?m)^==\d+==\s+(?:at|by) .*?$", block.group("body"))
            if len(frames) >= len(expected_stack_frames) and all(
                re.match(
                    rf"^==\d+==\s+(?:at|by) {re.escape(offset)}:.*\(in /usr/bin/tiffcrop\)$",
                    frame,
                )
                for frame, offset in zip(frames, expected_stack_frames)
            ):
                vulnerable_stack_present = True
                break
    return (
        not check.get("timedOut", False)
        and check.get("returncode") in (0, 97)
        and command
        and Path(command[0]).name == "valgrind"
        and "--tool=memcheck" in command
        and "tiffcrop" in [Path(argument).name for argument in command]
        and any(argument.startswith("format:txt,level:2,input:") for argument in command)
        and any(Path(argument).name == "multisample.tif" for argument in command)
        and valid_tiff_baseline_stack_signature(expected_stack_frames)
        and not vulnerable_stack_present
        and not valgrind_invalid_access_blocks(log)
        and error_summary is not None
        and ((check["returncode"] == 0 and error_summary.group(1) == "0")
             or (check["returncode"] == 97 and int(error_summary.group(1)) > 0))
    )


def pixarlog_probe_command_matches(check):
    command = check.get("command")
    if (check.get("cve") != "CVE-2026-12912"
            or check.get("testId") != "pixarlog-abgr-rgb-multirow-strip-overflow"
            or not isinstance(command, list) or len(command) != 9
            or command[:5] != ["valgrind", "--tool=memcheck", "--error-exitcode=97",
                               "--leak-check=no", "--read-var-info=yes"]
            or not command[5].startswith("--log-file=")
            or command[7] != "decode"):
        return False
    binary = Path(command[6])
    fixture = Path(command[8])
    log = Path(command[5].split("=", 1)[1])
    return (binary.name == "pixarlog-abgr" and fixture.name == "pixarlog-abgr.tif"
            and binary.parent == fixture.parent == log.parent)


def pixarlog_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and pixarlog_probe_command_matches(check)
        and re.fullmatch(r"decode_called=1 result=[1-9][0-9]* strip_size=24576\n",
                         check.get("stdout", "")) is not None
        and any(block.group("kind").startswith("Invalid write")
                and "libtiff.so" in block.group("body")
                for block in valgrind_invalid_access_blocks(log))
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log) is not None
    )


def pixarlog_patched_succeeded(check):
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 0
        and pixarlog_probe_command_matches(check)
        and check.get("stdout") == "decode_called=1 result=-1 strip_size=24576\n"
        and "Output buffer too small for PixarLog ABGR data" in check.get("stderr", "")
        and not valgrind_invalid_access_blocks(check.get("memoryLog", ""))
        and memcheck_has_no_errors(check.get("memoryLog", ""))
    )


def tiff_cve_required(policy, cve):
    configured = policy.get("targetCves") if isinstance(policy, dict) else None
    return isinstance(configured, list) and cve in configured


def _tiff_bigstrip_probe_command_matches(check):
    command = check.get("command", [])
    if (not isinstance(command, list) or len(command) != 12
            or command[:5] != [
                "valgrind", "--tool=memcheck", "--error-exitcode=97",
                "--leak-check=no", "--read-var-info=yes",
            ]):
        return False
    if not command[5].startswith("--log-file=") or command[6:10] != ["tiff2pdf", "-m", "0", "-o"]:
        return False
    output = Path(command[10])
    fixture = Path(command[11])
    log = Path(command[5].split("=", 1)[1])
    return (
        output.name == "CVE-2026-18495-output.pdf"
        and fixture.name == "CVE-2026-18495-bigstrip.tif"
        and output.parent == fixture.parent == log.parent
        and log.name == "CVE-2026-18495.valgrind"
    )


def tiff_bigstrip_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    stderr = check.get("stderr", "")
    bounded_read = re.search(r"GETPATCHED_TIFF_READ_BOUNDED requested=(\d+) cap=16", stderr)
    completed_read = re.search(r"GETPATCHED_TIFF_READ_COMPLETED requested=(\d+) bytes=16", stderr)
    vulnerable_read_blocks = re.finditer(
        r"(?ms)^==\d+== Syscall param read\(buf\) points to unaddressable byte\(s\)\n"
        r"(?P<body>.*?)(?=^==\d+== (?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)",
        log,
    )
    read_overrun_reproduced = any(
        "block of size 5 alloc'd" in block.group("body")
        and "libtiff.so." in block.group("body")
        and "/usr/bin/tiff2pdf" in block.group("body")
        for block in vulnerable_read_blocks
    )
    return (
        check.get("cve") == "CVE-2026-18495"
        and check.get("testId") == "tiff2pdf-bigtiff-strip-length-truncation"
        and check.get("timedOut") is False
        and check.get("returncode") == 97
        and check.get("fixtureSizeBytes") == 304
        and check.get("declaredStripBytes") == 4294967301
        and check.get("allocationCapEnabled") is False
        and check.get("memoryMappingDisabled") is True
        and _tiff_bigstrip_probe_command_matches(check)
        and "GETPATCHED_TIFF_MMAP_DISABLED" in stderr
        and "GETPATCHED_TIFF_SCRATCH_ALLOC_BOUNDED requested=4294967311 cap=65536" in stderr
        and "GETPATCHED_TIFF_SCRATCH_INIT_BOUNDED requested=4294967311 cap=65536" in stderr
        and bounded_read is not None
        and int(bounded_read.group(1)) > 64 * 1024 * 1024
        and completed_read is not None
        and bounded_read.group(1) == completed_read.group(1)
        and read_overrun_reproduced
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log) is not None
    )


def tiff_bigstrip_patched_succeeded(check):
    stderr = check.get("stderr", "")
    return (
        check.get("cve") == "CVE-2026-18495"
        and check.get("testId") == "tiff2pdf-bigtiff-strip-length-truncation"
        and check.get("timedOut") is False
        and check.get("returncode") == 1
        and check.get("fixtureSizeBytes") == 304
        and check.get("declaredStripBytes") == 4294967301
        and check.get("allocationCapEnabled") is True
        and check.get("memoryMappingDisabled") is True
        and _tiff_bigstrip_probe_command_matches(check)
        and "GETPATCHED_TIFF_MMAP_DISABLED" in stderr
        and "GETPATCHED_TIFF_SCRATCH_ALLOC_BOUNDED requested=4294967311 cap=65536" in stderr
        and "GETPATCHED_TIFF_SCRATCH_INIT_BOUNDED requested=4294967311 cap=65536" in stderr
        and "GETPATCHED_TIFF_READ_BOUNDED" not in stderr
        and "GETPATCHED_TIFF_READ_COMPLETED" not in stderr
        and "GETPATCHED_TIFF_ALLOCATION_REJECTED size=4294967301 cap=67108864" in stderr
        and "got 64 bytes, expected 4294967301" not in stderr
        and memcheck_has_no_errors(check.get("memoryLog", ""))
    )


TIFF_SUBDIVISION_OVERFLOW_COMMAND = ["tiffcrop", "-S", "134217729:32", "-h"]


def tiff_subdivision_baseline_reproduced(check):
    output = check.get("stdout", "") + check.get("stderr", "")
    return (
        check.get("cve") == "CVE-2026-52490"
        and check.get("testId") == "tiffcrop-subdivision-overflow-check"
        and check.get("command") == TIFF_SUBDIVISION_OVERFLOW_COMMAND
        and not check.get("timedOut", False)
        and check.get("returncode") == 0
        and "usage: tiffcrop" in output.lower()
        and "Limit for subdivisions" not in output
    )


def tiff_subdivision_patched_succeeded(check):
    output = check.get("stdout", "") + check.get("stderr", "")
    return (
        check.get("cve") == "CVE-2026-52490"
        and check.get("testId") == "tiffcrop-subdivision-overflow-check"
        and check.get("command") == TIFF_SUBDIVISION_OVERFLOW_COMMAND
        and not check.get("timedOut", False)
        and check.get("returncode") == 1
        and "Limit for subdivisions" in output
        and "usage: tiffcrop" not in output.lower()
    )


def valgrind_invalid_access_blocks(log):
    pattern = re.compile(
        r"(?ms)^==\d+== (?P<kind>Invalid (?:read|write) of size \d+)\n"
        r"(?P<body>.*?)(?=^==\d+== (?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)"
    )
    return list(pattern.finditer(log))


def imagemagick_morph_check_succeeded(check, phase):
    command = check.get("command")
    if (not isinstance(command, list) or len(command) != 12
            or command[:5] != ["valgrind", "--tool=memcheck", "--error-exitcode=97",
                              "--leak-check=no", "--track-origins=yes"]
            or not command[5].startswith("--log-file=")
            or command[6] != "/usr/bin/magick"
            or [Path(item).name for item in (command[7], command[8], command[11])]
            != ["first-graya.png", "second-srgb.png", "morph.miff"]
            or command[9:11] != ["-morph", "1"]
            or Path(command[7]).parent != Path(command[8]).parent
            or Path(command[7]).parent.name != "fixtures"
            or check.get("memoryLogPath") != command[5].split("=", 1)[1]
            or check.get("cve") != "CVE-2026-119124"
            or check.get("testId") != "imagemagick-morph-channel-bounds"
            or check.get("magickBinaryOwner") != "imagemagick-7.q16"
            or check.get("magickBinaryPath") != "/usr/bin/magick-im7.q16"
            or check.get("installedPackageVersions") != {
                name: check.get("expectedPackageVersion") for name in (
                    "imagemagick-7.q16", "libmagickcore-7.q16-10", "libmagickwand-7.q16-10"
                )
            }):
        return False
    log = check.get("memoryLog", "")
    invalid_writes = [block for block in valgrind_invalid_access_blocks(log)
                      if block.group("kind").startswith("Invalid write")]
    if phase == "baseline":
        return (not check.get("timedOut", False) and check.get("returncode") == 97
                and any("MorphImages" in block.group("body") for block in invalid_writes))
    return (not check.get("timedOut", False) and check.get("returncode") == 0
            and check.get("outputFrames") == 3
            and check.get("outputInspectReturncode") == 0
            and not valgrind_invalid_access_blocks(log) and memcheck_has_no_errors(log))


def memcheck_log_path_matches(check, command):
    memory_log_path = check.get("memoryLogPath")
    return (
        isinstance(memory_log_path, str) and bool(memory_log_path)
        and len(command) > 5
        and command[5] == "--log-file=" + memory_log_path
    )


def tiff_null_output_baseline_reproduced(check):
    command = check.get("command", [])
    log = check.get("memoryLog", "")
    output = Path(command[-1]) if command else Path("/")
    debug_dump = next((command[i + 1] for i, arg in enumerate(command[:-1]) if arg == "-D"), "")
    exact_probe = (
        len(command) == 15
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "tiffcrop"
        and command[7:11] == ["-U", "px", "-m", "0,2,0,2"]
        and command[11] == "-D"
        and debug_dump.startswith("format:txt,level:2,output:")
        and Path(command[13]).name == "multisample.tif"
        and Path(output).name == "tiffcrop-output.tif"
    )
    expected_fault = any(
        block.group("kind") == "Invalid read of size 8"
        and "Address 0x0 is not stack'd, malloc'd or (recently) free'd" in block.group("body")
        and re.search(r"(?m)^==\d+==\s+at .*TIFFFileName \(in /usr/lib(?:/[^ )]+)?/libtiff(?:xx)?\.so(?:\.[0-9]+)*\)", block.group("body"))
        for block in valgrind_invalid_access_blocks(log)
    )
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and exact_probe
        and expected_fault
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log)
    )


def tiff_null_output_patched_succeeded(check):
    command = check.get("command", [])
    log = check.get("memoryLog", "")
    output_text = check.get("stdout", "") + check.get("stderr", "")
    output_path = command[-1] if command else ""
    debug_output_path = check.get("debugOutputPath", "")
    debug_option = command[12] if len(command) > 12 else ""
    debug_prefix = debug_option.removeprefix("format:txt,level:2,output:")
    expected_debug_output = debug_prefix + "-write-001.txt"
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 1
        and len(command) == 15
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "tiffcrop"
        and command[7:11] == ["-U", "px", "-m", "0,2,0,2"]
        and command[11] == "-D"
        and debug_option.startswith("format:txt,level:2,output:")
        and bool(debug_prefix)
        and "," not in debug_prefix
        and Path(debug_prefix).is_absolute()
        and Path(command[13]).name == "multisample.tif"
        and Path(output_path).name == "tiffcrop-output.tif"
        and Path(debug_prefix).parent.resolve() == Path(output_path).parent.resolve()
        and isinstance(debug_output_path, str)
        and Path(debug_output_path).is_absolute()
        and Path(debug_output_path).resolve() == Path(expected_debug_output).resolve()
        and Path(expected_debug_output).parent.resolve() == Path(output_path).parent.resolve()
        and "Unable to define crop regions" in output_text
        and "Combined left and right margins exceed image width" in output_text
        and Path(debug_output_path).name in check.get("debugOutputFiles", [])
        and "Completed run for (not opened)" in check.get("debugOutput", "")
        and "ERROR SUMMARY: 0 errors" in log
    )


def consumer_version_succeeded(check, expected_banner):
    output = check.get("stdout", "") + check.get("stderr", "")
    return not check.get("timedOut", False) and check.get("returncode") == 0 and expected_banner in output


def expat_regression_succeeded(check, phase):
    if (check.get("cve") != "CVE-2026-117610"
            or check.get("testId") != "CVE-2026-117610-empty-nonfinal-subparser"
            or check.get("timedOut") is not False):
        return False
    if phase == "baseline":
        return check.get("returncode") == -signal.SIGSEGV
    return phase == "patched" and check.get("returncode") == 0


def expat_consumer_succeeded(check, expected_version):
    output = check.get("stdout", "") + check.get("stderr", "")
    return (not check.get("timedOut", False)
            and check.get("returncode") == 0
            and f"xmlwf using expat_{expected_version}" in output)


def brotli_baseline_reproduced(check):
    return (
        check.get("cve") == "CVE-2026-111497"
        and check.get("testId") == "brotli-invalid-block-switch"
        and check.get("timedOut") is False
        and check.get("returncode") == 0
        and check.get("decoderResult") == 0  # BROTLI_DECODER_RESULT_ERROR
        and check.get("decoderError") == -9  # BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1
        and check.get("formatBlockSwitchError") == -17
        and check.get("inputRemaining") == 3
        and check.get("decoderOutputBytes") == 16 * 1024 * 1024
        and check.get("decoderCalls") == 4096
        and check.get("normalStreamCompatible") is True
    )


def brotli_patched_succeeded(check):
    return (
        check.get("cve") == "CVE-2026-111497"
        and check.get("testId") == "brotli-invalid-block-switch"
        and check.get("timedOut") is False
        and check.get("returncode") == 0
        and check.get("decoderResult") == 0  # BROTLI_DECODER_RESULT_ERROR
        and check.get("decoderError") == -17
        and check.get("formatBlockSwitchError") == -17
        and isinstance(check.get("decoderOutputBytes"), int)
        and 0 <= check["decoderOutputBytes"] <= BROTLI_MAX_PROBE_OUTPUT
        and isinstance(check.get("decoderCalls"), int)
        and 1 <= check["decoderCalls"] <= BROTLI_MAX_PROBE_CALLS
        and check.get("normalStreamCompatible") is True
    )


def cares_regression_succeeded(check, target_id, phase):
    if (target_id not in ("ubuntu-focal-amd64", "debian-trixie-amd64")
            or phase not in ("baseline", "patched")
            or check.get("cve") != "CVE-2026-69184"
            or check.get("timedOut") is not False
            or check.get("returncode") != 0):
        return False
    output = check.get("stdout", "")
    if target_id == "ubuntu-focal-amd64":
        expected_test = "c-ares-overlong-expanded-name-focal"
        outcome = "overlong_status=0 rejected=no" if phase == "baseline" else "overlong_status=8 rejected=yes"
        expected_flag = "vulnerabilityReproduced" if phase == "baseline" else "patchedBehavior"
        return (
            check.get("testId") == expected_test
            and check.get(expected_flag) is True
            and outcome in output
            and "maximum_name_accepted=yes" in output
        )
    expected_test = "c-ares-unbounded-pointer-chain"
    outcome = "status=0 record=present" if phase == "baseline" else "status=8 record=null"
    expected_flag = "vulnerabilityReproduced" if phase == "baseline" else "patchedBehavior"
    return (
        check.get("testId") == expected_test
        and check.get(expected_flag) is True
        and outcome in output
        and "valid_status=0 valid_record=present" in output
    )


def massif_peak_heap_bytes(path):
    try:
        content = Path(path).read_text()
    except OSError:
        return None
    values = [int(value) for value in re.findall(r"(?m)^mem_heap_B=(\d+)$", content)]
    return max(values) if values else None


def cares_record_count_regression_succeeded(check, target_id, phase):
    command = check.get("command", [])
    peak = check.get("peakHeapBytes")
    if (target_id != "debian-trixie-amd64" or phase not in ("baseline", "patched")
            or check.get("cve") != "CVE-2026-69186"
            or check.get("testId") != "c-ares-malformed-record-count-allocation"
            or check.get("timedOut") is not False or check.get("returncode") != 0
            or not isinstance(peak, int) or not command or Path(command[0]).name != "valgrind"
            or "--tool=massif" not in command or "--time-unit=B" not in command
            or "--stacks=no" not in command
            or not any(item.startswith("--massif-out-file=") for item in command)
            or Path(command[-1]).name != "c-ares-record-count"):
        return False
    output = check.get("stdout", "")
    if "malformed_rejected=yes" not in output or "valid_status=0 valid_record=present" not in output:
        return False
    if phase == "baseline":
        return check.get("vulnerabilityReproduced") is True and peak > CARES_RECORD_COUNT_HEAP_LIMIT
    return check.get("patchedBehavior") is True and peak < CARES_RECORD_COUNT_HEAP_LIMIT


def msgpack_unpacker_reuse_regression_succeeded(check, target_id, phase, expected_package_version):
    command = check.get("command", [])
    expected_target = target_id in ("debian-bookworm-amd64", "debian-trixie-amd64")
    if (not expected_target or phase not in ("baseline", "patched")
            or check.get("cve") != "CVE-2026-57585"
            or check.get("testId") != "python-msgpack-unpacker-error-reuse"
            or check.get("timedOut") is not False
            or not isinstance(expected_package_version, str)
            or not expected_package_version
            or len(command) != 2 or Path(command[0]).name != "python3"
            or Path(command[1]).name != "cve-2026-57585-unpacker-reuse.py"):
        return False
    output = check.get("stdout", "")
    required_identity = (
        "module_path=/usr/lib/python3/dist-packages/msgpack/"
        in output
        and "debian_package=python3-msgpack" in output
        and "module_owner=python3-msgpack" in output
        and f"debian_package_version={expected_package_version}" in output
    )
    if not required_identity:
        return False
    if phase == "baseline":
        return (check.get("returncode") == -signal.SIGSEGV
                and "caught expected ValueError" in output)
    return (check.get("returncode") == 0
            and "caught expected ValueError" in output
            and "after-error skip completed without process crash" in output)


def libpng_probe_command_matches(check, test_id, executable, arguments):
    command = check.get("command")
    prefix = ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
    if (check.get("testId") != test_id or not isinstance(command, list)
            or command[:5] != prefix or len(command) != 7 + len(arguments)
            or not command[5].startswith("--log-file=")):
        return False
    binary = Path(command[6])
    log = Path(command[5].split("=", 1)[1])
    allowed_log_names = {binary.name + ".valgrind"}
    cve = check.get("cve")
    if isinstance(cve, str) and cve.startswith("CVE-"):
        allowed_log_names.add(cve + ".valgrind")
    if (binary.name != executable or log.parent != binary.parent
            or log.name not in allowed_log_names):
        return False
    return all(
        Path(argument).name == expected and Path(argument).parent == binary.parent
        for argument, expected in zip(command[7:], arguments)
    )


def memcheck_has_no_errors(log):
    summaries = re.findall(r"(?m)^.*ERROR SUMMARY:\s*(.*?)\s*$", log)
    return (len(summaries) == 1
            and re.fullmatch(r"0 errors(?: from \d+ contexts)?(?: \(suppressed: \d+ from \d+\))?", summaries[0]) is not None)


def libpng_output_buffer_result(check, expected_result):
    log = check.get("memoryLog", "")
    return (check.get("cve") == "CVE-2025-65018"
            and libpng_probe_command_matches(check, "read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE])
            and not check.get("timedOut", False) and check.get("returncode") == 0
            and check.get("stdout", "").strip() == expected_result
            and memcheck_has_no_errors(log))


def libpng_overwrite_reproduced(check):
    return libpng_output_buffer_result(check, "result=overrun:output-buffer")


def libpng_stride_read_reproduced(check):
    log = check.get("memoryLog", "")
    return (check.get("cve") == "CVE-2026-22801"
            and libpng_probe_command_matches(check, "write-negative-stride.c", "write-negative-stride", [])
            and not check.get("timedOut", False) and check.get("returncode") == 97
            and "Invalid read" in log and "png_image_write_to_file" in log
            and "libpng16.so." in log)


def libpng_followup_read_is_clean(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 0
            and memcheck_has_no_errors(log))


def libpng_patched_checks_succeeded(checks):
    expected = {
        "CVE-2025-65018": ("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE]),
        "CVE-2026-22695": ("CVE-2026-22695-padded-stride-follow-up", "read-padded-stride", ["adam7.png"]),
        "CVE-2026-22801": ("write-negative-stride.c", "write-negative-stride", []),
    }
    by_cve = {}
    for cve in expected:
        matches = [check for check in checks if check.get("cve") == cve]
        if len(matches) != 1:
            return False
        by_cve[cve] = matches[0]
    for cve, (test_id, executable, arguments) in expected.items():
        check = by_cve[cve]
        if (check.get("passed") is not True
                or not libpng_probe_command_matches(check, test_id, executable, arguments)
                or check.get("timedOut") is not False
                or check.get("returncode") != 0
                or not memcheck_has_no_errors(check.get("memoryLog", ""))):
            return False
        if cve == "CVE-2025-65018" and check.get("stdout", "").strip() != "result=within-output-buffer":
            return False
    comparisons = [check for check in checks if check.get("testId") == "adam7-pixel-equality"]
    if len(comparisons) != 1:
        return False
    comparison = comparisons[0]
    command = comparison.get("command", [])
    return (
        comparison.get("passed") is True
        and not comparison.get("timedOut", False)
        and comparison.get("returncode") == 0
        and isinstance(command, list) and len(command) == 3
        and Path(command[0]).name == "compare-interlaced-read"
        and [Path(argument).name for argument in command[1:]] == ["adam7.png", "flat.png"]
        and Path(command[0]).parent == Path(command[1]).parent == Path(command[2]).parent
        and "differing channels: 0 / 3072" in comparison.get("stdout", "")
    )


def poppler_uaf_reproduced(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 97
            and any(error in log for error in ("Invalid read", "Invalid write", "Invalid free"))
            and "StructTreeRoot" in log and "parentTreeAdd" in log)


def poppler_revision6_probe_command(check):
    command = check.get("command", [])
    if (not isinstance(command, list) or len(command) != 8
            or not all(isinstance(argument, str) for argument in command)):
        return False
    return (
        Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and command[5].startswith("--log-file=")
        and Path(command[5][len("--log-file="):]).name == "revision6-password.valgrind"
        and Path(command[6]).name == "poppler-revision6-password"
        and Path(command[7]).name == "CVE-2026-107705-r6-encrypted.pdf"
    )


def poppler_revision6_password_overflow_reproduced(check):
    log = check.get("memoryLog", "")
    stderr = check.get("stderr", "")
    # The vulnerable write is performed while filling the fixed K1/E buffers
    # in revision6Hash(). A library mapping alone is too broad: require the
    # offending Valgrind error context to identify that implementation frame.
    error_contexts = re.findall(
        r"(?ms)^==\d+== Invalid write[^\n]*\n(.*?)(?=^==\d+== (?:Invalid |ERROR SUMMARY:))",
        log,
    )
    expected_hash_frame = any(
        re.search(r"(?:revision6Hash|Decrypt\.cc:17(?:6[4-9]|[7-9][0-9]))", context)
        for context in error_contexts
    )
    instrumented_write = (
        check.get("returncode") == 97
        and bool(error_contexts)
        and expected_hash_frame
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log)
    )
    stack_canary_abort = (
        check.get("returncode") == -6
        and stderr.strip() == "*** stack smashing detected ***: terminated"
        and re.search(r"Process terminating with default action of signal 6 \(SIGABRT\)", log)
        and "__stack_chk_fail" in log
    )
    return (
        not check.get("timedOut", False)
        and check.get("cve") == "CVE-2026-107705"
        and check.get("testId") == "CVE-2026-107705-revision6-long-owner-password"
        and poppler_revision6_probe_command(check)
        and re.search(r"\(in /usr/lib(?:/[^ )]+)?/libpoppler\.so(?:\.[0-9]+)*\)", log)
        and (instrumented_write or stack_canary_abort)
    )


def compile_poppler_revision6_probe(source, binary):
    pkg_flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "poppler"], text=True
    ))
    flags = []
    for flag in pkg_flags:
        if flag.startswith("-I") and len(flag) > 2:
            flags.extend(["-isystem", flag[2:]])
        else:
            flags.append(flag)
    command = ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", str(source), *flags,
               "-o", str(binary)]
    subprocess.run(command, check=True, timeout=30)
    return binary


def compile_libgit2_probe(source, binary, patched):
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "libgit2"], text=True
    ))
    command = ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-Wno-missing-field-initializers"]
    if patched:
        command.append("-DGETPATCHED_PATCHED=1")
    command.extend([str(source), *flags, "-o", str(binary)])
    subprocess.run(command, check=True, timeout=30)
    return binary


def compile_pkg_config_probe(source, binary, modules):
    cflags = subprocess.check_output(["pkg-config", "--cflags", *modules], text=True).split()
    libraries = subprocess.check_output(["pkg-config", "--libs", *modules], text=True).split()
    command = ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", *cflags,
               str(source), *libraries, "-o", str(binary)]
    subprocess.run(command, check=True, timeout=30)
    return binary


def parse_callback_urls(stdout):
    prefix = "callback_url="
    return [line[len(prefix):] for line in stdout.splitlines() if line.startswith(prefix)]


def parse_callback_url(stdout):
    urls = parse_callback_urls(stdout)
    return urls[0] if len(urls) == 1 else None


def libgit2_redirect_reproduced(check, phase):
    if check.get("timedOut") or check.get("returncode") != 0:
        return False
    callback_urls = check.get("callbackUrls", [])
    if not callback_urls:
        return False
    expected_origin = check.get("initialOrigin") if phase == "baseline" else check.get("redirectedOrigin")
    callback_origins = []
    for callback_url in callback_urls:
        parsed = urlsplit(callback_url)
        callback_origins.append(f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None)
    if any(origin != expected_origin for origin in callback_origins):
        return False
    if phase == "baseline":
        return check.get("redirectedHostReceivedFixtureCredential") is True
    return check.get("redirectedHostAuthorizationHeaderPresent") is False


def run_libgit2_redirect_regression(binary, temp, phase):
    fixture_credential = "Basic " + base64.b64encode(b"getpatched-test:fixture-only-credential").decode("ascii")
    target_state = {"authorizationHeaderPresent": False, "fixtureCredentialReceived": False}

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", target_origin + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format, *_args):
            pass

    class UnauthorizedHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            authorization = self.headers.get("Authorization")
            target_state["authorizationHeaderPresent"] |= authorization is not None
            target_state["fixtureCredentialReceived"] |= authorization == fixture_credential
            if authorization == fixture_credential:
                # End the baseline request after observing the dummy credential.
                # An empty Git advertisement makes libgit2 return promptly instead
                # of repeating the challenged request until the timeout.
                self.send_response(200)
                self.send_header("Content-Type", "application/x-git-upload-pack-advertisement")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="getpatched-test"')
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format, *_args):
            pass

    initial_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    target_server = ThreadingHTTPServer(("127.0.0.1", 0), UnauthorizedHandler)
    initial_server.daemon_threads = True
    target_server.daemon_threads = True
    target_origin = f"http://127.0.0.1:{target_server.server_address[1]}"
    initial_origin = f"http://127.0.0.1:{initial_server.server_address[1]}"
    servers = (initial_server, target_server)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    try:
        for thread in threads:
            thread.start()
        environment = {
            key: value for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
        }
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        environment["no_proxy"] = environment["NO_PROXY"]
        environment["GETPATCHED_TRUSTED_ORIGIN"] = initial_origin
        result = execute([
            str(binary), initial_origin + "/repository", str(temp / "redirect-clone"),
        ], timeout=30, env=environment)
        result["callbackUrls"] = parse_callback_urls(result["stdout"])
        result["redirectedHostAuthorizationHeaderPresent"] = target_state["authorizationHeaderPresent"]
        result["redirectedHostReceivedFixtureCredential"] = target_state["fixtureCredentialReceived"]
        return result, initial_origin, target_origin
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "patched"), required=True)
    parser.add_argument("--image-id", help="image digest or ID containing the installed package")
    parser.add_argument("--verification-id", help="unique identifier pairing the baseline and patched image checks")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.recipe / "package-manifest.json").read_text())
    validate_recipe_regression_fixture_hashes(args.recipe, manifest)
    policy = json.loads(args.policy.read_text())
    package = policy["source"]
    tiff_baseline_stack_frames = None
    if package == "tiff":
        patch_metadata = json.loads((args.recipe / "patches/metadata.json").read_text())
        regression = next((test for patch in patch_metadata.get("patches", [])
                           for test in patch.get("tests", [])
                           if test.get("id") == "tiffcrop-debug-sample-bounds"), None)
        tiff_baseline_stack_frames = (regression or {}).get("baselineStackSignatures", {}).get(policy["targetId"])
    fixtures = args.recipe / manifest["regressionTests"]["fixturesDirectory"]
    expected = policy["baseVersion"] if args.phase == "baseline" else policy["version"]
    binary_packages = policy.get("binaryPackages")
    if not isinstance(binary_packages, list) or not binary_packages or not all(
        isinstance(name, str) and name for name in binary_packages
    ):
        raise RuntimeError("Package policy has no installed binary package for version verification")
    installed_name = binary_packages[0]
    installed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", installed_name], text=True)
    if installed != expected:
        raise RuntimeError("Installed version mismatch: " + installed + " != " + expected)
    checks = []
    with tempfile.TemporaryDirectory(prefix="getpatched-regression-") as directory:
        temp = Path(directory)
        if package == "libxml2":
            for cve in policy["targetCves"]:
                if cve in ("CVE-2025-49794", "CVE-2025-49796"):
                    stem = cve.lower()
                    log = temp / (stem + ".valgrind")
                    check = execute([
                        "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes",
                        "--log-file=" + str(log), "xmllint", "--nonet", "--schematron",
                        str(fixtures / (stem + ".sct")), str(fixtures / (stem + "_0.xml")),
                    ])
                    check["cve"] = cve
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["passed"] = not check["timedOut"] and (
                        schematron_baseline_reproduced(check)
                        if args.phase == "baseline" else
                        check["returncode"] == 3 and "ERROR SUMMARY: 0 errors" in check["memoryLog"]
                    )
                    checks.append(check)
                elif cve == "CVE-2026-6653":
                    probe = temp / "libxml2-cve-2026-6653"
                    flags = shlex.split(subprocess.check_output(
                        ["pkg-config", "--cflags", "--libs", "libxml-2.0"], text=True, timeout=15
                    ))
                    compiled = subprocess.run(
                        ["c++", "-std=c++11", "-O1", "-g", str(fixtures / "cve-2026-6653-harness.cc"),
                         "-o", str(probe), *flags],
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    if compiled.returncode != 0:
                        raise RuntimeError("could not compile the libxml2 CVE-2026-6653 regression harness: " + compiled.stderr[-2000:])
                    log = temp / "cve-2026-6653.valgrind"
                    check = execute([
                        "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes", "--log-file=" + str(log), str(probe),
                        str(fixtures / "cve-2026-6653.xml"),
                    ])
                    check["cve"] = cve
                    check["testId"] = "parameter-entity-eof-use-after-free"
                    check["memoryLogPath"] = str(log)
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["passed"] = (
                        libxml2_parameter_entity_baseline_reproduced(check)
                        if args.phase == "baseline" else libxml2_parameter_entity_patched_succeeded(check)
                    )
                    checks.append(check)
                elif cve == "CVE-2026-86144":
                    probe = temp / "libxml2-cve-2026-86144"
                    flags = shlex.split(subprocess.check_output(
                        ["pkg-config", "--cflags", "--libs", "libxml-2.0"], text=True, timeout=15
                    ))
                    compiled = subprocess.run(
                        ["c++", "-std=c++11", "-O1", "-g", str(fixtures / "cve-2026-86144-xinclude-harness.cc"),
                         "-pthread", "-o", str(probe), *flags],
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    if compiled.returncode != 0:
                        raise RuntimeError("could not compile the libxml2 CVE-2026-86144 regression harness: " + compiled.stderr[-2000:])
                    for api in ("document", "tree"):
                        mode = "expect-network" if args.phase == "baseline" else "expect-blocked"
                        check = execute([
                            str(probe), str(fixtures / "cve-2026-86144-xinclude.xml"), api, mode,
                        ], timeout=10)
                        check["cve"] = cve
                        check["testId"] = "xinclude-nonet-" + api
                        check["phase"] = args.phase
                        check["passed"] = libxml2_xinclude_nonet_result(check, args.phase)
                        checks.append(check)
                elif cve == "CVE-2026-76781":
                    probe = temp / "libxml2-cve-2026-76781"
                    flags = shlex.split(subprocess.check_output(
                        ["pkg-config", "--cflags", "--libs", "libxml-2.0"], text=True, timeout=15
                    ))
                    compiled = subprocess.run(
                        ["cc", "-std=c11", "-O1", "-g", str(fixtures / "cve-2026-76781-catalog-harness.c"),
                         "-o", str(probe), *flags],
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    if compiled.returncode != 0:
                        raise RuntimeError("could not compile the libxml2 CVE-2026-76781 regression harness: " + compiled.stderr[-2000:])
                    log = temp / "cve-2026-76781.valgrind"
                    check = execute([
                        "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes", "--log-file=" + str(log), str(probe),
                        str(fixtures / "cve-2026-76781-catalog.xml"),
                    ], timeout=20)
                    check["cve"] = cve
                    check["testId"] = "catalog-next-catalog-missing-attribute"
                    check["memoryLogPath"] = str(log)
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["passed"] = (
                        libxml2_catalog_baseline_reproduced(check)
                        if args.phase == "baseline" else libxml2_catalog_patched_succeeded(check)
                    )
                    checks.append(check)
                elif cve == "CVE-2026-86141":
                    probe = temp / "libxml2-cve-2026-86141"
                    flags = shlex.split(subprocess.check_output(
                        ["pkg-config", "--cflags", "--libs", "libxml-2.0"], text=True, timeout=15
                    ))
                    compiled = subprocess.run(
                        ["cc", "-std=c11", "-O1", "-g", str(fixtures / "cve-2026-86141-regexp-alloc-failure.c"),
                         "-o", str(probe), *flags],
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    if compiled.returncode != 0:
                        raise RuntimeError("could not compile the libxml2 CVE-2026-86141 regression harness: " + compiled.stderr[-2000:])
                    log = temp / "cve-2026-86141.valgrind"
                    check = execute([
                        "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                        "--read-var-info=yes", "--log-file=" + str(log), str(probe),
                    ], timeout=15)
                    check["cve"] = cve
                    check["testId"] = "regexp-allocation-failure-null-check"
                    check["injection"] = "xmlMemSetup:test_malloc:sizeof-regexp"
                    check["memoryLogPath"] = str(log)
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["phase"] = args.phase
                    check["passed"] = (
                        libxml2_regexp_alloc_failure_baseline_reproduced(check)
                        if args.phase == "baseline" else libxml2_regexp_alloc_failure_patched_succeeded(check)
                    )
                    checks.append(check)
                else:
                    raise RuntimeError("no libxml2 regression is configured for " + cve)
            if args.phase == "patched":
                normal = temp / "normal.xml"
                normal.write_text("<document><item>compatible</item></document>\n")
                check = execute(["xmllint", "--nonet", "--xpath", "string(/document/item)", str(normal)])
                check["passed"] = check["returncode"] == 0 and check["stdout"] == "compatible\n"
                checks.append(check)
        elif package == "libarchive":
            if policy["targetId"] == "debian-trixie-amd64":
                source_report_path = args.output.parent / f"libarchive-source-ubsan-{args.phase}.json"
                source_report = json.loads(source_report_path.read_text())
                source_provenance_path = args.output.parent / "source-provenance.json"
                if (not source_provenance_path.is_file()
                        or hashlib.sha256(source_provenance_path.read_bytes()).hexdigest()
                        != source_report.get("sourceProvenanceSha256")):
                    raise RuntimeError("exact-source UBSan report is not bound to this build's pinned source provenance")
                recipe_manifest = json.loads((args.recipe / "package-manifest.json").read_text())
                recipe_target_ref = next(item for item in recipe_manifest["targets"] if item["id"] == policy["targetId"])
                recipe_target = json.loads((args.recipe / recipe_target_ref["file"]).read_text())
                recipe_patch_metadata = json.loads((args.recipe / recipe_manifest["patchMetadata"]).read_text())
                recipe_patches = [
                    item for item in recipe_patch_metadata["patches"]
                    if item.get("id") in recipe_target["patches"] and "CVE-2026-16517" in item.get("cves", [])
                ]
                if len(recipe_patches) != 1:
                    raise RuntimeError("recipe does not identify one exact CVE-2026-16517 patch")
                expected_patch = recipe_patches[0]
                if (source_report.get("runner") != "getpatched-libarchive-source-ubsan/1"
                        or source_report.get("phase") != args.phase
                        or source_report.get("cryptoBackend") != "nettle"
                        or source_report.get("evidenceType") != "exact-source-ubsan; installed package behavior is reported separately"
                        or source_report.get("targetId") != policy["targetId"]
                        or source_report.get("sourceVersion") != policy["baseVersion"]
                        or source_report.get("sourceDescriptorSha256") != recipe_target["source"]["descriptor"]["sha256"]
                        or source_report.get("patchId") != expected_patch["id"]
                        or source_report.get("patchSha256") != expected_patch["sha256"]
                        or source_report.get("changelogVersion") != (policy["baseVersion"] if args.phase == "baseline" else policy["version"])
                        or not re.fullmatch(r"[0-9a-f]{64}", str(source_report.get("sourceProvenanceSha256", "")))
                        or not re.fullmatch(r"[0-9a-f]{64}", str(source_report.get("sourceTreeSha256", "")))
                        or not re.fullmatch(r"[0-9a-f]{64}", str(source_report.get("vulnerableFileSha256", "")))
                        or source_report.get("patchApplied") is not (args.phase == "patched")
                        or source_report.get("passed") is not True):
                    raise RuntimeError("exact-source UBSan regression is missing or failed")
                if args.phase == "baseline" and source_report.get("sourceVulnerabilityReproduced") is not True:
                    raise RuntimeError("exact-source UBSan baseline did not reproduce the signed overflow")
                if args.phase == "patched" and source_report.get("patchedBehavior") is not True:
                    raise RuntimeError("exact-source patched UBSan test did not complete cleanly")
                probe = compile_pkg_config_probe(
                    fixtures / "zip-encrypted-size-overflow.c", temp / "zip-encrypted-size-overflow", ["libarchive"]
                )
                check = execute([str(probe)], timeout=5)
                check["cve"] = "CVE-2026-16517"
                check["headerGenerationSucceeded"] = (
                    not check["timedOut"] and check["returncode"] == 0
                    and "GETPATCHED:ZIP_HEADER_START" in check["stderr"]
                    and "GETPATCHED:ZIP_HEADER_RETURN" in check["stderr"]
                )
                check["sourceRegressionSha256"] = hashlib.sha256(source_report_path.read_bytes()).hexdigest()
                check["sourceProvenanceSha256"] = source_report["sourceProvenanceSha256"]
                check["sourceVulnerabilityReproduced"] = source_report.get("sourceVulnerabilityReproduced") is True
                check["patchedBehavior"] = source_report.get("patchedBehavior") is True
                check["passed"] = check["headerGenerationSucceeded"] and source_report["passed"] is True
                checks.append(check)
                if args.phase == "patched":
                    item = temp / "consumer.txt"
                    item.write_text("consumer round trip\n")
                    archive = temp / "consumer.tar.gz"
                    create = execute(["bsdtar", "-czf", str(archive), "-C", str(temp), item.name])
                    extract = execute(["bsdtar", "-xOf", str(archive), item.name])
                    create["passed"] = create["returncode"] == 0
                    extract["passed"] = extract["returncode"] == 0 and extract["stdout"] == item.read_text()
                    checks.extend([create, extract])
            else:
                lines = (fixtures / "test_read_format_rar5_loop_bug.rar.uu").read_bytes().splitlines()
                start = next(i for i, line in enumerate(lines) if line.startswith(b"begin "))
                data = bytearray()
                for line in lines[start + 1:]:
                    if line == b"end": break
                    data.extend(binascii.a2b_uu(line))
                if not 0 < len(data) < 1024 * 1024:
                    raise RuntimeError("Fixture exceeds regression resource bound")
                fixture = temp / "loop.rar"
                fixture.write_bytes(data)
                probe = temp / "archive-probe"
                subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("archive-probe.c")), "-larchive", "-o", str(probe)], check=True, timeout=30)
                check = execute([str(probe), str(fixture)], timeout=5)
                check["cve"] = "CVE-2026-4111"
                check["passed"] = check["timedOut"] if args.phase == "baseline" else not check["timedOut"] and check["returncode"] == 0
                checks.append(check)
                if args.phase == "patched":
                    item = temp / "consumer.txt"
                    item.write_text("consumer round trip\n")
                    archive = temp / "consumer.tar.gz"
                    create = execute(["bsdtar", "-czf", str(archive), "-C", str(temp), item.name])
                    extract = execute(["bsdtar", "-xOf", str(archive), item.name])
                    create["passed"] = create["returncode"] == 0
                    extract["passed"] = extract["returncode"] == 0 and extract["stdout"] == item.read_text()
                    checks.extend([create, extract])
        elif package == "c-ares":
            if policy["targetId"] == "ubuntu-focal-amd64":
                probe = compile_pkg_config_probe(
                    fixtures / "c-ares-name-length.c", temp / "c-ares-name-length", ["libcares"]
                )
                check = execute([str(probe)], timeout=5)
                output = check["stdout"]
                check["testId"] = "c-ares-overlong-expanded-name-focal"
                check["vulnerabilityReproduced"] = (
                    "overlong_status=0 rejected=no" in output
                    and "maximum_name_accepted=yes" in output
                )
                check["patchedBehavior"] = (
                    "overlong_status=8 rejected=yes" in output
                    and "maximum_name_accepted=yes" in output
                )
            else:
                probe = compile_pkg_config_probe(
                    fixtures / "c-ares-pointer-chain.c", temp / "c-ares-pointer-chain", ["libcares"]
                )
                check = execute([str(probe)], timeout=5)
                output = check["stdout"]
                check["testId"] = "c-ares-unbounded-pointer-chain"
                check["vulnerabilityReproduced"] = (
                    "status=0 record=present" in output
                    and "valid_status=0 valid_record=present" in output
                )
                check["patchedBehavior"] = (
                    "status=8 record=null" in output
                    and "valid_status=0 valid_record=present" in output
                )
            check["cve"] = "CVE-2026-69184"
            check["passed"] = cares_regression_succeeded(check, policy["targetId"], args.phase)
            checks.append(check)
            if "CVE-2026-69186" in policy.get("targetCves", []):
                if policy["targetId"] != "debian-trixie-amd64":
                    raise RuntimeError("CVE-2026-69186 regression is only defined for Debian Trixie amd64")
                probe = compile_pkg_config_probe(
                    fixtures / "c-ares-record-count.c", temp / "c-ares-record-count", ["libcares"]
                )
                massif_file = temp / "c-ares-record-count.massif"
                check = execute([
                    "valgrind", "--tool=massif", "--time-unit=B", "--stacks=no",
                    "--massif-out-file=" + str(massif_file), str(probe),
                ], timeout=20)
                check["testId"] = "c-ares-malformed-record-count-allocation"
                check["cve"] = "CVE-2026-69186"
                check["massifFile"] = massif_file.name
                check["peakHeapBytes"] = massif_peak_heap_bytes(massif_file)
                check["vulnerabilityReproduced"] = (
                    check["peakHeapBytes"] is not None
                    and check["peakHeapBytes"] > CARES_RECORD_COUNT_HEAP_LIMIT
                )
                check["patchedBehavior"] = (
                    check["peakHeapBytes"] is not None
                    and check["peakHeapBytes"] < CARES_RECORD_COUNT_HEAP_LIMIT
                )
                check["passed"] = cares_record_count_regression_succeeded(
                    check, policy["targetId"], args.phase
                )
                checks.append(check)
        elif package == "python-msgpack":
            if policy["targetId"] not in ("debian-bookworm-amd64", "debian-trixie-amd64"):
                raise RuntimeError("CVE-2026-57585 regression is only defined for Debian Bookworm and Trixie amd64")
            fixture = fixtures / "cve-2026-57585-unpacker-reuse.py"
            check = execute(["python3", str(fixture)], timeout=5)
            check["testId"] = "python-msgpack-unpacker-error-reuse"
            check["cve"] = "CVE-2026-57585"
            expected_package_version = (
                policy["baseVersion"] if args.phase == "baseline" else policy["version"]
            )
            check["installedPackage"] = "python3-msgpack"
            package_version_match = re.search(
                r"(?m)^debian_package_version=(\S+)$", check["stdout"]
            )
            check["installedPackageVersion"] = (
                package_version_match.group(1) if package_version_match else None
            )
            check["vulnerabilityReproduced"] = (
                check["returncode"] == -signal.SIGSEGV
                and "caught expected ValueError" in check["stdout"]
            )
            check["patchedBehavior"] = (
                check["returncode"] == 0
                and "caught expected ValueError" in check["stdout"]
                and "after-error skip completed without process crash" in check["stdout"]
            )
            check["passed"] = msgpack_unpacker_reuse_regression_succeeded(
                check, policy["targetId"], args.phase, expected_package_version
            )
            checks.append(check)
        elif package == "brotli":
            probe = compile_pkg_config_probe(
                fixtures / "brotli-stream-probe.c", temp / "brotli-stream-probe",
                ["libbrotlidec", "libbrotlienc"],
            )
            check = execute([str(probe), str(fixtures / "invalid-block-switch.hex")], timeout=5)
            check["cve"] = "CVE-2026-111497"
            check["testId"] = "brotli-invalid-block-switch"
            match = re.search(
                r"malformed_result=(-?\d+) error=(-?\d+) format_error=(-?\d+) "
                r"input_remaining=(\d+) output=(\d+) calls=(\d+)",
                check["stdout"],
            )
            if match:
                result, error, expected_format_error, input_remaining, output_bytes, calls = map(int, match.groups())
                check["decoderResult"] = result
                check["decoderError"] = error
                check["formatBlockSwitchError"] = expected_format_error
                check["inputRemaining"] = input_remaining
                check["decoderOutputBytes"] = output_bytes
                check["decoderCalls"] = calls
            else:
                check["decoderResult"] = None
                check["decoderError"] = None
                check["formatBlockSwitchError"] = None
                check["inputRemaining"] = None
                check["decoderOutputBytes"] = None
                check["decoderCalls"] = None
            check["normalStreamCompatible"] = "compatible=yes" in check["stdout"]
            check["vulnerabilityReproduced"] = brotli_baseline_reproduced(check)
            check["patchedBehavior"] = brotli_patched_succeeded(check)
            check["passed"] = (
                not check["timedOut"] and check["returncode"] == 0
                and check["normalStreamCompatible"]
                and (check["vulnerabilityReproduced"] if args.phase == "baseline"
                     else check["patchedBehavior"])
            )
            checks.append(check)
        elif package == "expat":
            probe = compile_pkg_config_probe(
                fixtures / "CVE-2026-117610-empty-subparser.c", temp / "expat-empty-subparser", ["expat"]
            )
            check = execute([str(probe)])
            check["cve"] = "CVE-2026-117610"
            check["testId"] = "CVE-2026-117610-empty-nonfinal-subparser"
            check["passed"] = expat_regression_succeeded(check, args.phase)
            checks.append(check)
            source_version = policy["baseVersion"].split("-", 1)[0]
            consumer = execute(["xmlwf", "-v"])
            consumer["testId"] = "expat-xmlwf-version"
            consumer["passed"] = expat_consumer_succeeded(consumer, source_version)
            checks.append(consumer)
        elif package == "tiff":
            fixture = fixtures / "multisample.tif"
            if tiff_cve_required(policy, "CVE-2026-18495"):
                fixture_source = fixtures / "CVE-2026-18495-bigstrip.c"
                shim_source = fixtures / "CVE-2026-18495-bounded-read-shim.c"
                fixture_generator = temp / "CVE-2026-18495-fixture"
                generated = temp / "CVE-2026-18495-bigstrip.tif"
                shim = temp / "CVE-2026-18495-bounded-read-shim.so"
                subprocess.run(
                    ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                     str(fixture_source), "-o", str(fixture_generator)],
                    check=True, timeout=30,
                )
                subprocess.run(
                    ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                     str(shim_source), "-ldl", "-o", str(shim)],
                    check=True, timeout=30,
                )
                generated_check = execute([str(fixture_generator), str(generated)])
                if (generated_check.get("timedOut") or generated_check.get("returncode") != 0
                        or not generated.is_file() or generated.stat().st_size != 304):
                    raise RuntimeError("Could not generate the bounded CVE-2026-18495 BigTIFF fixture")
                inspected = execute(["tiffinfo", "-s", str(generated)])
                if (inspected.get("timedOut") or inspected.get("returncode") != 0
                        or "4294967301" not in inspected.get("stdout", "")):
                    raise RuntimeError("CVE-2026-18495 fixture has the wrong BigTIFF strip byte count")
                memory_log = temp / "CVE-2026-18495.valgrind"
                command = [
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(memory_log),
                    "tiff2pdf", "-m", "0", "-o", str(temp / "CVE-2026-18495-output.pdf"),
                    str(generated),
                ]
                environment = os.environ.copy()
                environment.pop("LD_PRELOAD", None)
                allocation_cap_enabled = args.phase == "patched"
                environment["LD_PRELOAD"] = str(shim)
                environment.pop("GETPATCHED_TIFF_ALLOC_CAP_ENABLED", None)
                if allocation_cap_enabled:
                    environment["GETPATCHED_TIFF_ALLOC_CAP_ENABLED"] = "1"
                else:
                    environment["GETPATCHED_TIFF_STOP_AFTER_BOUNDED_READ"] = "1"
                check = execute(command, timeout=20, env=environment)
                check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
                check["memoryLogPath"] = str(memory_log)
                check["fixtureSizeBytes"] = generated.stat().st_size
                check["declaredStripBytes"] = 4294967301
                check["allocationCapEnabled"] = allocation_cap_enabled
                check["memoryMappingDisabled"] = "GETPATCHED_TIFF_MMAP_DISABLED" in check.get("stderr", "")
                check["cve"] = "CVE-2026-18495"
                check["testId"] = "tiff2pdf-bigtiff-strip-length-truncation"
                check["passed"] = (
                    tiff_bigstrip_baseline_reproduced(check)
                    if args.phase == "baseline" else tiff_bigstrip_patched_succeeded(check)
                )
                checks.append(check)
            if tiff_cve_required(policy, "CVE-2026-12912"):
                source = fixtures / "pixarlog-abgr.c"
                probe = temp / "pixarlog-abgr"
                generated = temp / "pixarlog-abgr.tif"
                subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                                str(source), "-ltiff", "-o", str(probe)],
                               check=True, timeout=30)
                create = execute([str(probe), "generate", str(generated)])
                if (create.get("timedOut") or create.get("returncode") != 0
                        or not generated.is_file()
                        or not 0 < generated.stat().st_size < 1024 * 1024):
                    raise RuntimeError("Could not generate bounded PixarLog CVE regression input")
                memory_log = temp / "CVE-2026-12912.valgrind"
                check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(memory_log),
                    str(probe), "decode", str(generated),
                ])
                check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
                check["memoryLogPath"] = str(memory_log)
                check["cve"] = "CVE-2026-12912"
                check["testId"] = "pixarlog-abgr-rgb-multirow-strip-overflow"
                check["passed"] = (pixarlog_baseline_reproduced(check) if args.phase == "baseline"
                                   else pixarlog_patched_succeeded(check))
                checks.append(check)
            if not fixture.is_file() or not 0 < fixture.stat().st_size < 1024 * 1024:
                raise RuntimeError("TIFF regression fixture is missing or exceeds its size bound")
            output = temp / "tiffcrop-output.tif"
            if tiff_cve_required(policy, "CVE-2025-61143"):
                null_dump_prefix = temp / "tiffcrop-null-output"
                null_log = temp / "tiffcrop-null-output.valgrind"
                null_check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(null_log),
                    "tiffcrop", "-U", "px", "-m", "0,2,0,2", "-D",
                    f"format:txt,level:2,output:{null_dump_prefix}", str(fixture), str(output),
                ])
                null_check["memoryLog"] = null_log.read_text() if null_log.exists() else ""
                null_check["memoryLogPath"] = str(null_log)
                debug_path = Path(str(null_dump_prefix) + "-write-001.txt")
                null_check["debugOutputPath"] = str(debug_path)
                null_check["debugOutputFiles"] = [path.name for path in sorted(temp.glob("tiffcrop-null-output-write-*.txt"))]
                null_check["debugOutput"] = (
                    debug_path.read_text() if debug_path.is_file() and debug_path.stat().st_size <= 1024 * 1024 else ""
                )
                null_check["cve"] = "CVE-2025-61143"
                null_check["testId"] = "tiffcrop-null-output-debug-log"
                null_check["passed"] = (
                    tiff_null_output_baseline_reproduced(null_check)
                    if args.phase == "baseline"
                    else tiff_null_output_patched_succeeded(null_check)
                )
                checks.append(null_check)

            if tiff_cve_required(policy, "CVE-2025-61144"):
                dump_prefix = temp / "tiffcrop-debug"
                command = [
                    "tiffcrop", "-D", f"format:txt,level:2,input:{dump_prefix}",
                    str(fixture), str(output),
                ]
                memory_log = temp / "tiffcrop-valgrind.log"
                check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(memory_log), *command,
                ])
                check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
                check["memoryLogPath"] = str(memory_log)
                check["cve"] = "CVE-2025-61144"
                check["testId"] = "tiffcrop-debug-sample-bounds"
                check["baselineStackFrames"] = tiff_baseline_stack_frames
                check["passed"] = (
                    tiff_baseline_reproduced(check, tiff_baseline_stack_frames)
                    if args.phase == "baseline"
                    else tiff_patched_regression_succeeded(check)
                    and output.is_file() and output.stat().st_size > 0
                )
                checks.append(check)

            if tiff_cve_required(policy, "CVE-2026-52490"):
                check = execute(TIFF_SUBDIVISION_OVERFLOW_COMMAND, timeout=10)
                check["cve"] = "CVE-2026-52490"
                check["testId"] = "tiffcrop-subdivision-overflow-check"
                check["passed"] = (
                    tiff_subdivision_baseline_reproduced(check)
                    if args.phase == "baseline"
                    else tiff_subdivision_patched_succeeded(check)
                )
                checks.append(check)

            if args.phase == "patched":
                consumer = execute(["tiffinfo", str(output)])
                consumer["passed"] = consumer["returncode"] == 0 and "Image Width" in consumer["stdout"]
                checks.append(consumer)
        elif package == "libpng1.6":
            cflags = []
            libs = ["-lpng16", "-lz"]
            cve_fixture_source = fixtures / LIBPNG_CVE_2025_65018_FIXTURE
            if not cve_fixture_source.is_file():
                raise RuntimeError("the CVE-2025-65018 RGB16 Adam7 fixture is missing")
            cve_fixture_data = cve_fixture_source.read_bytes()
            if hashlib.sha256(cve_fixture_data).hexdigest() != LIBPNG_CVE_2025_65018_FIXTURE_SHA256:
                raise RuntimeError("the CVE-2025-65018 RGB16 Adam7 fixture hash does not match metadata")
            cve_fixture = temp / LIBPNG_CVE_2025_65018_FIXTURE
            cve_fixture.write_bytes(cve_fixture_data)

            def compile_probe(name):
                binary = temp / Path(name).stem
                subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                                *cflags, str(fixtures.parent / name), *libs, "-o", str(binary)],
                               check=True, timeout=30)
                return binary

            adam7 = temp / "adam7.png"
            flat = temp / "flat.png"
            generator = fixtures.parent / "generate-adam7-rgb16.py"
            subprocess.run(["python3", str(generator), str(adam7)], check=True, timeout=10)
            subprocess.run(["python3", str(generator), str(flat), "--flat"], check=True, timeout=10)
            if args.phase == "baseline":
                for cve, source in (
                    ("CVE-2025-65018", "read-interlaced-rgba.c"),
                    ("CVE-2026-22801", "write-negative-stride.c"),
                ):
                    binary = compile_probe(source)
                    log = temp / (cve + ".valgrind")
                    check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                     "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                     str(binary), *([str(cve_fixture)] if cve == "CVE-2025-65018" else [])])
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["cve"] = cve
                    check["testId"] = source
                    check["passed"] = (libpng_overwrite_reproduced(check) if cve == "CVE-2025-65018"
                                       else libpng_stride_read_reproduced(check))
                    checks.append(check)
                binary = compile_probe("read-padded-stride.c")
                log = temp / "CVE-2026-22695.valgrind"
                check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                 "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                 str(binary), str(adam7)])
                check["memoryLog"] = log.read_text() if log.exists() else ""
                check["cve"] = "CVE-2026-22695"
                check["testId"] = "CVE-2026-22695-padded-stride-follow-up"
                check["passed"] = libpng_followup_read_is_clean(check)
                checks.append(check)
            else:
                for cve, name, args_for_probe in (
                    ("CVE-2025-65018", "read-interlaced-rgba.c", [str(cve_fixture)]),
                    ("CVE-2026-22695", "read-padded-stride.c", [str(adam7)]),
                    ("CVE-2026-22801", "write-negative-stride.c", []),
                ):
                    binary = compile_probe(name)
                    log = temp / (binary.name + ".valgrind")
                    check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                     "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                     str(binary), *args_for_probe])
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["cve"] = cve
                    check["testId"] = name
                    if cve == "CVE-2025-65018":
                        check["passed"] = libpng_output_buffer_result(check, "result=within-output-buffer")
                    elif cve == "CVE-2026-22695":
                        check["passed"] = libpng_followup_read_is_clean(check)
                    else:
                        check["passed"] = (not check.get("timedOut") and check.get("returncode") == 0
                                           and memcheck_has_no_errors(check["memoryLog"]))
                    checks.append(check)
                comparison = compile_probe("compare-interlaced-read.c")
                check = execute([str(comparison), str(adam7), str(flat)])
                check["passed"] = check["returncode"] == 0 and "differing channels: 0 / 3072" in check["stdout"]
                check["testId"] = "adam7-pixel-equality"
                checks.append(check)
                checks[1]["testId"] = "CVE-2026-22695-padded-stride-follow-up"
        elif package == "poppler":
            target_cves = set(policy.get("targetCves", []))
            if "CVE-2025-52885" in target_cves:
                fixture = fixtures / "bug.pdf"
                if not fixture.is_file() or not 0 < fixture.stat().st_size < 1024 * 1024:
                    raise RuntimeError("Poppler CVE regression fixture is missing or exceeds its size bound")
                memory_log = temp / "pdfinfo.valgrind"
                check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(memory_log),
                    "pdfinfo", "-struct", str(fixture),
                ])
                check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
                check["cve"] = "CVE-2025-52885"
                check["testId"] = "CVE-2025-52885-structtree-uaf"
                check["passed"] = (
                    poppler_uaf_reproduced(check)
                    if args.phase == "baseline"
                    else not check.get("timedOut") and check.get("returncode") == 0
                    and "ERROR SUMMARY: 0 errors" in check["memoryLog"]
                )
                checks.append(check)
                if args.phase == "patched":
                    consumer = execute(["pdfinfo", "-v"])
                    consumer["passed"] = consumer_version_succeeded(consumer, "pdfinfo version")
                    checks.append(consumer)
            if "CVE-2026-107705" in target_cves:
                probe_source = fixtures / "CVE-2026-107705-revision6-password.cpp"
                fixture = fixtures / "CVE-2026-107705-r6-encrypted.pdf"
                if (not probe_source.is_file() or not 0 < probe_source.stat().st_size < 64 * 1024
                        or not fixture.is_file() or not 0 < fixture.stat().st_size < 1024 * 1024):
                    raise RuntimeError("Poppler revision 6 probe or encrypted PDF fixture is missing or exceeds its size bound")
                probe = compile_poppler_revision6_probe(probe_source, temp / "poppler-revision6-password")
                memory_log = temp / "revision6-password.valgrind"
                check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(memory_log), str(probe), str(fixture),
                ])
                check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
                check["cve"] = "CVE-2026-107705"
                check["testId"] = "CVE-2026-107705-revision6-long-owner-password"
                check["passed"] = (
                    poppler_revision6_password_overflow_reproduced(check)
                    if args.phase == "baseline"
                    else not check.get("timedOut") and check.get("returncode") == 0
                    and "ERROR SUMMARY: 0 errors" in check["memoryLog"]
                )
                checks.append(check)
                if args.phase == "patched":
                    consumer = execute(["pdfinfo", "-v"])
                    consumer["passed"] = consumer_version_succeeded(consumer, "pdfinfo version")
                    checks.append(consumer)
        elif package == "imagemagick":
            expected_version = policy["baseVersion"] if args.phase == "baseline" else policy["version"]
            installed_versions = {}
            for binary_package in policy["binaryPackages"]:
                installed_version = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Version}", binary_package], text=True
                )
                if installed_version != expected_version:
                    raise RuntimeError(
                        f"Installed ImageMagick package version mismatch: {binary_package}="
                        f"{installed_version} != {expected_version}"
                    )
                installed_versions[binary_package] = installed_version
            binary_path = Path("/usr/bin/magick").resolve(strict=True)
            if binary_path != Path("/usr/bin/magick-im7.q16"):
                raise RuntimeError(f"/usr/bin/magick resolves to an unexpected binary: {binary_path}")
            binary_owner = subprocess.check_output(
                ["dpkg-query", "-S", str(binary_path)], text=True
            ).split(":", 1)[0]
            if binary_owner != "imagemagick-7.q16":
                raise RuntimeError(f"{binary_path} is not owned by the pinned imagemagick-7.q16 package")
            log = temp / "CVE-2026-119124.valgrind"
            output = temp / "morph.miff"
            check = execute([
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--track-origins=yes", "--log-file=" + str(log), "/usr/bin/magick",
                str(fixtures / "first-graya.png"), str(fixtures / "second-srgb.png"),
                "-morph", "1", str(output),
            ], timeout=120)
            check["cve"] = "CVE-2026-119124"
            check["testId"] = "imagemagick-morph-channel-bounds"
            check["memoryLogPath"] = str(log)
            check["memoryLog"] = log.read_text(errors="replace") if log.exists() else ""
            check["expectedPackageVersion"] = expected_version
            check["installedPackageVersions"] = installed_versions
            check["magickBinaryOwner"] = binary_owner
            check["magickBinaryPath"] = str(binary_path)
            if args.phase == "patched" and output.is_file():
                frames = subprocess.run(["/usr/bin/magick", "identify", "-format", "x", str(output)],
                                        capture_output=True, text=True, timeout=30, check=False)
                check["outputFrames"] = len(frames.stdout) if frames.returncode == 0 else None
                check["outputInspectReturncode"] = frames.returncode
            check["passed"] = imagemagick_morph_check_succeeded(check, args.phase)
            checks.append(check)
        elif package == "libgit2":
            patched = args.phase == "patched"
            pack_probe = compile_libgit2_probe(
                fixtures / "pack-size-limit.c", temp / "pack-size-limit", patched
            )
            pack_work = temp / "pack-indexer"
            pack_work.mkdir()
            pack_check = execute([
                str(pack_probe), str(fixtures / "delta_100mb.pack"), str(pack_work)
            ], timeout=45)
            pack_check["cve"] = "CVE-2026-53585"
            pack_check["declaredObjectSize"] = 100 * 1024 * 1024
            pack_check["configuredObjectLimit"] = 42 * 1024 * 1024 if patched else None
            pack_check["result"] = pack_check["stdout"].strip()
            pack_check["rejectedLargeObject"] = patched and pack_check["result"] == "result=rejected:overly-large-object"
            pack_check["baselineAcceptedLargeObject"] = not patched and pack_check["result"] == "result=accepted:large-object"
            pack_check["passed"] = pack_check["returncode"] == 0 and not pack_check["timedOut"]
            checks.append(pack_check)

            submodule_probe = compile_libgit2_probe(
                fixtures / "submodule-path.c", temp / "submodule-path", patched
            )
            repo_parent = temp / "submodule-workspace"
            repo_parent.mkdir()
            repo_path = repo_parent / "repo"
            escaped_path = repo_parent / "escape-target"
            submodule_check = execute([str(submodule_probe), str(repo_path)], timeout=20)
            submodule_check["cve"] = "CVE-2026-53584"
            submodule_check["outsideDirectoryCreated"] = escaped_path.is_dir()
            submodule_check["result"] = submodule_check["stdout"].strip()
            submodule_check["baselinePathEscapeReproduced"] = (
                not patched and submodule_check["returncode"] == 0
                and submodule_check["outsideDirectoryCreated"]
                and submodule_check["result"] == "result=created:escaped-submodule-directory"
            )
            submodule_check["patchedPathRejected"] = (
                patched and submodule_check["returncode"] == 0
                and not submodule_check["outsideDirectoryCreated"]
                and submodule_check["result"] == "result=rejected:invalid-submodule-path"
            )
            submodule_check["passed"] = (
                submodule_check["baselinePathEscapeReproduced"] if not patched
                else submodule_check["patchedPathRejected"]
            )
            checks.append(submodule_check)

            redirect_probe = compile_libgit2_probe(
                fixtures / "redirect-auth.c", temp / "redirect-auth", patched
            )
            redirect_result, initial_origin, target_origin = run_libgit2_redirect_regression(
                redirect_probe, temp, args.phase
            )
            redirect_result["cve"] = "CVE-2026-53586"
            redirect_result["initialOrigin"] = initial_origin
            redirect_result["redirectedOrigin"] = target_origin
            redirect_result["initialOrigin"] = initial_origin
            redirect_result["redirectedOrigin"] = target_origin
            redirect_result["callbackOrigin"] = []
            for callback_url in redirect_result["callbackUrls"]:
                callback = urlsplit(callback_url)
                redirect_result["callbackOrigin"].append(
                    f"{callback.scheme}://{callback.netloc}" if callback.scheme and callback.netloc else None
                )
            redirect_result["baselineCredentialLeakReproduced"] = (
                not patched and libgit2_redirect_reproduced(redirect_result, "baseline")
            )
            redirect_result["patchedCredentialLeakPrevented"] = (
                patched and libgit2_redirect_reproduced(redirect_result, "patched")
            )
            redirect_result["passed"] = libgit2_redirect_reproduced(redirect_result, args.phase)
            checks.append(redirect_result)
        else:
            raise RuntimeError("Unsupported source package")
    report = {
        "runner": "getpatched-platform-regression/1",
        "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "imageId": args.image_id,
        "verificationId": args.verification_id,
        "source": package, "targetId": policy["targetId"], "distribution": policy["distribution"],
        "release": policy["release"], "architecture": policy["architecture"],
        "phase": args.phase, "installedVersion": installed, "expectedVersion": expected,
        "checks": checks, "passed": bool(checks) and all(c["passed"] for c in checks),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(package, args.phase, "PASS" if report["passed"] else "FAIL")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
