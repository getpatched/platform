#!/usr/bin/env python3
"""Build exact Debian libarchive source with UBSan and check CVE-2026-16517."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(command, *, timeout, env=None, cwd=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
        return {
            "command": [str(item) for item in command],
            "returncode": result.returncode,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
            "timedOut": False,
        }
    except subprocess.TimeoutExpired as error:
        def decode(value):
            if value is None:
                return ""
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
        return {
            "command": [str(item) for item in command],
            "returncode": None,
            "stdout": decode(error.stdout)[-4000:],
            "stderr": decode(error.stderr)[-4000:],
            "timedOut": True,
        }


def tree_sha256(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative + b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0" + os.readlink(path).encode() + b"\0")
        elif path.is_file():
            digest.update(b"file\0" + hashlib.sha256(path.read_bytes()).digest() + b"\0")
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-provenance", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "patched"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    fixture = args.fixture.resolve()
    if not (source / "CMakeLists.txt").is_file() or not fixture.is_file():
        raise SystemExit("exact libarchive source or regression fixture is missing")
    policy = json.loads(args.policy.read_text())
    provenance_bytes = args.source_provenance.read_bytes()
    provenance = json.loads(provenance_bytes)
    manifest = json.loads((args.recipe / "package-manifest.json").read_text())
    target_refs = [item for item in manifest["targets"] if item.get("id") == policy["targetId"]]
    if len(target_refs) != 1:
        raise SystemExit("package recipe has no unique target for the source regression")
    target = json.loads((args.recipe / target_refs[0]["file"]).read_text())
    metadata = json.loads((args.recipe / manifest["patchMetadata"]).read_text())
    patch_ids = target.get("patches", [])
    patches = [item for item in metadata["patches"] if item.get("id") in patch_ids and "CVE-2026-16517" in item.get("cves", [])]
    if len(patches) != 1:
        raise SystemExit("package target has no unique CVE-2026-16517 patch")
    patch = patches[0]
    patch_path = args.recipe / "patches" / patch["file"]
    patch_sha = hashlib.sha256(patch_path.read_bytes()).hexdigest()
    if patch_sha != patch.get("sha256"):
        raise SystemExit("packaging patch hash differs from its metadata")

    expected_assets = {
        item["name"]: item["sha256"]
        for item in [target["source"]["descriptor"], *target["source"]["files"]]
    }
    downloaded_assets = {item["name"]: item["sha256"] for item in provenance.get("downloadedSources", [])}
    expected_changelog_version = policy["baseVersion"] if args.phase == "baseline" else policy["version"]
    identity_valid = (
        policy.get("source") == "libarchive"
        and policy.get("targetId") == "debian-trixie-amd64"
        and policy.get("baseVersion") == target["source"]["version"]
        and provenance.get("source") == "libarchive"
        and provenance.get("targetId") == policy["targetId"]
        and provenance.get("baseVersion") == policy["baseVersion"]
        and provenance.get("sourceVersion") == policy["baseVersion"]
        and provenance.get("packageVersion") == policy["version"]
        and provenance.get("sourceDescriptor", {}).get("sha256") == target["source"]["descriptor"]["sha256"]
        and provenance.get("patches") and any(
            item.get("id") == patch["id"] and item.get("sha256") == patch_sha
            for item in provenance["patches"]
        )
        and downloaded_assets == expected_assets
    )
    if not identity_valid:
        raise SystemExit("source provenance does not match the pinned Trixie recipe, archives, and patch")
    changelog_version = run(["dpkg-parsechangelog", "-S", "Version"], timeout=30, cwd=source)
    if changelog_version["returncode"] != 0 or changelog_version["stdout"].strip() != expected_changelog_version:
        raise SystemExit("source changelog version does not match the baseline or patched package phase")
    series_path = source / "debian/patches/series"
    series = series_path.read_text().splitlines() if series_path.is_file() else []
    patch_applied = patch["file"] in series
    if patch_applied != (args.phase == "patched"):
        raise SystemExit("GetPatched patch series state does not match the requested source phase")
    if patch_applied and hashlib.sha256((source / "debian/patches" / patch["file"]).read_bytes()).hexdigest() != patch_sha:
        raise SystemExit("applied GetPatched patch differs from the pinned patch file")
    source_file = source / "libarchive/archive_write_set_format_zip.c"
    if not source_file.is_file():
        raise SystemExit("source tree lacks the vulnerable ZIP writer implementation")
    source_tree_hash = tree_sha256(source)
    source_file_hash = hashlib.sha256(source_file.read_bytes()).hexdigest()

    with tempfile.TemporaryDirectory(prefix="getpatched-libarchive-ubsan-") as directory:
        root = Path(directory)
        build = root / "build"
        cflags = "-fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -O1 -g"
        cmake_version = run(["cmake", "--version"], timeout=30)
        version_match = re.search(r"cmake version (\d+)\.(\d+)", cmake_version["stdout"], re.IGNORECASE)
        if cmake_version["returncode"] != 0 or version_match is None:
            raise SystemExit("could not determine the installed CMake version")
        cmake_options = [
            "cmake", "-S", str(source), "-B", str(build),
            "-DCMAKE_BUILD_TYPE=Debug", "-DBUILD_SHARED_LIBS=ON",
            "-DCMAKE_INSTALL_PREFIX=" + str(root / "install"),
            "-DENABLE_OPENSSL=OFF", "-DENABLE_NETTLE=ON", "-DCMAKE_C_FLAGS=" + cflags,
            "-DENABLE_WERROR=OFF",
            "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined -fno-sanitize-recover=undefined",
        ]
        if int(version_match.group(1)) >= 4:
            cmake_options.append("-DCMAKE_POLICY_VERSION_MINIMUM=3.5")
        configured = run(cmake_options, timeout=300)
        if configured["returncode"] != 0:
            raise SystemExit("UBSan CMake configuration failed: " + configured["stderr"][-2000:])
        config_header = build / "config.h"
        if not config_header.is_file() or not re.search(r"^#define HAVE_LIBNETTLE 1$", config_header.read_text(), re.MULTILINE):
            raise SystemExit("UBSan CMake configuration did not enable Debian's Nettle crypto backend")
        built = run(["cmake", "--build", str(build), "--parallel", "2"], timeout=600)
        if built["returncode"] != 0:
            raise SystemExit("UBSan libarchive build failed: " + built["stderr"][-2000:])

        executable = root / "zip-encrypted-size-overflow"
        library_dir = build / "libarchive"
        compiled = run([
            "cc", "-std=c99", "-Wall", "-Wextra", "-Werror", *cflags.split(),
            "-I" + str(source / "libarchive"), "-I" + str(library_dir),
            str(fixture), "-L" + str(library_dir), "-Wl,-rpath," + str(library_dir),
            "-larchive", "-o", str(executable),
        ], timeout=60)
        if compiled["returncode"] != 0:
            raise SystemExit("UBSan regression harness compilation failed: " + compiled["stderr"][-2000:])
        environment = dict(os.environ)
        environment["LD_LIBRARY_PATH"] = str(library_dir) + os.pathsep + environment.get("LD_LIBRARY_PATH", "")
        check = run([str(executable)], timeout=10, env=environment)

    marker_start = "GETPATCHED:ZIP_HEADER_START" in check["stderr"]
    marker_return = "GETPATCHED:ZIP_HEADER_RETURN" in check["stderr"]
    overflow_operands = (
        "9223372036854775807 + 28" in check["stderr"]
        or "28 + 9223372036854775807" in check["stderr"]
    )
    overflow = (
        "runtime error: signed integer overflow:" in check["stderr"]
        and overflow_operands
        and "archive_write_set_format_zip.c:" in check["stderr"]
    )
    reproduced = (
        args.phase == "baseline" and not check["timedOut"] and check["returncode"] != 0
        and marker_start and not marker_return and overflow
    )
    patched = (
        args.phase == "patched" and not check["timedOut"] and check["returncode"] == 0
        and marker_start and marker_return and not overflow
    )
    report = {
        "runner": "getpatched-libarchive-source-ubsan/1",
        "source": "libarchive",
        "phase": args.phase,
        "testId": "CVE-2026-16517-encrypted-zip-signed-overflow",
        "cryptoBackend": "nettle",
        "evidenceType": "exact-source-ubsan; installed package behavior is reported separately",
        "targetId": policy["targetId"],
        "sourceVersion": policy["baseVersion"],
        "changelogVersion": changelog_version["stdout"].strip(),
        "sourceProvenanceSha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "sourceDescriptorSha256": provenance["sourceDescriptor"]["sha256"],
        "sourceTreeSha256": source_tree_hash,
        "vulnerableFileSha256": source_file_hash,
        "patchId": patch["id"],
        "patchSha256": patch_sha,
        "patchApplied": patch_applied,
        "sourcePath": str(source),
        "fixtureSha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "check": check,
        "sourceVulnerabilityReproduced": reproduced,
        "patchedBehavior": patched,
        "passed": reproduced if args.phase == "baseline" else patched,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("libarchive UBSan source", args.phase, "PASS" if report["passed"] else "FAIL")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
