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


def run(command, *, timeout, env=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "patched"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    fixture = args.fixture.resolve()
    if not (source / "CMakeLists.txt").is_file() or not fixture.is_file():
        raise SystemExit("exact libarchive source or regression fixture is missing")

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
    overflow = (
        "runtime error: signed integer overflow: 9223372036854775807 + 28" in check["stderr"]
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
        "sourcePath": str(source),
        "fixtureSha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "check": check,
        "vulnerabilityReproduced": reproduced,
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
