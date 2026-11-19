#!/usr/bin/env python3
"""Build a harmless native smoke package and unsigned Focal preview repository."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import lzma
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SOURCE = ROOT / "preview" / "getpatched-preview-smoke"
PACKAGE_NAME = "getpatched-preview-smoke"
PACKAGE_PATH = Path("pool/main/g/getpatched-preview-smoke")
def package_version() -> str:
    changelog = (PACKAGE_SOURCE / "debian" / "changelog").read_text()
    match = re.match(r"^getpatched-preview-smoke \(([^)]+)\) focal;", changelog)
    if not match:
        raise ValueError("preview package changelog must start with its Focal source version")
    return match.group(1)


def run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.PIPE)


def parse_binary_identity(control_text: str) -> tuple[str | None, str | None, str | None]:
    fields: dict[str, str] = {}
    for line in control_text.splitlines():
        if line and not line[0].isspace() and ":" in line:
            name, value = line.split(":", 1)
            fields[name] = value.strip()
    return fields.get("Package"), fields.get("Version"), fields.get("Architecture")


def build_package(repository: Path, version: str) -> None:
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~]*", version):
        raise ValueError("preview package version is not a valid native Debian version")
    pool = repository / PACKAGE_PATH
    pool.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="getpatched-preview-build-") as temporary:
        temporary_path = Path(temporary)
        source_tree = temporary_path / PACKAGE_NAME
        shutil.copytree(PACKAGE_SOURCE, source_tree)
        changelog_path = source_tree / "debian" / "changelog"
        changelog = changelog_path.read_text()
        base_version = package_version()
        changelog_path.write_text(changelog.replace(f"({base_version})", f"({version})", 1))
        command_path = source_tree / "usr" / "bin" / PACKAGE_NAME
        command_path.write_text(command_path.read_text().replace(base_version, version, 1))
        binary_root = temporary_path / "binary-root"
        control_dir = binary_root / "DEBIAN"
        (binary_root / "usr" / "bin").mkdir(parents=True)
        (binary_root / "usr" / "share" / "doc" / PACKAGE_NAME).mkdir(parents=True)
        shutil.copy2(command_path, binary_root / "usr" / "bin" / PACKAGE_NAME)
        shutil.copy2(source_tree / "usr" / "share" / "doc" / PACKAGE_NAME / "README", binary_root / "usr" / "share" / "doc" / PACKAGE_NAME / "README")
        (binary_root / "usr" / "bin" / PACKAGE_NAME).chmod(0o755)
        control_dir.mkdir()
        (control_dir / "control").write_text(
            f"Package: {PACKAGE_NAME}\nVersion: {version}\nArchitecture: all\n"
            "Maintainer: GetPatched Release Engineering <release@getpatched.dev>\n"
            "Description: Harmless package for GetPatched isolated APT preview checks\n"
            " Installs a small command and documentation under /usr.\n"
        )
        deb_path = temporary_path / f"{PACKAGE_NAME}_{version}_all.deb"
        run(["dpkg-deb", "--root-owner-group", "--build", str(binary_root), str(deb_path)])
        run(["dpkg-source", "-b", str(source_tree)], cwd=temporary_path)

        binary_control = run(["dpkg-deb", "-f", str(deb_path)]).stdout.decode()
        if parse_binary_identity(binary_control) != (PACKAGE_NAME, version, "all"):
            raise ValueError("generated preview binary has an unexpected package identity")
        extracted = temporary_path / "extracted-package"
        run(["dpkg-deb", "--extract", str(deb_path), str(extracted)])
        command_output = run([str(extracted / "usr" / "bin" / PACKAGE_NAME)]).stdout.decode()
        if command_output != f"GetPatched isolated public preview package: {version}\n":
            raise ValueError("generated preview binary does not report its package version")

        generated = [
            temporary_path / f"{PACKAGE_NAME}_{version}.dsc",
            temporary_path / f"{PACKAGE_NAME}_{version}.tar.xz",
            deb_path,
        ]
        for artifact in generated:
            if not artifact.is_file() or artifact.stat().st_size == 0:
                raise ValueError(f"preview package build did not produce {artifact.name}")
            shutil.copy2(artifact, pool / artifact.name)


def compressed_index(data: bytes, destination: Path) -> None:
    if destination.suffix == ".gz":
        with destination.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=output, mtime=0) as stream:
                stream.write(data)
    else:
        destination.write_bytes(lzma.compress(data, preset=9))


def build_indexes(repository: Path) -> list[Path]:
    focal = repository / "dists" / "focal"
    binary_dir = focal / "main" / "binary-amd64"
    source_dir = focal / "main" / "source"
    binary_dir.mkdir(parents=True)
    source_dir.mkdir(parents=True)
    package_index = run(["dpkg-scanpackages", "--arch", "amd64", "pool", "/dev/null"], cwd=repository).stdout
    source_index = run(["dpkg-scansources", "pool", "/dev/null"], cwd=repository).stdout
    (binary_dir / "Packages").write_bytes(package_index)
    (source_dir / "Sources").write_bytes(source_index)
    indexes: list[Path] = []
    for directory, stem, data in (
        (binary_dir, "Packages", package_index),
        (source_dir, "Sources", source_index),
    ):
        for suffix in (".gz", ".xz"):
            destination = directory / f"{stem}{suffix}"
            compressed_index(data, destination)
            indexes.append(destination)
        indexes.append(directory / stem)
    return indexes


def write_release(repository: Path, indexes: list[Path], *, now: datetime | None = None) -> Path:
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("release timestamp must be timezone aware")
    instant = instant.astimezone(timezone.utc).replace(microsecond=0)
    expiry = instant + timedelta(days=7)
    date_format = "%a, %d %b %Y %H:%M:%S UTC"
    fields = [
        "Origin: GetPatched",
        "Label: GetPatched Public Preview",
        "Suite: focal",
        "Codename: focal",
        f"Date: {instant.strftime(date_format).replace(' UTC', ' +0000')}",
        f"Valid-Until: {expiry.strftime(date_format).replace(' UTC', ' +0000')}",
        "Architectures: amd64",
        "Components: main",
        "Description: Isolated test-only public preview APT channel",
        "SHA256:",
    ]
    for index in sorted(indexes, key=lambda path: path.relative_to(repository / "dists" / "focal").as_posix()):
        relative = index.relative_to(repository / "dists" / "focal").as_posix()
        digest = hashlib.sha256(index.read_bytes()).hexdigest()
        fields.append(f" {digest} {index.stat().st_size} {relative}")
    release = repository / "dists" / "focal" / "Release"
    release.write_text("\n".join(fields) + "\n")
    return release


def build_repository(output: Path, *, version: str | None = None, now: datetime | None = None) -> None:
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError("preview repository output must be a real directory")
    if output.exists() and any(output.iterdir()):
        raise ValueError("preview repository output must be empty; choose a fresh build directory")
    output.mkdir(parents=True, exist_ok=True)
    build_package(output, version or package_version())
    indexes = build_indexes(output)
    write_release(output, indexes, now=now)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", help="Unique native Debian version for immutable per-run preview artifacts")
    arguments = parser.parse_args()
    build_repository(arguments.output.absolute(), version=arguments.version)


if __name__ == "__main__":
    main()
