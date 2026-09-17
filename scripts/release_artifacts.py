#!/usr/bin/env python3
"""Build and verify the immutable package-first release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
REGISTRY_ORIGIN = "https://git.nmulti.cloud"


class ReleaseArtifactError(ValueError):
    """Release bytes or registry metadata violate the reviewed contract."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def canonical_name(value: str) -> str:
    """Return the PEP 503 spelling used by the package contract."""
    return re.sub(r"[-_.]+", "-", value).lower()


def _record(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or SAFE_NAME_RE.fullmatch(path.name) is None:
        raise ReleaseArtifactError("Release artifact is not a safe regular file")
    size = path.stat().st_size
    if not 0 < size <= MAX_ARTIFACT_BYTES:
        raise ReleaseArtifactError("Release artifact size is invalid")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"name": path.name, "sha256": digest.hexdigest(), "size": size}


def _manifest_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _release_files(dist: Path, version: str) -> list[Path]:
    files = sorted(
        path for path in dist.iterdir() if path.is_file() and path.name != ".gitignore"
    )
    wheels = [path for path in files if path.name.endswith(".whl")]
    sdists = [path for path in files if path.name.endswith(".tar.gz")]
    if len(files) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise ReleaseArtifactError("Release must contain exactly one wheel and one sdist")
    if any(version.replace("-", "_") not in path.name for path in files):
        raise ReleaseArtifactError("Artifact filename does not carry the release version")
    return files


def _validate_version(version: str) -> None:
    version_pattern = (
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
        r"(?:0|[1-9][0-9]*)(?:rc[1-9][0-9]*|\.post[1-9][0-9]*)?"
    )
    if re.fullmatch(version_pattern, version) is None:
        raise ReleaseArtifactError("Version is not a supported release version")


def create_manifest(*, dist: Path, version: str, source_sha: str) -> dict[str, Any]:
    """Create the exact schema-1 manifest consumed by NMS package deployment."""
    if SHA_RE.fullmatch(source_sha) is None:
        raise ReleaseArtifactError("Source SHA must be lowercase 40-hex")
    _validate_version(version)
    files = _release_files(dist, version)
    return {
        "artifacts": [_record(path) for path in files],
        "package": "netbox-openbao",
        "schema": 1,
        "source_sha": source_sha,
        "version": version,
    }


def load_manifest(path: Path) -> dict[str, Any]:
    """Load canonical JSON with the exact NMS schema-1 key set."""
    raw = path.read_bytes()
    if not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        raise ReleaseArtifactError("Manifest size is invalid")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseArtifactError("Manifest is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "artifacts", "package", "schema", "source_sha", "version"
    }:
        raise ReleaseArtifactError("Manifest schema is not exact")
    if value.get("schema") != 1 or value.get("package") != "netbox-openbao":
        raise ReleaseArtifactError("Manifest identity is invalid")
    if _manifest_bytes(value) != raw:
        raise ReleaseArtifactError("Manifest is not canonical JSON")
    return value


def write_manifest(
    *, dist: Path, version: str, source_sha: str, output: Path
) -> dict[str, Any]:
    """Write a canonical release manifest."""
    manifest = create_manifest(dist=dist, version=version, source_sha=source_sha)
    output.write_bytes(_manifest_bytes(manifest))
    return manifest


def verify_manifest(
    *, manifest_path: Path, dist: Path, version: str, source_sha: str
) -> dict[str, Any]:
    """Verify the manifest against independently hashed artifacts."""
    actual = load_manifest(manifest_path)
    expected = create_manifest(dist=dist, version=version, source_sha=source_sha)
    if actual != expected:
        raise ReleaseArtifactError("Manifest does not match the artifact bytes")
    return actual


def _quoted(value: str) -> str:
    if SAFE_NAME_RE.fullmatch(value) is None:
        raise ReleaseArtifactError("Registry identity is unsafe")
    return urllib.parse.quote(value, safe="")


def _request(url: str, *, token: str, maximum: int) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if f"{parsed.scheme}://{parsed.netloc}" != REGISTRY_ORIGIN:
        raise ReleaseArtifactError("Registry origin is not canonical")
    headers = {"Accept": "application/json", "User-Agent": "netbox-openbao-release/1"}
    if token:
        headers["Authorization"] = f"token {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=30) as response:
            if response.status != 200:
                raise ReleaseArtifactError("Registry returned a non-success status")
            content = response.read(maximum + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReleaseArtifactError("Registry request failed") from exc
    if len(content) > maximum:
        raise ReleaseArtifactError("Registry response exceeds its size bound")
    return content


def _fetch_manifest(
    *, owner: str, repository: str, version: str, token: str, output: Path
) -> dict[str, Any]:
    package = "netbox-openbao-release-manifest"
    base = (
        f"{REGISTRY_ORIGIN}/api/v1/packages/{_quoted(owner)}/generic/"
        f"{package}/{_quoted(version)}"
    )
    metadata = json.loads(_request(base, token=token, maximum=MAX_MANIFEST_BYTES))
    files = json.loads(
        _request(f"{base}/files", token=token, maximum=MAX_MANIFEST_BYTES)
    )
    size, digest = _manifest_inventory(
        metadata=metadata,
        files=files,
        owner=owner,
        repository=repository,
        package=package,
        version=version,
    )
    url = (
        f"{REGISTRY_ORIGIN}/api/packages/{_quoted(owner)}/generic/"
        f"{package}/{_quoted(version)}/release-manifest.json"
    )
    raw = _request(url, token=token, maximum=MAX_MANIFEST_BYTES)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ReleaseArtifactError("Release manifest differs from registry inventory")
    output.write_bytes(raw)
    return load_manifest(output)


def _manifest_inventory(
    *,
    metadata: object,
    files: object,
    owner: str,
    repository: str,
    package: str,
    version: str,
) -> tuple[int, str]:
    linked = metadata.get("repository") if isinstance(metadata, dict) else None
    identity = (
        metadata.get("name") if isinstance(metadata, dict) else None,
        metadata.get("version") if isinstance(metadata, dict) else None,
        metadata.get("type") if isinstance(metadata, dict) else None,
        linked.get("full_name") if isinstance(linked, dict) else None,
    )
    if identity != (package, version, "generic", f"{owner}/{repository}"):
        raise ReleaseArtifactError("Release-manifest package identity is invalid")
    if not isinstance(files, list) or len(files) != 1:
        raise ReleaseArtifactError("Release-manifest file inventory is invalid")
    inventory = files[0]
    if not isinstance(inventory, dict) or inventory.get("name") != "release-manifest.json":
        raise ReleaseArtifactError("Release-manifest file identity is invalid")
    size, digest = inventory.get("size"), inventory.get("sha256")
    valid_size = not isinstance(size, bool) and isinstance(size, int)
    valid_digest = isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None
    if not valid_size or not valid_digest:
        raise ReleaseArtifactError("Release-manifest inventory is invalid")
    return size, digest


def _download_artifact(
    *, owner: str, version: str, artifact: object, token: str, dist: Path
) -> None:
    if not isinstance(artifact, dict):
        raise ReleaseArtifactError("Artifact inventory is invalid")
    name = artifact.get("name")
    size = artifact.get("size")
    digest = artifact.get("sha256")
    if (
        not isinstance(name, str)
        or SAFE_NAME_RE.fullmatch(name) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not isinstance(digest, str)
        or DIGEST_RE.fullmatch(digest) is None
    ):
        raise ReleaseArtifactError("Artifact inventory is invalid")
    url = (
        f"{REGISTRY_ORIGIN}/api/packages/{_quoted(owner)}/pypi/files/"
        f"netbox-openbao/{_quoted(version)}/{_quoted(name)}"
    )
    content = _request(url, token=token, maximum=MAX_ARTIFACT_BYTES)
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise ReleaseArtifactError("Artifact differs from release manifest")
    (dist / name).write_bytes(content)


def fetch_gitea_artifacts(
    *,
    owner: str,
    repository: str,
    version: str,
    source_sha: str,
    dist: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    """Fetch a repository-linked manifest and its exact wheel/sdist pair."""
    token = os.getenv("GITEA_PACKAGE_TOKEN", "")
    manifest = _fetch_manifest(
        owner=owner,
        repository=repository,
        version=version,
        token=token,
        output=manifest_path,
    )
    if manifest.get("version") != version or manifest.get("source_sha") != source_sha:
        raise ReleaseArtifactError("Release manifest source identity is invalid")
    dist.mkdir(mode=0o700)
    for artifact in manifest["artifacts"]:
        _download_artifact(
            owner=owner,
            version=version,
            artifact=artifact,
            token=token,
            dist=dist,
        )
    return verify_manifest(manifest_path=manifest_path, dist=dist, version=version, source_sha=source_sha)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("manifest", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--dist", type=Path, required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--source-sha", required=True)
        command.add_argument("--manifest", type=Path, required=True)
    fetch = commands.add_parser("fetch-gitea")
    fetch.add_argument("--owner", required=True)
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--version", required=True)
    fetch.add_argument("--source-sha", required=True)
    fetch.add_argument("--dist", type=Path, required=True)
    fetch.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "manifest":
        manifest = write_manifest(
            dist=args.dist,
            version=args.version,
            source_sha=args.source_sha,
            output=args.manifest,
        )
    elif args.command == "verify":
        manifest = verify_manifest(
            manifest_path=args.manifest,
            dist=args.dist,
            version=args.version,
            source_sha=args.source_sha,
        )
    else:
        manifest = fetch_gitea_artifacts(
            owner=args.owner,
            repository=args.repository,
            version=args.version,
            source_sha=args.source_sha,
            dist=args.dist,
            manifest_path=args.manifest,
        )
    print(hashlib.sha256(_manifest_bytes(manifest)).hexdigest())


if __name__ == "__main__":
    main()
