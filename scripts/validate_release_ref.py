#!/usr/bin/env python3
"""Validate a release tag against canonical main and tagged package metadata."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

RC_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+rc[1-9][0-9]*$")
FINAL_TAG_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:\.post[1-9][0-9]*)?$"
)
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
VERSION_RE = re.compile(r"^__version__ = ['\"]([^'\"]+)['\"]$", re.MULTILINE)
GIT = Path("/usr/bin/git")


class ReleaseRefError(ValueError):
    """A release ref is not bound to canonical reviewed source."""


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(  # noqa: S603
        [str(GIT), "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if check and result.returncode != 0:
        raise ReleaseRefError("Git could not validate the release ref")
    return result.stdout.strip()


def _tag_pattern(event: str) -> re.Pattern[str]:
    if event == "rc":
        return RC_TAG_RE
    if event == "final":
        return FINAL_TAG_RE
    raise ReleaseRefError("Release event is unsupported")


def _declared_version(repository: Path, source_sha: str) -> str:
    row = _git(repository, "ls-tree", source_sha, "--", "netbox_openbao/__init__.py")
    fields = row.split()
    if len(fields) != 4 or fields[1] != "blob" or SHA_RE.fullmatch(fields[2]) is None:
        raise ReleaseRefError("Tagged package metadata is unavailable")
    source = _git(repository, "cat-file", "blob", fields[2])
    match = VERSION_RE.search(source)
    if match is None:
        raise ReleaseRefError("Tagged package version is unavailable")
    return match.group(1)


def validate_release_ref(
    *, repository: Path, tag: str, event: str, expected_head: str = ""
) -> dict[str, str]:
    """Return identities only when the exact tag belongs to canonical main."""
    if _tag_pattern(event).fullmatch(tag) is None:
        raise ReleaseRefError("Release tag does not match its event")
    tag_object = _git(repository, "rev-parse", "refs/release-policy/candidate")
    source_sha = _git(repository, "rev-parse", "refs/release-policy/candidate^{commit}")
    main_sha = _git(repository, "rev-parse", "refs/release-policy/main^{commit}")
    if any(SHA_RE.fullmatch(value) is None for value in (tag_object, source_sha, main_sha)):
        raise ReleaseRefError("Release object identity is invalid")
    if expected_head and source_sha != expected_head:
        raise ReleaseRefError("Checked-out source differs from the release tag")
    result = subprocess.run(  # noqa: S603
        [
            str(GIT),
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            source_sha,
            main_sha,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode != 0:
        raise ReleaseRefError("Release tag source is not on canonical main")
    version = tag.removeprefix("v")
    if _declared_version(repository, source_sha) != version:
        raise ReleaseRefError("Tagged package version differs from the tag")
    return {
        "source_sha": source_sha,
        "tag": tag,
        "tag_object": tag_object,
        "version": version,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--tag", required=True)
    parser.add_argument("--event", choices=("rc", "final"), required=True)
    parser.add_argument("--expected-head", default="")
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    values = validate_release_ref(
        repository=args.repository,
        tag=args.tag,
        event=args.event,
        expected_head=args.expected_head,
    )
    with args.github_output.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
