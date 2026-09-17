"""Static and executable contracts for package-first release workflows."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".gitea/workflows/publish-gitea.yml"
DEPLOY = ROOT / ".gitea/workflows/deploy-production.yml"
PUBLIC = ROOT / ".github/workflows/publish.yml"
HELPER = ROOT / "scripts/release_artifacts.py"
REF_VALIDATOR = ROOT / "scripts/validate_release_ref.py"


def _helper():
    spec = importlib.util.spec_from_file_location("release_artifacts", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ref_validator():
    spec = importlib.util.spec_from_file_location("validate_release_ref", REF_VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _commit_version(repository: Path, version: str, message: str) -> str:
    package = repository / "netbox_openbao"
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_text(
        f"__version__ = {version!r}\n", encoding="utf-8"
    )
    _git(repository, "add", "netbox_openbao/__init__.py")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _release_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.email", "release-test@example.invalid")
    _git(repository, "config", "user.name", "Release Test")
    return repository


@pytest.mark.parametrize("path", [PUBLISH, DEPLOY, PUBLIC])
def test_workflow_shell_blocks_parse(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            script = step.get("run")
            if not isinstance(script, str):
                continue
            result = subprocess.run(
                ["/bin/bash", "-n"],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0, (
                f"{path.name}:{job_name}:{step.get('name')}: {result.stderr}"
            )


def test_release_trigger_and_target_contracts() -> None:
    publish = PUBLISH.read_text(encoding="utf-8")
    deploy = DEPLOY.read_text(encoding="utf-8")
    assert "netbox-openbao-release-manifest" in publish
    assert "NMS target 9" in publish
    assert '--password "$GITEA_PACKAGE_TOKEN"' not in publish
    assert 'Authorization: token ${GITEA_PACKAGE_TOKEN}' not in publish
    assert "release-manifest.json" in publish
    assert "target 20" in deploy
    assert "'target_id': 21" in deploy
    assert "proof-v3 outer schema is not exact" in deploy
    assert "deploy-netbox-plugin-package" in deploy
    assert "options: [latest_package, main_branch]" in deploy
    assert "--main netbox-openbao" in deploy
    assert "DEPLOYMENT_PROOF_NOT_BOUND" in deploy
    assert "for attempt in 1 2 3 4 5 6" in deploy


def test_public_publish_trigger_contract() -> None:
    public = PUBLIC.read_text(encoding="utf-8")
    assert 'tags: ["v*rc*"]' in public
    assert "types: [published]" in public
    assert 'tags: ["v*"]' not in public
    assert "+refs/heads/main:refs/release-policy/main" in public
    policy_checkout = public.index("Checkout protected canonical-main policy")
    policy_ref = public.index("ref: main", policy_checkout)
    validator = public.index("python scripts/validate_release_ref.py")
    candidate_checkout = public.index("Checkout validated release source")
    assert policy_checkout < policy_ref < validator < candidate_checkout
    validator_command = public[validator : public.index('"$GITHUB_OUTPUT"', validator)]
    assert '--repository . --tag "$tag"' in validator_command
    assert '--event "$event"' in validator_command
    assert "--github-output" in validator_command
    assert public.count("id-token: write") == 1
    validate_job = public[public.index("validate-build:") : public.index("  publish:")]
    assert "id-token: write" not in validate_job
    publish_job = public[public.index("  publish:") :]
    assert "scripts/validate_release_ref.py" not in publish_job
    assert "actions/download-artifact@" in publish_job


@pytest.mark.parametrize(
    ("tag", "event", "version"),
    [("v0.1.0rc1", "rc", "0.1.0rc1"), ("v0.1.0", "final", "0.1.0")],
)
def test_release_ref_rejects_tag_outside_main(
    tmp_path: Path, tag: str, event: str, version: str
) -> None:
    validator = _ref_validator()
    repository = _release_repository(tmp_path)
    main_sha = _commit_version(repository, "0.0.9", "main")
    _git(repository, "switch", "-c", "unreviewed")
    _commit_version(repository, version, "unreviewed")
    _git(repository, "tag", tag)
    _git(repository, "update-ref", "refs/release-policy/candidate", tag)
    _git(repository, "update-ref", "refs/release-policy/main", main_sha)
    with pytest.raises(validator.ReleaseRefError, match="not on canonical main"):
        validator.validate_release_ref(
            repository=repository,
            tag=tag,
            event=event,
        )


def test_release_ref_reads_version_from_older_tagged_source(tmp_path: Path) -> None:
    validator = _ref_validator()
    repository = _release_repository(tmp_path)
    tagged_sha = _commit_version(repository, "0.1.0rc1", "candidate")
    _git(repository, "tag", "v0.1.0rc1")
    main_sha = _commit_version(repository, "0.1.0", "main advanced")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0rc1")
    _git(repository, "update-ref", "refs/release-policy/main", main_sha)
    result = validator.validate_release_ref(
        repository=repository,
        tag="v0.1.0rc1",
        event="rc",
    )
    assert result["source_sha"] == tagged_sha
    assert result["version"] == "0.1.0rc1"


def test_release_ref_cli_exact_workflow_argv_accepts_main_and_rejects_hostile(
    tmp_path: Path,
) -> None:
    repository = _release_repository(tmp_path)
    main_sha = _commit_version(repository, "0.1.0rc1", "reviewed")
    _git(repository, "tag", "v0.1.0rc1")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0rc1")
    _git(repository, "update-ref", "refs/release-policy/main", main_sha)
    output = tmp_path / "github-output"
    argv = [
        sys.executable,
        str(REF_VALIDATOR),
        "--repository",
        str(repository),
        "--tag",
        "v0.1.0rc1",
        "--event",
        "rc",
        "--github-output",
        str(output),
    ]
    accepted = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    assert accepted.returncode == 0, accepted.stderr
    assert "version=0.1.0rc1" in output.read_text(encoding="utf-8")

    _git(repository, "switch", "-c", "hostile")
    _commit_version(repository, "0.1.0rc2", "hostile")
    _git(repository, "tag", "v0.1.0rc2")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0rc2")
    hostile_argv = argv.copy()
    hostile_argv[hostile_argv.index("v0.1.0rc1")] = "v0.1.0rc2"
    rejected = subprocess.run(hostile_argv, capture_output=True, text=True, timeout=10)
    assert rejected.returncode != 0
    assert "not on canonical main" in rejected.stderr


def test_workflow_uses_no_unpinned_actions() -> None:
    for path in (PUBLISH, DEPLOY, PUBLIC):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "uses:" not in line:
                continue
            target = line.split("uses:", 1)[1].split("#", 1)[0].strip()
            assert "@" in target
            revision = target.rsplit("@", 1)[1]
            assert len(revision) == 40 or target == "pypa/gh-action-pypi-publish@release/v1"


def test_manifest_is_canonical_and_byte_bound(tmp_path: Path) -> None:
    helper = _helper()
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "netbox_openbao-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    (dist / "netbox_openbao-0.1.0.tar.gz").write_bytes(b"sdist")
    output = tmp_path / "release-manifest.json"
    expected = helper.write_manifest(
        dist=dist,
        version="0.1.0",
        source_sha="a" * 40,
        output=output,
    )
    assert set(expected) == {"artifacts", "package", "schema", "source_sha", "version"}
    assert expected["schema"] == 1
    assert expected["package"] == "netbox-openbao"
    assert helper.verify_manifest(
        manifest_path=output,
        dist=dist,
        version="0.1.0",
        source_sha="a" * 40,
    ) == expected


def test_manifest_rejects_extra_artifact(tmp_path: Path) -> None:
    helper = _helper()
    for name in (
        "netbox_openbao-0.1.0-py3-none-any.whl",
        "netbox_openbao-0.1.0.tar.gz",
        "unexpected.txt",
    ):
        (tmp_path / name).write_bytes(b"x")
    with pytest.raises(helper.ReleaseArtifactError, match="exactly one wheel"):
        helper.create_manifest(dist=tmp_path, version="0.1.0", source_sha="b" * 40)
