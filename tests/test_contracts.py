"""Contract validation, identity, comparison and consumer-specific export."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from pathlib import Path

import pytest
import typer
import yaml

from dotenv import dotenv_values
from envers.cli import app
from envers.core import Envers
from typer.testing import CliRunner

PASSWORD = "synthetic contract password"
SPEC = Path(".envers/specs.yaml")
LOCK = Path(".envers/data/base.lock")
TOKEN = 'synthetic ${REFERENCE} $BARE $$ # "quote" \\path\nnext\rline café'


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Envers:
    """Deploy typed definitions with optional, empty and required values."""
    monkeypatch.chdir(tmp_path)
    project = Envers()
    project.init(Path("."))
    project.draft("1.0")
    specs = yaml.safe_load(SPEC.read_text())
    release = specs["releases"]["1.0"]
    release["profiles"] = ["base", "prod"]
    release["spec"]["files"] = {
        ".env": {
            "type": "dotenv",
            "vars": {
                "TOKEN": {"type": "string", "required": True},
                "RETRIES": {"type": "int", "default": 3, "allowed": [3, 5]},
                "ENABLED": {"type": "bool", "default": False},
                "MODE": {
                    "type": "string",
                    "default": "dev",
                    "allowed": ["dev", "prod"],
                },
                "EMPTY": {"type": "string", "default": ""},
                "OPTIONAL": {"type": "path"},
            },
        },
        "config/db.env": {
            "type": "dotenv",
            "vars": {
                "PASSWORD": {"type": "string", "required": True},
            },
        },
    }
    SPEC.write_text(yaml.safe_dump(specs))
    project.deploy("base", "1.0", PASSWORD)
    return project


def populate(project: Envers) -> None:
    """Set the first file while leaving the second file incomplete."""
    escaped = (
        TOKEN.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    Path("input.env").write_text(
        f'TOKEN="{escaped}"\nRETRIES=5\nENABLED=TRUE\nMODE=prod\n',
        encoding="utf-8",
    )
    project.profile_import("base", "1.0", "input.env", ".env", PASSWORD)


def snapshot() -> dict[str, tuple[bytes, int]]:
    """Capture content and modification times to detect validation writes."""
    return {
        str(path): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in Path(".envers").rglob("*")
        if path.is_file()
    }


def test_read_only_validation_types_and_unset_values(project: Envers) -> None:
    """Validate without prompts, output files or metadata changes."""
    before = snapshot()
    assert (
        "required value is unset"
        in project.validate("1.0", "base", PASSWORD)[0]
    )
    assert snapshot() == before
    missing = CliRunner().invoke(
        app, "validate --spec 1.0 --profile base", input=""
    )
    assert missing.exit_code == 1
    assert json.loads(missing.output)["valid"] is False
    assert snapshot() == before
    populate(project)
    data = project._read_data_file("base", PASSWORD)
    values = data["releases"]["1.0"]["data"]["base"]["files"][".env"]["vars"]
    assert values["RETRIES"] == 5 and type(values["RETRIES"]) is int
    assert values["ENABLED"] is True
    assert values["EMPTY"] == "" and "OPTIONAL" not in values
    assert values["TOKEN"] == TOKEN
    before = snapshot()
    result = CliRunner().invoke(
        app, "validate --spec 1.0 --profile base", input=PASSWORD + "\n"
    )
    assert result.exit_code == 1
    assert "config/db.env/PASSWORD" in result.output
    assert "synthetic" not in result.output
    assert snapshot() == before
    Path("db-input.env").write_text("PASSWORD=synthetic-db-password\n")
    project.profile_import(
        "base", "1.0", "db-input.env", "config/db.env", PASSWORD
    )
    before = snapshot()
    assert project.validate("1.0", "base", PASSWORD) == []
    assert project.validate("1.0") == []
    assert snapshot() == before


@pytest.mark.parametrize(
    "line",
    [
        "RETRIES=synthetic-invalid-int",
        "ENABLED=synthetic-invalid-bool",
        "MODE=synthetic-not-allowed",
    ],
)
def test_invalid_typed_import_is_private_and_atomic(
    project: Envers, line: str
) -> None:
    """A bad value rejects preceding valid edits without exposing either."""
    Path("input.env").write_text("TOKEN=synthetic-partial\n" + line + "\n")
    before = snapshot()
    result = CliRunner().invoke(
        app,
        "profile-import --profile base --spec 1.0 "
        "--from-env input.env --file .env",
        input=PASSWORD + "\n",
    )
    assert result.exit_code == 1
    assert "synthetic" not in result.output
    assert snapshot() == before


@pytest.mark.parametrize(
    "case", ["releases", "type", "required", "allowed", "format"]
)
def test_malformed_contracts_return_private_diagnostics(
    project: Envers, case: str
) -> None:
    """Reject malformed structures and rules without serializing values."""
    specs = yaml.safe_load(SPEC.read_text())
    info = specs["releases"]["1.0"]["spec"]["files"][".env"]
    if case == "releases":
        specs["releases"] = []
    elif case == "type":
        info["vars"]["RETRIES"]["type"] = ["synthetic-invalid"]
    elif case == "required":
        info["vars"]["TOKEN"]["required"] = "synthetic-invalid"
    elif case == "allowed":
        info["vars"]["RETRIES"]["allowed"] = ["synthetic-invalid"]
    else:
        info["type"] = "synthetic-unsupported"
    SPEC.write_text(yaml.safe_dump(specs))
    before = snapshot()
    diagnostics = project.validate("1.0")
    assert diagnostics and "synthetic" not in json.dumps(diagnostics)
    assert snapshot() == before


def test_schema_drift_is_detected_across_profiles(project: Envers) -> None:
    """Bind profiles to one identity and reject manual schema drift."""
    project.deploy("prod", "1.0", PASSWORD)
    base = project.profile_versions("base", PASSWORD)
    prod = project.profile_versions("prod", PASSWORD)
    assert base[0]["schema_id"] == prod[0]["schema_id"]
    populate(project)
    assert project.profile_versions("base", PASSWORD)[0]["revision"] == 2
    assert project.profile_versions("prod", PASSWORD)[0]["revision"] == 1
    assert "synthetic" not in json.dumps(base + prod)
    specs = yaml.safe_load(SPEC.read_text())
    specs["releases"]["1.0"]["spec"]["files"][".env"]["vars"]["TOKEN"][
        "required"
    ] = False
    SPEC.write_text(yaml.safe_dump(specs))
    before = LOCK.read_bytes()
    assert "schema has changed" in project.validate("1.0", "base", PASSWORD)[0]
    with pytest.raises(typer.Exit):
        project.profile_import("base", "1.0", "input.env", ".env", PASSWORD)
    assert LOCK.read_bytes() == before


def test_comparison_reports_names_and_input_needs(project: Envers) -> None:
    """Compare schema releases without decrypting or reporting values."""
    project.draft("2.0", from_spec="1.0")
    specs = yaml.safe_load(SPEC.read_text())
    variables = specs["releases"]["2.0"]["spec"]["files"][".env"]["vars"]
    variables["NEW"] = {"type": "string", "required": True}
    variables["RETRIES"] = {
        "type": "string",
        "default": "synthetic-new-default",
    }
    del variables["OPTIONAL"]
    SPEC.write_text(yaml.safe_dump(specs))
    before = snapshot()
    changes = project.compare("1.0", "2.0")
    assert changes["added"] == [".env/NEW"]
    assert changes["removed"] == [".env/OPTIONAL"]
    assert changes["changed"] == [".env/RETRIES"]
    assert changes["migration"] == [".env/RETRIES"]
    assert changes["needs_input"] == [".env/NEW"]
    assert "synthetic" not in json.dumps(changes)
    assert snapshot() == before


def test_selective_export_and_explicit_output(
    project: Envers, tmp_path: Path
) -> None:
    """Export complete selected files without requiring unrelated values."""
    populate(project)
    output = tmp_path.parent / (tmp_path.name + "-export")
    project.profile_load(
        "base", "1.0", PASSWORD, files=[".env"], output_dir=output
    )
    assert dotenv_values(output / ".env", interpolate=False) == {
        "TOKEN": TOKEN,
        "RETRIES": "5",
        "ENABLED": "true",
        "MODE": "prod",
        "EMPTY": "",
    }
    assert not (output / "config/db.env").exists()
    with pytest.raises(typer.Exit):
        project.profile_load(
            "base",
            "1.0",
            PASSWORD,
            files=[".env"],
            output_dir=Path(".envers/export"),
        )
    assert not Path(".envers/export").exists()


def test_compose_export_preserves_literals(project: Envers) -> None:
    """Use Compose's own env-file parser without running any containers."""
    binary = os.environ.get("ENVERS_COMPOSE") or shutil.which("docker-compose")
    docker = shutil.which("docker")
    command = [binary] if binary else [docker, "compose"] if docker else []
    if not command:
        if os.environ.get("ENVERS_REQUIRE_COMPOSE") == "1":
            pytest.fail("Compose is required for this CI job")
        pytest.skip("Compose is not installed")
    available = subprocess.run(
        [*command, "version"], capture_output=True, timeout=10
    )
    if available.returncode:
        if os.environ.get("ENVERS_REQUIRE_COMPOSE") == "1" or binary:
            pytest.fail("The configured Compose tool is unavailable")
        pytest.skip("The Docker CLI has no Compose plugin")
    populate(project)
    project.profile_load(
        "base",
        "1.0",
        PASSWORD,
        files=[".env"],
        output_dir=Path("export"),
        format="compose",
    )
    Path("empty.env").write_text("")
    Path("compose.yaml").write_text(
        "services:\n  app:\n    image: busybox\n    env_file: export/.env\n"
    )
    result = subprocess.run(
        [
            *command,
            "--env-file",
            "empty.env",
            "-f",
            "compose.yaml",
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env={
            **os.environ,
            "REFERENCE": "synthetic-host-ref",
            "BARE": "synthetic-host-bare",
        },
    )
    # Compose doubles dollars when printing a reusable configuration. Undo that
    # presentation step before inspecting its resolved service environment.
    resolved = json.loads(result.stdout.replace("$$", "$"))
    assert resolved["services"]["app"]["environment"] == {
        "TOKEN": TOKEN,
        "RETRIES": "5",
        "ENABLED": "true",
        "MODE": "prod",
        "EMPTY": "",
    }
