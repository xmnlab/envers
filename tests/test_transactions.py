"""Process exclusion, interruption recovery and encrypted backup lifecycle."""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys

from pathlib import Path

import pytest
import typer
import yaml

from envers import crypt
from envers.cli import app
from envers.core import Envers
from typer.testing import CliRunner

PASSWORD = "synthetic recovery password"
LOCK = Path(".envers/data/base.lock")


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Envers:
    """Create an editable schema with a synthetic public default."""
    monkeypatch.chdir(tmp_path)
    project = Envers()
    project.init(Path("."))
    project.draft("1.0")
    path = Path(".envers/specs.yaml")
    specs = yaml.safe_load(path.read_text())
    specs["releases"]["1.0"]["spec"]["files"] = {
        ".env": {
            "type": "dotenv",
            "vars": {
                "TOKEN": {"type": "string", "default": "synthetic-value"}
            },
        }
    }
    path.write_text(yaml.safe_dump(specs))
    return project


def test_other_process_excludes_updates_and_death_releases_lock(
    project: Envers,
) -> None:
    """Exclude competing writers and release locks on process death."""
    code = """from envers.core import Envers
import sys
from pathlib import Path
p = Envers(Path(sys.argv[1]))
with p._session():
    print('locked', flush=True)
    sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(project.root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline() == "locked\n"
        before = Path(".envers/specs.yaml").read_bytes()
        result = CliRunner().invoke(app, "draft 2.0")
        assert result.exit_code == 1 and "busy" in result.output
        assert Path(".envers/specs.yaml").read_bytes() == before
    finally:
        child.kill()
        child.communicate(timeout=5)
    project.draft("2.0")
    assert set(
        yaml.safe_load(Path(".envers/specs.yaml").read_text())["releases"]
    ) == {"1.0", "2.0"}


def test_process_crash_between_deployment_writes_is_recoverable(
    project: Envers,
) -> None:
    """Replay an encrypted journal after a real process exits mid-commit."""
    code = """import os, sys
from pathlib import Path
from envers import core
p = core.Envers(Path(sys.argv[1]))
write = core._atomic_write
def crash(path, content):
    write(path, content)
    if path == p._profile_path('base'):
        os._exit(73)
core._atomic_write = crash
p.deploy('base', '1.0', sys.stdin.readline().rstrip('\\n'))
"""
    child = subprocess.run(
        [sys.executable, "-c", code, str(project.root)],
        input=PASSWORD + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert child.returncode == 73, child.stderr
    journal = Path(".envers/transaction.json")
    assert journal.exists()
    payload = json.loads(journal.read_text())
    ciphertext = payload["files"]["data/base.lock"]["content"]
    assert (
        "synthetic-value" not in ciphertext
        and PASSWORD not in journal.read_text()
    )
    assert project.validate("1.0", "base", PASSWORD) == [
        "A pending transaction requires recover."
    ]
    result = CliRunner().invoke(app, "recover")
    assert result.exit_code == 0
    assert not journal.exists()
    assert project.validate("1.0", "base", PASSWORD) == []
    assert project.profile_versions("base", PASSWORD)[0]["revision"] == 1


def test_rotation_backup_restore_and_failed_credentials(
    project: Envers,
) -> None:
    """Rotate and restore values; failed authentication preserves data."""
    project.deploy("base", "1.0", PASSWORD)
    original = project._read_data_file("base", PASSWORD)
    project.profile_backup("base", Path("backup.lock"), PASSWORD)
    assert "synthetic-value" not in Path("backup.lock").read_text()
    before = LOCK.read_bytes()
    result = CliRunner().invoke(
        app,
        "profile-password --profile base",
        input=PASSWORD + "\nnew-password\nmismatch\n",
    )
    assert result.exit_code == 1 and LOCK.read_bytes() == before
    new_password = "synthetic new password \t "
    project.profile_password("base", PASSWORD, new_password)
    assert project._read_data_file("base", new_password) == original
    before = LOCK.read_bytes()
    with pytest.raises(typer.Exit):
        project.profile_password("base", PASSWORD, "unused")
    assert LOCK.read_bytes() == before
    envelope = json.loads(before)
    assert envelope["format"] == "envers-v1"
    assert envelope["iterations"] == crypt.KDF_ITERATIONS
    envelope["iterations"] *= 1000
    with pytest.raises(ValueError, match="Unsupported"):
        crypt.decrypt_data(json.dumps(envelope), new_password)
    LOCK.write_text("synthetic-corruption")
    project.profile_restore("base", Path("backup.lock"), PASSWORD)
    assert project._read_data_file("base", PASSWORD) == original
    assert project.validate("1.0", "base", PASSWORD) == []


def test_invalid_recovery_journal_cannot_overwrite_arbitrary_paths(
    project: Envers,
) -> None:
    """Validate the complete journal before applying any recovery write."""
    path = Path(".envers/transaction.json")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "files": {
                    "../escape": {"content": "synthetic", "sha256": "invalid"}
                },
            }
        )
    )
    before = Path(".envers/specs.yaml").read_bytes()
    result = CliRunner().invoke(app, "recover")
    assert result.exit_code == 1
    assert "Invalid transaction" in result.output
    assert not Path("escape").exists()
    assert Path(".envers/specs.yaml").read_bytes() == before
    assert path.exists()


@pytest.mark.skipif(
    sys.platform == "win32", reason="Directory fsync is POSIX-only"
)
@pytest.mark.parametrize("error", [errno.EINVAL, errno.EIO])
def test_directory_sync_distinguishes_unsupported_and_failed_storage(
    project: Envers, monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    """Ignore unsupported sync; retain recovery state on real disk errors."""
    sync = os.fsync

    def directory_error(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(error, "synthetic directory sync failure")
        sync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", directory_error)
        if error == errno.EINVAL:
            project.deploy("base", "1.0", PASSWORD)
        else:
            with pytest.raises(typer.Exit):
                project.deploy("base", "1.0", PASSWORD)
            assert Path(".envers/transaction.json").exists()
    project.recover()
    assert project.validate("1.0", "base", PASSWORD) == []
