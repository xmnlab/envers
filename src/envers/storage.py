"""Process exclusion and recoverable commits of encrypted profile metadata."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import sys

from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator


class StorageError(ValueError):
    """A storage operation cannot proceed safely."""


def sync_directory(path: Path) -> None:
    """Persist directory changes on platforms supporting directory fsync."""
    if sys.platform == "win32":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
    finally:
        os.close(descriptor)


@contextmanager
def project_lock(path: Path, *, create: bool) -> Iterator[None]:
    """Hold an OS lock released automatically if the process exits."""
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
            )
        except FileExistsError:
            descriptor = os.open(
                path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            )
            fresh = False
        else:
            fresh = True
    else:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        fresh = False
    with os.fdopen(descriptor, "rb") as file:
        if fresh:
            os.write(file.fileno(), b"0")
            os.fsync(file.fileno())
        file.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise StorageError(
                "Project is busy; retry after the other command exits."
            ) from None
        try:
            yield
        finally:
            if sys.platform == "win32":
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def recover(
    journal: Path,
    resolve: Callable[[str], Path],
    write: Callable[[Path, str], None],
) -> bool:
    """Replay a durable commit without needing profile passwords."""
    if not journal.exists():
        return False
    try:
        transaction = json.loads(journal.read_text(encoding="utf-8"))
        if (
            set(transaction) != {"version", "files"}
            or type(transaction["version"]) is not int
            or transaction["version"] != 1
        ):
            raise ValueError
        files = transaction["files"]
        if not isinstance(files, dict) or not files:
            raise ValueError
        prepared = []
        for name, entry in files.items():
            if name != "specs.yaml" and not re.fullmatch(
                r"data/[A-Za-z0-9][A-Za-z0-9_.-]*\.lock", name
            ):
                raise ValueError
            if not isinstance(entry, dict) or set(entry) != {
                "content",
                "sha256",
            }:
                raise ValueError
            content = entry["content"]
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if digest != entry["sha256"]:
                raise ValueError
            if name.startswith("data/"):
                envelope = json.loads(content)
                if envelope.get("format") != "envers-v1":
                    raise ValueError
            prepared.append((resolve(name), content))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise StorageError(
            "Invalid transaction journal; restore a project backup."
        ) from None
    for path, content in prepared:
        path.parent.mkdir(parents=True, exist_ok=True)
        write(path, content)
        sync_directory(path.parent)
    journal.unlink()
    sync_directory(journal.parent)
    return True


def commit(
    journal: Path,
    files: dict[Path, str],
    resolve: Callable[[str], Path],
    write: Callable[[Path, str], None],
) -> None:
    """Record all new content before replacing any destination."""
    entries = {
        path.relative_to(journal.parent).as_posix(): {
            "content": content,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
        for path, content in files.items()
    }
    write(journal, json.dumps({"version": 1, "files": entries}))
    sync_directory(journal.parent)
    recover(journal, resolve, write)
