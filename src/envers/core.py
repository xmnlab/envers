"""Immutable schema releases and current, revisioned profile values.

Each value edit increments its release's revision; password rotation does not.
Backup restoration reinstates the snapshot and its revision. No value history
is retained.
"""

from __future__ import annotations

import copy
import os
import re
import shutil
import tempfile

from contextlib import contextmanager
from functools import wraps
from pathlib import Path, PureWindowsPath
from typing import (
    Any,
    Callable,
    Concatenate,
    Iterator,
    NoReturn,
    Optional,
    ParamSpec,
    TypeVar,
    cast,
)

import typer
import yaml

from cryptography.fernet import InvalidToken
from dotenv.parser import parse_stream

from envers import crypt, storage, validation

P = ParamSpec("P")
R = TypeVar("R")


def raise_error(message: str, exit_code: int = 1) -> NoReturn:
    """Raise an error using typer."""
    red_text = typer.style(message, fg=typer.colors.RED, bold=True)
    typer.echo(red_text, err=True, color=True)
    raise typer.Exit(exit_code)


def _fail(message: str) -> NoReturn:
    raise validation.InvalidConfiguration(message)


def _locked(
    method: Callable[Concatenate[Envers, P], R],
) -> Callable[Concatenate[Envers, P], R]:
    @wraps(method)
    def call(self: Envers, /, *args: P.args, **kwargs: P.kwargs) -> R:
        try:
            with self._session():
                return method(self, *args, **kwargs)
        except (
            validation.InvalidConfiguration,
            storage.StorageError,
        ) as error:
            raise_error(str(error))
        except OSError:
            raise_error(
                "Storage operation failed; run recover before retrying."
            )

    return call


def merge_dicts(
    dict_lhs: dict[str, Any], dict_rhs: dict[str, Any]
) -> dict[str, Any]:
    """
    Merge two dictionaries recursively.

    Parameters
    ----------
    dict_lhs : dict
        The primary dictionary to retain values from.
    dict_rhs : dict
        The secondary dictionary to merge values from.

    Returns
    -------
    dict
        The merged dictionary.
    """
    dict_lhs = copy.deepcopy(dict_lhs)

    for key in dict_rhs:
        if key in dict_lhs:
            if isinstance(dict_lhs[key], dict) and isinstance(
                dict_rhs[key], dict
            ):
                dict_lhs[key] = merge_dicts(dict_lhs[key], dict_rhs[key])
            else:
                dict_lhs[key] = dict_rhs[key]
        else:
            dict_lhs[key] = dict_rhs[key]
    return dict_lhs


# constants
ENVERS_SPEC_FILENAME = "specs.yaml"
# ENVERS_DATA_FILENAME = "data.lock"


def escape_template_tag(v: str) -> str:
    """Escape template tags for template rendering."""
    return v.replace("{{", r"\{\{").replace("}}", r"\}\}")


def unescape_template_tag(v: str) -> str:
    """Unescape template tags for template rendering."""
    return v.replace(r"\{\{", "{{").replace(r"\}\}", "}}")


def _atomic_write(path: Path, content: str) -> None:
    """Replace a file with fully written content using a private sibling."""
    temporary_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _render_dotenv(variables: dict[str, Any], *, compose: bool = False) -> str:
    """Quote literal values for python-dotenv with interpolation disabled."""
    lines = []
    for name, value in variables.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            _fail("Invalid dotenv variable name in profile.")
        if isinstance(value, bool):
            value = "true" if value else "false"
        escaped = (
            str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        if compose:
            escaped = escaped.replace("$", "$$")
        lines.append(f'{name}="{escaped}"\n')
    return "".join(lines)


def _checked_path(root: Path, relative: Path) -> Path:
    """Keep project paths inside their root without following symlinks."""
    path = root / relative
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        _fail("Cannot resolve project path safely.")
    if not resolved.is_relative_to(root):
        _fail("Project paths must stay within the project root.")
    if resolved != path:
        _fail("Project paths must not contain redirected components.")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _fail("Project paths must not contain symlinks.")
        if current != path and current.exists() and not current.is_dir():
            _fail("A project path parent is not a directory.")
    return path


class Envers:
    """EnversBase defined the base structure for the Envers classes."""

    def __init__(self, root: Optional[Path] = None) -> None:
        """Anchor operations to an explicit root or the current directory."""
        self.root = (Path.cwd() if root is None else Path(root)).resolve()

    def _metadata_path(
        self, relative: str, root: Optional[Path] = None
    ) -> Path:
        path = _checked_path(
            self.root if root is None else root, Path(".envers") / relative
        )
        if path.is_dir():
            _fail("A metadata file path points to a directory.")
        return path

    def _profile_path(self, profile: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", profile) or (
            PureWindowsPath(f"{profile}.lock").is_reserved()
        ):
            _fail(
                "Profile names must start with a letter or digit and contain "
                "only letters, digits, underscores, dots or hyphens. "
                "Reserved device names are not allowed."
            )
        return self._metadata_path(f"data/{profile}.lock")

    def _output_paths(
        self, files: dict[str, Any], root: Optional[Path] = None
    ) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        for name in files:
            relative = PureWindowsPath(name)
            if (
                not relative.parts
                or relative.drive
                or relative.root
                or any(
                    part == ".."
                    or ":" in part
                    or part.endswith((".", " "))
                    or PureWindowsPath(part).is_reserved()
                    for part in relative.parts
                )
            ):
                _fail("Output files must use safe relative paths.")
            if any(
                part.lower() in (".envers", ".git") for part in relative.parts
            ):
                _fail("Output files must not overwrite project metadata.")
            path = _checked_path(
                self.root if root is None else root, Path(*relative.parts)
            )
            if path.exists() and not path.is_file():
                _fail("An output file path is not a regular file.")
            if any(
                relative == other
                or relative in other.parents
                or other in relative.parents
                for other in map(PureWindowsPath, paths)
            ):
                _fail("Output file paths conflict with each other.")
            paths[name] = path
        return paths

    @contextmanager
    def _session(self, *, read_only: bool = False) -> Iterator[None]:
        lock = self._metadata_path("write.lock")
        with storage.project_lock(lock, create=not read_only):
            journal = self._metadata_path("transaction.json")
            if read_only and journal.exists():
                raise storage.StorageError(
                    "A pending transaction requires recover."
                )
            if not read_only:
                storage.recover(journal, self._metadata_path, _atomic_write)
            yield

    def _commit(self, files: dict[Path, str]) -> None:
        storage.commit(
            self._metadata_path("transaction.json"),
            files,
            self._metadata_path,
            _atomic_write,
        )

    def _read_specs(self) -> dict[str, Any]:
        path = self._metadata_path(ENVERS_SPEC_FILENAME)
        if not path.exists():
            _fail("Spec file not found. Please initialize envers first.")
        try:
            specs = validation.document(
                yaml.safe_load(path.read_text(encoding="utf-8"))
            )
        except (yaml.YAMLError, UnicodeError):
            _fail("Invalid public spec document.")
        for item in specs["releases"].values():
            self._output_paths(item["spec"]["files"])
            for profile in item["profiles"]:
                self._profile_path(profile)
        return specs

    def _release(self, specs: dict[str, Any], version: str) -> dict[str, Any]:
        if version not in specs["releases"]:
            _fail(f"Release {version} not found.")
        return cast(dict[str, Any], specs["releases"][version])

    def _read_data_file(
        self, profile: str, password: str = ""
    ) -> dict[str, Any]:
        crypt.validate_password(password)
        return self._decode_profile(
            self._profile_path(profile).read_text(encoding="utf-8"), password
        )

    def _decode_profile(self, raw: str, password: str) -> dict[str, Any]:
        try:
            data = yaml.safe_load(crypt.decrypt_data(raw, password))
            if not isinstance(data, dict) or not data:
                _fail(
                    "The data.lock is not valid; restore an encrypted backup."
                )
            return data
        except InvalidToken:
            _fail("The given password is not correct. Try it again.")
        except (ValueError, TypeError, yaml.YAMLError, UnicodeError):
            _fail("The data.lock is not valid; restore an encrypted backup.")

    def _encode_profile(self, data: dict[str, Any], password: str) -> str:
        return crypt.encrypt_data(
            yaml.safe_dump(data, sort_keys=False), password
        )

    def _write_data_file(
        self, profile: str, data: dict[str, Any], password: str = ""
    ) -> None:
        path = self._profile_path(profile)
        content = self._encode_profile(data, password)
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, content)

    def _check_store(
        self, data: dict[str, Any], profile: str, specs: dict[str, Any]
    ) -> None:
        if (
            set(data) != {"version", "profile", "releases"}
            or data.get("version") != "1"
            or data.get("profile") != profile
        ):
            _fail("Unsupported store; recreate it or restore a v1 backup.")
        releases = data.get("releases")
        if not isinstance(releases, dict) or not releases:
            _fail("Profile has no valid releases.")
        for version, entry in releases.items():
            if not isinstance(version, str) or not isinstance(entry, dict):
                _fail("Invalid stored release.")
            current = self._release(specs, version)
            if (
                set(entry) != {"spec", "schema_id", "revision", "data"}
                or profile not in current["profiles"]
            ):
                _fail("Invalid stored release binding.")
            schema = validation.release(
                entry.get("spec"), version, public=False
            )
            entry["spec"] = schema
            identity = validation.schema_id(schema)
            if (
                entry.get("schema_id") != identity
                or current.get("schema_id") != identity
            ):
                _fail(f"Release {version}: schema drift; draft a new release.")
            if type(entry.get("revision")) is not int or entry["revision"] < 1:
                _fail("Invalid profile value revision.")
            if not isinstance(entry.get("data"), dict) or set(
                entry["data"]
            ) != {profile}:
                _fail("Stored release belongs to a different profile.")
            self._check_values(entry, profile, required=False)

    def _check_values(
        self,
        entry: dict[str, Any],
        profile: str,
        *,
        required: bool,
        selected: Optional[list[str]] = None,
    ) -> None:
        definitions = entry["spec"]["spec"]["files"]
        body = entry["data"][profile]
        if not isinstance(body, dict) or not isinstance(
            body.get("files"), dict
        ):
            _fail("Invalid stored profile files.")
        files = body["files"]
        if set(files) != set(definitions):
            _fail("Stored files do not match the release contract.")
        for name, info in files.items():
            if not isinstance(info, dict) or info.get("type") != "dotenv":
                _fail("Invalid stored file format.")
            info["vars"] = validation.values(
                definitions[name]["vars"],
                info.get("vars"),
                name,
                required=required and (selected is None or name in selected),
            )

    def _load_profile(
        self, profile: str, password: str, specs: dict[str, Any]
    ) -> dict[str, Any]:
        if not self._profile_path(profile).exists():
            _fail("Data lock file not found. Please deploy a version first.")
        data = self._read_data_file(profile, password)
        self._check_store(data, profile, specs)
        return data

    def _entry(self, data: dict[str, Any], version: str) -> dict[str, Any]:
        if version not in data["releases"]:
            _fail(f"Release {version} not found in profile.")
        return cast(dict[str, Any], data["releases"][version])

    def _save_profile(
        self, profile: str, data: dict[str, Any], password: str
    ) -> None:
        self._commit(
            {self._profile_path(profile): self._encode_profile(data, password)}
        )

    def init(self, path: Path) -> None:
        """Initialize a project, including its process lock."""
        project = Envers((self.root / path).resolve())
        try:
            with project._session():
                target = project._metadata_path(ENVERS_SPEC_FILENAME)
                if not target.exists():
                    _atomic_write(target, "version: '0.1'\nreleases: {}\n")
                    storage.sync_directory(target.parent)
        except (
            validation.InvalidConfiguration,
            storage.StorageError,
        ) as error:
            raise_error(str(error))

    @_locked
    def recover(self) -> None:
        """Finish an interrupted commit; commands also recover first."""
        typer.echo("Project recovery complete.")

    def _read_dotenv(
        self, path: Path, *, allow_unset: bool = False
    ) -> dict[str, Any]:
        values = {}
        try:
            with path.open(encoding="utf-8") as stream:
                for binding in parse_stream(stream):
                    if binding.error:
                        _fail(
                            "Invalid dotenv syntax at line "
                            f"{binding.original.line}."
                        )
                    if binding.key is None:
                        continue
                    if not validation.NAME.fullmatch(binding.key):
                        _fail("Invalid dotenv variable name.")
                    if binding.value is None and not allow_unset:
                        _fail("Variable has no value; use NAME= for empty.")
                    values[binding.key] = binding.value
        except (OSError, UnicodeError):
            _fail("Cannot read dotenv input as UTF-8.")
        return values

    @_locked
    def draft(
        self, version: str, from_spec: str = "", from_env: str = ""
    ) -> None:
        """Create or update a draft; dotenv input discovers names only."""
        specs = self._read_specs()
        existing = specs["releases"].get(version, {})
        if existing and existing["status"] != "draft":
            _fail("Release is not a draft; use --from-spec for a new version.")
        if from_spec and from_env:
            _fail("Choose --from-spec or --from-env, not both.")
        release = (
            copy.deepcopy(existing)
            if existing
            else {
                "docs": "",
                "status": "draft",
                "profiles": ["base"],
                "spec": {"files": {}},
            }
        )
        if from_spec:
            release = merge_dicts(self._release(specs, from_spec), existing)
            release["status"] = "draft"
            release.pop("schema_id", None)
        elif from_env:
            path = self._output_paths({from_env: {}})[from_env]
            names = self._read_dotenv(path, allow_unset=True)
            info = release["spec"]["files"].setdefault(
                from_env, {"docs": "", "type": "dotenv", "vars": {}}
            )
            for name in names:
                info["vars"].setdefault(name, {"docs": "", "type": "string"})
        specs["releases"][version] = validation.release(release, version)
        self._output_paths(release["spec"]["files"])
        self._commit(
            {
                self._metadata_path(ENVERS_SPEC_FILENAME): yaml.safe_dump(
                    specs, sort_keys=False
                )
            }
        )

    @_locked
    def deploy(
        self, profile: str, spec: str, password: Optional[str] = None
    ) -> None:
        """Bind a profile to an immutable schema; unset values stay absent."""
        specs = self._read_specs()
        release = self._release(specs, spec)
        if profile not in release["profiles"]:
            _fail(f"Profile '{profile}' is not defined for this release.")
        if release["status"] not in ("draft", "deployed"):
            _fail("Release is not available for deployment.")
        path = self._profile_path(profile)
        if password is None:
            password = crypt.get_password()
            if not path.exists() and password != crypt.get_password(
                "Confirm your password"
            ):
                _fail("The password and confirmation do not match.")
        crypt.validate_password(password)
        if path.exists():
            data = self._load_profile(profile, password, specs)
            if spec in data["releases"]:
                _fail(
                    "Release is already deployed; use profile-set "
                    "or draft a new version."
                )
        else:
            data = {"version": "1", "profile": profile, "releases": {}}
        schema = copy.deepcopy(release)
        schema.pop("status", None)
        schema.pop("schema_id", None)
        identity = validation.schema_id(schema)
        files = {}
        for name, info in schema["spec"]["files"].items():
            files[name] = {
                "type": "dotenv",
                "vars": {
                    key: copy.deepcopy(definition["default"])
                    for key, definition in info["vars"].items()
                    if "default" in definition
                },
            }
        data["releases"][spec] = {
            "spec": schema,
            "schema_id": identity,
            "revision": 1,
            "data": {profile: {"files": files}},
        }
        release.update(status="deployed", schema_id=identity)
        spec_content = yaml.safe_dump(specs, sort_keys=False)
        self._commit(
            {
                path: self._encode_profile(data, password),
                self._metadata_path(ENVERS_SPEC_FILENAME): spec_content,
            }
        )

    @_locked
    def profile_set(
        self, profile: str, spec: str, password: Optional[str] = None
    ) -> None:
        """Edit values privately; Enter retains the current or unset value."""
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        data = self._load_profile(profile, password, specs)
        entry = self._entry(data, spec)
        before = copy.deepcopy(entry["data"])
        width = shutil.get_terminal_size().columns
        typer.echo(f" Profile: {profile} ".center(width, "="))
        for filename, info in entry["spec"]["spec"]["files"].items():
            typer.echo(f">>> File: {filename}")
            values = entry["data"][profile]["files"][filename]["vars"]
            for name, definition in info["vars"].items():
                value = typer.prompt(
                    f"Enter value for `{name}` (Enter to keep current)",
                    default="",
                    show_default=False,
                    hide_input=True,
                )
                if value:
                    values[name] = validation.coerce(
                        definition, value, f"{filename}/{name}"
                    )
        if before != entry["data"]:
            entry["revision"] += 1
            self._save_profile(profile, data, password)

    @_locked
    def profile_import(
        self,
        profile: str,
        spec: str,
        from_env: str,
        file_path: str = "",
        password: Optional[str] = None,
    ) -> None:
        """Import literal typed values, rejecting the entire input on error."""
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        data = self._load_profile(profile, password, specs)
        entry = self._entry(data, spec)
        target = file_path or from_env
        files = entry["data"][profile]["files"]
        if target not in files:
            _fail("Target file is not declared in this profile release.")
        incoming = self._read_dotenv(self.root / from_env)
        if not incoming:
            _fail("Dotenv input contains no values.")
        definitions = entry["spec"]["spec"]["files"][target]["vars"]
        values = validation.values(
            definitions, incoming, target, required=False
        )
        updated = {**files[target]["vars"], **values}
        if updated != files[target]["vars"]:
            files[target]["vars"] = updated
            entry["revision"] += 1
            self._save_profile(profile, data, password)
        typer.echo("Profile values imported.")

    def _export_root(self, directory: Optional[Path]) -> Path:
        if directory is None:
            return self.root
        root = (self.root / directory).resolve()
        if root.exists() and not root.is_dir():
            _fail("Output placement must be a directory.")
        if any(part.lower() in (".envers", ".git") for part in root.parts):
            _fail("Output placement must not overwrite project metadata.")
        return root

    @_locked
    def profile_load(
        self,
        profile: str,
        spec: str,
        password: Optional[str] = None,
        *,
        files: Optional[list[str]] = None,
        output_dir: Optional[Path] = None,
        format: str = "dotenv",
    ) -> None:
        """Export selected files; compose format escapes literal dollars."""
        if format not in ("dotenv", "compose"):
            _fail("Export format must be dotenv or compose.")
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        data = self._load_profile(profile, password, specs)
        entry = self._entry(data, spec)
        source = entry["data"][profile]["files"]
        selected = list(source) if files is None else files
        if (
            not selected
            or len(set(selected)) != len(selected)
            or set(selected) - set(source)
        ):
            _fail("Select unique files declared in this release.")
        self._check_values(entry, profile, required=True, selected=selected)
        root = self._export_root(output_dir)
        paths = self._output_paths(
            {name: source[name] for name in selected}, root
        )
        output = {
            paths[name]: _render_dotenv(
                source[name]["vars"], compose=format == "compose"
            )
            for name in selected
        }
        for path, content in output.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(path, content)
        typer.echo("Environment files created/updated.")

    def validate(
        self, spec: str, profile: str = "", password: Optional[str] = None
    ) -> list[str]:
        """Return diagnostics without values, prompts or file writes."""
        try:
            with self._session(read_only=True):
                specs = self._read_specs()
                self._release(specs, spec)
                if profile:
                    if password is None:
                        _fail("A password is required for profile validation.")
                    data = self._load_profile(profile, password, specs)
                    self._check_values(
                        self._entry(data, spec), profile, required=True
                    )
            return []
        except (
            validation.InvalidConfiguration,
            storage.StorageError,
            typer.BadParameter,
        ) as error:
            return [str(error)]
        except OSError:
            return [
                "Cannot read project; initialize it or check file permissions."
            ]

    def compare(self, from_spec: str, to_spec: str) -> dict[str, Any]:
        """Compare schema contracts without decrypting or displaying values."""
        with self._session(read_only=True):
            specs = self._read_specs()
            previous = self._release(specs, from_spec)
            target = self._release(specs, to_spec)
            old = previous["spec"]["files"]
            new = target["spec"]["files"]
            result: dict[str, Any] = {
                "profiles_added": sorted(
                    set(target["profiles"]) - set(previous["profiles"])
                ),
                "profiles_removed": sorted(
                    set(previous["profiles"]) - set(target["profiles"])
                ),
                "files_added": sorted(set(new) - set(old)),
                "files_removed": sorted(set(old) - set(new)),
                "added": [],
                "removed": [],
                "changed": [],
                "migration": [],
                "needs_input": [],
            }
            for filename in sorted(set(old) | set(new)):
                lhs = old.get(filename, {}).get("vars", {})
                rhs = new.get(filename, {}).get("vars", {})
                for name in sorted(set(lhs) | set(rhs)):
                    identifier = f"{filename}/{name}"
                    if name not in lhs:
                        result["added"].append(identifier)
                    elif name not in rhs:
                        result["removed"].append(identifier)
                    else:
                        left = {
                            key: value
                            for key, value in lhs[name].items()
                            if key != "docs"
                        }
                        right = {
                            key: value
                            for key, value in rhs[name].items()
                            if key != "docs"
                        }
                        for definition in (left, right):
                            definition.setdefault("type", "string")
                            definition.setdefault("required", False)
                        if left != right:
                            result["changed"].append(identifier)
                        if any(
                            left.get(rule) != right.get(rule)
                            for rule in ("type", "allowed")
                        ):
                            result["migration"].append(identifier)
                    if (
                        name in rhs
                        and rhs[name].get("required")
                        and "default" not in rhs[name]
                        and (name not in lhs or lhs[name] != rhs[name])
                    ):
                        result["needs_input"].append(identifier)
            return result

    @_locked
    def profile_versions(
        self, profile: str, password: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """List schema identities and current value revision numbers."""
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        data = self._load_profile(profile, password, specs)
        return [
            {
                "version": version,
                "schema_id": entry["schema_id"],
                "revision": entry["revision"],
            }
            for version, entry in data["releases"].items()
        ]

    @_locked
    def profile_password(
        self,
        profile: str,
        password: Optional[str] = None,
        new_password: Optional[str] = None,
    ) -> None:
        """Re-encrypt releases with a new password; retain their values."""
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        data = self._load_profile(profile, password, specs)
        if new_password is None:
            new_password = crypt.get_password("Enter the new password")
            if new_password != crypt.get_password("Confirm the new password"):
                _fail("The new password and confirmation do not match.")
        crypt.validate_password(new_password)
        self._save_profile(profile, data, new_password)
        typer.echo("Profile password changed.")

    @_locked
    def profile_backup(
        self, profile: str, destination: Path, password: Optional[str] = None
    ) -> None:
        """Write an encrypted backup protected by the current password."""
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        self._load_profile(profile, password, specs)
        destination = self.root / destination
        root = self._export_root(destination.parent)
        path = self._output_paths({destination.name: {}}, root)[
            destination.name
        ]
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            path, self._profile_path(profile).read_text(encoding="utf-8")
        )
        typer.echo("Encrypted profile backup created.")

    @_locked
    def profile_restore(
        self, profile: str, source: Path, password: Optional[str] = None
    ) -> None:
        """Restore a missing/corrupt profile from a compatible backup."""
        specs = self._read_specs()
        password = crypt.get_password() if password is None else password
        data = self._decode_profile(
            (self.root / source).read_text(encoding="utf-8"), password
        )
        self._check_store(data, profile, specs)
        self._save_profile(profile, data, password)
        typer.echo("Encrypted profile restored.")
