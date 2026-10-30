"""Release contracts and value-free diagnostics."""

from __future__ import annotations

import copy
import hashlib
import json
import re

from typing import Any, NoReturn

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
TYPES = {"string", "int", "bool", "path"}


class InvalidConfiguration(ValueError):
    """A document or value violates the release contract."""


def invalid(location: str, rule: str) -> NoReturn:
    """Raise a diagnostic containing an identifier and rule, never a value."""
    raise InvalidConfiguration(f"{location}: {rule}")


def coerce(definition: dict[str, Any], value: Any, location: str) -> Any:
    """Interpret dotenv strings according to their declared type."""
    kind = definition.get("type", "string")
    if kind in ("string", "path"):
        valid = isinstance(value, str) and "\x00" not in value
    elif kind == "int":
        valid = type(value) is int or (
            isinstance(value, str)
            and bool(re.fullmatch(r"[+-]?[0-9]+", value))
        )
        if valid:
            value = int(value)
    elif kind == "bool":
        valid = type(value) is bool or (
            isinstance(value, str) and value.lower() in ("true", "false")
        )
        if valid and isinstance(value, str):
            value = value.lower() == "true"
    else:
        invalid(location, "unsupported type")
    if not valid:
        invalid(location, f"expected {kind}")
    if definition.get("required", False) and value == "":
        invalid(location, "required value cannot be empty")
    if "allowed" in definition and value not in definition["allowed"]:
        invalid(location, "value is not in the allowed set")
    return value


def release(raw: Any, location: str, *, public: bool = True) -> dict[str, Any]:
    """Validate and normalize one release's schema."""
    if not isinstance(raw, dict):
        invalid(location, "expected a release mapping")
    result = copy.deepcopy(raw)
    if set(result) - {"docs", "status", "profiles", "spec", "schema_id"}:
        invalid(location, "unknown release field")
    if "docs" in result and not isinstance(result["docs"], str):
        invalid(location, "docs must be a string")
    if public and result.get("status") not in (
        "draft",
        "deployed",
        "cancelled",
    ):
        invalid(location, "invalid release status")
    profiles = result.get("profiles")
    if (
        not isinstance(profiles, list)
        or not profiles
        or any(not isinstance(item, str) or not item for item in profiles)
    ):
        invalid(location, "profiles must be a nonempty list of names")
    if len({item.casefold() for item in profiles}) != len(profiles):
        invalid(location, "profile names must be unique")
    spec = result.get("spec")
    if not isinstance(spec, dict) or set(spec) != {"files"}:
        invalid(location, "spec must contain a files mapping")
    if not isinstance(spec["files"], dict):
        invalid(location, "files must be a mapping")
    for filename, info in spec["files"].items():
        if not isinstance(filename, str) or not filename:
            invalid(location, "file names must be nonempty strings")
        here = f"{location}/{filename}"
        if not isinstance(info, dict) or set(info) - {"docs", "type", "vars"}:
            invalid(here, "invalid file definition")
        if info.get("type", "dotenv") != "dotenv":
            invalid(here, "only dotenv files are supported")
        if "docs" in info and not isinstance(info["docs"], str):
            invalid(here, "docs must be a string")
        definitions = info.get("vars")
        if not isinstance(definitions, dict):
            invalid(here, "vars must be a mapping")
        for name, definition in definitions.items():
            if not isinstance(name, str) or not NAME.fullmatch(name):
                invalid(here, "invalid variable name")
            context = f"{here}/{name}"
            if not isinstance(definition, dict) or set(definition) - {
                "docs",
                "type",
                "default",
                "required",
                "allowed",
            }:
                invalid(context, "invalid variable definition")
            kind = definition.get("type", "string")
            if not isinstance(kind, str) or kind not in TYPES:
                invalid(context, "unsupported type")
            if "docs" in definition and not isinstance(
                definition["docs"], str
            ):
                invalid(context, "docs must be a string")
            if type(definition.get("required", False)) is not bool:
                invalid(context, "required must be boolean")
            if "allowed" in definition:
                allowed = definition["allowed"]
                if not isinstance(allowed, list) or not allowed:
                    invalid(context, "allowed must be a nonempty list")
                unconstrained = {"type": definition.get("type", "string")}
                definition["allowed"] = [
                    coerce(unconstrained, item, context) for item in allowed
                ]
            if "default" in definition:
                definition["default"] = coerce(
                    definition, definition["default"], context
                )
    identity = result.get("schema_id")
    if identity is not None and identity != schema_id(result):
        invalid(location, "deployed schema has changed; draft a new release")
    if public and result.get("status") == "deployed" and identity is None:
        invalid(location, "deployed release has no schema identity")
    return result


def document(raw: Any) -> dict[str, Any]:
    """Check the public spec document without reading any profile values."""
    if not isinstance(raw, dict) or set(raw) - {"version", "releases"}:
        invalid("spec", "expected a versioned release document")
    if raw.get("version") != "0.1":
        invalid("spec", "unsupported document version")
    releases = raw.get("releases")
    if releases is None:
        releases = {}
    if not isinstance(releases, dict):
        invalid("spec", "releases must be a mapping")
    result: dict[str, Any] = {"version": "0.1", "releases": {}}
    for version, item in releases.items():
        if not isinstance(version, str) or not version:
            invalid("spec", "release identifiers must be nonempty strings")
        result["releases"][version] = release(item, version)
    return result


def schema_id(schema: dict[str, Any]) -> str:
    """Identify the contract independently of status and documentation."""
    files = copy.deepcopy(schema["spec"]["files"])
    for info in files.values():
        info.pop("docs", None)
        info.setdefault("type", "dotenv")
        for definition in info["vars"].values():
            definition.pop("docs", None)
            definition.setdefault("type", "string")
            definition.setdefault("required", False)
    contract = {"profiles": sorted(schema["profiles"]), "files": files}
    raw = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def values(
    definitions: dict[str, Any], raw: Any, location: str, *, required: bool
) -> dict[str, Any]:
    """Validate supplied values and optionally require a complete profile."""
    if not isinstance(raw, dict):
        invalid(location, "values must be a mapping")
    if set(raw) - set(definitions):
        invalid(location, "contains undeclared variables")
    result = {}
    for name, definition in definitions.items():
        context = f"{location}/{name}"
        if name not in raw:
            if required and definition.get("required", False):
                invalid(context, "required value is unset")
            continue
        result[name] = coerce(definition, raw[name], context)
    return result
