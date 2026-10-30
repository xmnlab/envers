"""Command-line operations for release contracts and encrypted profiles."""

from __future__ import annotations

import json
import sys

from pathlib import Path
from typing import Optional

import typer

from typer import Context, Option
from typing_extensions import Annotated

from envers import __version__, crypt, storage, validation
from envers.core import Envers, raise_error

app = typer.Typer(pretty_exceptions_show_locals=False)
Profile = Annotated[str, Option(help="Deployment profile name.")]
Spec = Annotated[str, Option(help="Release identifier.")]


@app.callback(invoke_without_command=True)
def main(
    ctx: Context,
    version: Annotated[
        bool, Option("--version", "-v", help="Show the version.")
    ] = False,
) -> None:
    """Manage configuration contracts and encrypted deployment profiles."""
    if version:
        typer.echo(f"Version: {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command()
def init(path: str = ".") -> None:
    """Initialize a project and its process lock."""
    Envers().init(Path(path))


@app.command()
def draft(version: str, from_spec: str = "", from_env: str = "") -> None:
    """Draft a schema; --from-env imports names, never values."""
    Envers().draft(version, from_spec, from_env)


@app.command()
def deploy(profile: Profile, spec: Spec) -> None:
    """Freeze a release's schema and initialize its profile values."""
    Envers().deploy(profile, spec)


@app.command()
def profile_set(profile: Profile, spec: Spec) -> None:
    """Edit values privately; Enter keeps the current or unset value."""
    Envers().profile_set(profile, spec)


@app.command()
def profile_import(
    profile: Profile,
    spec: Spec,
    from_env: Annotated[
        Path, Option(help="Dotenv source file; no interpolation.")
    ],
    file_path: Annotated[
        str,
        Option("--file", help="Declared target file; defaults to --from-env."),
    ] = "",
) -> None:
    """Import typed values. NAME= is empty; omitted names stay unchanged."""
    Envers().profile_import(profile, spec, str(from_env), file_path)


@app.command()
def profile_load(
    profile: Profile,
    spec: Spec,
    files: Annotated[
        Optional[list[str]],
        Option("--file", help="Export only these declared files; repeatable."),
    ] = None,
    output_dir: Annotated[
        Optional[Path],
        Option(
            help="Explicit export directory, including outside the project."
        ),
    ] = None,
    format: Annotated[
        str,
        Option(help="dotenv (no interpolation) or compose (literal dollars)."),
    ] = "dotenv",
) -> None:
    """Export validated plaintext (private permissions on POSIX)."""
    Envers().profile_load(
        profile, spec, files=files, output_dir=output_dir, format=format
    )


@app.command()
def validate(
    spec: Spec,
    profile: Annotated[
        str,
        Option(
            help="Validate this profile too; supply its password on stdin."
        ),
    ] = "",
) -> None:
    """Read-only checks: JSON diagnostics; exit 0 valid or 1 invalid."""
    password = None
    errors = []
    if profile:
        if sys.stdin.isatty():
            errors = ["Validation never prompts; supply a password on stdin."]
        else:
            try:
                password = crypt.get_password()
            except typer.BadParameter as error:
                errors = [error.message]
    if not errors:
        errors = Envers().validate(spec, profile, password)
    typer.echo(json.dumps({"valid": not errors, "errors": errors}))
    raise typer.Exit(1 if errors else 0)


@app.command()
def compare(
    from_spec: Annotated[str, Option(help="Source release identifier.")],
    to_spec: Annotated[str, Option(help="Target release identifier.")],
) -> None:
    """Compare release contracts and input needs without values."""
    try:
        result = Envers().compare(from_spec, to_spec)
    except (validation.InvalidConfiguration, storage.StorageError) as error:
        raise_error(str(error))
    except OSError:
        raise_error("Cannot read project.")
    typer.echo(json.dumps(result, sort_keys=True))


@app.command()
def profile_versions(profile: Profile) -> None:
    """List deployed versions, schema identities and value revisions."""
    typer.echo(json.dumps(Envers().profile_versions(profile), sort_keys=True))


@app.command()
def profile_password(profile: Profile) -> None:
    """Change a password: stdin takes current, new and confirmation lines."""
    Envers().profile_password(profile)


@app.command()
def profile_backup(
    profile: Profile,
    output: Annotated[Path, Option(help="Encrypted backup destination.")],
) -> None:
    """Copy an encrypted profile, protected by its current password."""
    Envers().profile_backup(profile, output)


@app.command()
def profile_restore(
    profile: Profile,
    from_backup: Annotated[
        Path, Option(help="Encrypted backup; supply its password.")
    ],
) -> None:
    """Replace a profile from a schema-compatible encrypted backup."""
    Envers().profile_restore(profile, from_backup)


@app.command()
def recover() -> None:
    """Complete an interrupted commit; no password is required."""
    Envers().recover()


if __name__ == "__main__":
    app()
