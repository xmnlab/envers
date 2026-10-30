"""Native v1 envelope: JSON with format, kdf, iterations, salt and token.

The salt is 16 random bytes encoded as hex. PBKDF2-HMAC-SHA256 uses 1,200,000
iterations and derives a 32-byte Fernet key. The Fernet token authenticates the
encrypted document. KDF parameters are fixed for this envelope version and
checked before derivation. Old unversioned profiles must be recreated.
"""

from __future__ import annotations

import base64
import json
import os
import sys

from typing import Optional, cast

import typer

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LENGTH = 16
KDF_ITERATIONS = 1_200_000


def create_fernet_key(password: str, salt: bytes) -> bytes:
    """Create a Fernet key."""
    # Use PBKDF2HMAC to derive a Fernet-compatible key from the user password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def get_password(message: str = "") -> str:
    """Prompt a password."""
    if sys.stdin.isatty():
        # Interactive mode: Use Typer's prompt
        message = "Enter your password" if not message else message
        password = cast(
            str,
            typer.prompt(
                message, hide_input=True, default="", show_default=False
            ),
        )
    else:
        # Non-interactive mode: Read from stdin
        line = sys.stdin.readline()
        if not line:
            raise typer.BadParameter("No password received on stdin.")
        password = line.rstrip("\r\n")
    validate_password(password)
    return password


def validate_password(password: str) -> None:
    """Reject an empty credential without displaying it."""
    if not password:
        raise typer.BadParameter("Password cannot be empty.")


def generate_salt() -> bytes:
    """Generate a salt in byte format."""
    return os.urandom(SALT_LENGTH)


def encrypt_data(data: str, password: Optional[str] = None) -> str:
    """Encrypt the given data."""
    if password is None:
        password = get_password()
    validate_password(password)

    salt = generate_salt()
    key = create_fernet_key(password, salt)
    cipher_suite = Fernet(key)

    encrypted = cipher_suite.encrypt(data.encode("utf-8")).decode("utf-8")
    return json.dumps(
        {
            "format": "envers-v1",
            "kdf": "pbkdf2-sha256",
            "iterations": KDF_ITERATIONS,
            "salt": salt.hex(),
            "token": encrypted,
        },
        sort_keys=True,
    )


def decrypt_data(data: str, password: Optional[str] = None) -> str:
    """Decrypt the given data."""
    if password is None:
        password = get_password()
    validate_password(password)

    envelope = json.loads(data)
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"format", "kdf", "iterations", "salt", "token"}
        or (
            envelope["format"] != "envers-v1"
            or envelope["kdf"] != "pbkdf2-sha256"
            or type(envelope["iterations"]) is not int
            or envelope["iterations"] != KDF_ITERATIONS
            or not isinstance(envelope["salt"], str)
            or not isinstance(envelope["token"], str)
        )
    ):
        raise ValueError("Unsupported encrypted profile envelope")
    salt = bytes.fromhex(envelope["salt"])
    if len(salt) != SALT_LENGTH:
        raise ValueError("Invalid profile salt")

    key = create_fernet_key(password, salt)
    cipher_suite = Fernet(key)

    return cipher_suite.decrypt(envelope["token"].encode("utf-8")).decode(
        "utf-8"
    )
