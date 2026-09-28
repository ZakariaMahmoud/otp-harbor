from __future__ import annotations

import argparse
import base64
import os
import sqlite3
import sys
from pathlib import Path

from sqlalchemy import func, select

from app.auth import create_api_key
from app.config import ConfigurationError, Settings
from app.crypto import associated_data, decrypt_secret, encrypt_secret
from app.database import Base, build_engine, session_factory
from app.models import ApiClient, Credential


def cmd_init(settings: Settings) -> None:
    settings.load_master_key()
    engine = build_engine(settings.database_url)
    Base.metadata.create_all(engine)
    print("Database initialized.")


def cmd_bootstrap(settings: Settings, name: str) -> None:
    settings.load_master_key()
    engine = build_engine(settings.database_url)
    Base.metadata.create_all(engine)
    factory = session_factory(engine)
    with factory() as session:
        if session.scalar(select(func.count()).select_from(ApiClient)):
            raise RuntimeError("bootstrap is disabled after the first API client exists")
        generated = create_api_key()
        client = ApiClient(name=name, key_id=generated.key_id, key_hash=generated.verifier, role="admin")
        session.add(client)
        session.commit()
        print("Administrator created. Store this API key now; it cannot be recovered:")
        print(generated.plaintext)


def cmd_rotate(settings: Settings, new_key_file: Path) -> None:
    old_key = settings.load_master_key()
    temporary = Settings(settings.database_url, new_key_file)
    new_key = temporary.load_master_key()
    if old_key == new_key:
        raise RuntimeError("new key must differ from current key")
    engine = build_engine(settings.database_url)
    factory = session_factory(engine)
    with factory() as session, session.begin():
        for item in session.scalars(select(Credential)):
            aad = associated_data(credential_id=item.id, issuer=item.issuer, account_name=item.account_name,
                                  algorithm=item.algorithm, digits=item.digits, period=item.period)
            secret = decrypt_secret(old_key, item.encrypted_secret, item.nonce, aad)
            item.encrypted_secret, item.nonce = encrypt_secret(new_key, secret, aad)
    print("Database rotated. Activate the new key before restarting the service.")


def cmd_generate_key(output: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(output, flags, 0o400)
    try:
        os.write(fd, base64.b64encode(os.urandom(32)) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    print(f"Created {output} with mode 0400.")


def cmd_backup(settings: Settings, output: Path) -> None:
    prefix = "sqlite:///"
    if not settings.database_url.startswith(prefix):
        raise RuntimeError("the built-in backup command supports SQLite only")
    source = Path(settings.database_url.removeprefix(prefix))
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(source) as source_db, sqlite3.connect(output) as backup_db:
            source_db.backup(backup_db)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    print(f"Encrypted database backup created at {output}; the master key was not copied.")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="otp-harbor")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db")
    bootstrap = commands.add_parser("bootstrap-admin")
    bootstrap.add_argument("--name", default="initial administrator")
    rotate = commands.add_parser("rotate-key")
    rotate.add_argument("--new-key-file", type=Path, required=True)
    generate = commands.add_parser("generate-key")
    generate.add_argument("--output", type=Path, required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--output", type=Path, required=True)
    return result


def main() -> None:
    os.umask(0o077)
    args = parser().parse_args()
    try:
        if args.command == "generate-key":
            cmd_generate_key(args.output)
            return
        settings = Settings.from_env()
        if args.command == "init-db":
            cmd_init(settings)
        elif args.command == "bootstrap-admin":
            cmd_bootstrap(settings, args.name)
        elif args.command == "rotate-key":
            cmd_rotate(settings, args.new_key_file)
        elif args.command == "backup":
            cmd_backup(settings, args.output)
    except (ConfigurationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
