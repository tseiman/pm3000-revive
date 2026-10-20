#!/usr/bin/env python3
"""Provision and administer PM3000 REST tokens on a trusted host."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

from token_store import IssuedTokenDurabilityError, TokenStore, TokenStoreError


def _add_store_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--store", required=True, type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provision and administer REST bearer tokens. Newly generated plaintext "
            "tokens are written once as JSON to standard output."
        ),
        allow_abbrev=False,
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    bootstrap = subcommands.add_parser("bootstrap", allow_abbrev=False)
    _add_store_argument(bootstrap)
    bootstrap.add_argument("--label", required=True)

    create = subcommands.add_parser("create", allow_abbrev=False)
    _add_store_argument(create)
    create.add_argument("--label", required=True)
    create.add_argument("--scope", required=True, choices=("read", "control", "admin"))
    create.add_argument("--outlet", action="append", dest="outlets")

    list_command = subcommands.add_parser("list", allow_abbrev=False)
    _add_store_argument(list_command)

    for command in ("disable", "enable", "revoke"):
        mutation = subcommands.add_parser(command, allow_abbrev=False)
        _add_store_argument(mutation)
        mutation.add_argument("--id", required=True)
    return parser


def _read_administrator_token() -> str:
    if sys.stdin.isatty():
        token = getpass.getpass("Administrator token: ")
    else:
        token = sys.stdin.readline(129).rstrip("\r\n")
    if re.fullmatch(r"pm3_[A-Za-z0-9_-]{43}", token) is None:
        raise TokenStoreError("administrator token input has an invalid format")
    return token


def _emit(value: object) -> None:
    print(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not arguments.store.is_absolute():
        print("error: --store must be an absolute path", file=sys.stderr)
        return 2

    store = TokenStore(arguments.store)
    try:
        if arguments.command == "bootstrap":
            store.bootstrap(
                arguments.label,
                deliver=lambda issued: _emit(
                    {
                        "id": issued.record.id,
                        "label": issued.record.label,
                        "scope": issued.record.scope,
                        "token": issued.plaintext,
                    }
                ),
            )
        elif arguments.command == "create":
            store.create_token(
                _read_administrator_token(),
                label=arguments.label,
                scope=arguments.scope,
                outlets=arguments.outlets,
                deliver=lambda issued: _emit(
                    {
                        "id": issued.record.id,
                        "label": issued.record.label,
                        "scope": issued.record.scope,
                        "outlets": issued.record.outlets,
                        "token": issued.plaintext,
                    }
                ),
            )
        elif arguments.command == "list":
            records = store.list_tokens(_read_administrator_token())
            _emit({"tokens": [asdict(record) for record in records]})
        elif arguments.command in {"disable", "enable"}:
            store.set_enabled(
                _read_administrator_token(),
                arguments.id,
                arguments.command == "enable",
            )
            _emit({"id": arguments.id, "enabled": arguments.command == "enable"})
        elif arguments.command == "revoke":
            store.revoke(_read_administrator_token(), arguments.id)
            _emit({"id": arguments.id, "revoked": True})
        else:  # pragma: no cover - argparse prevents this path
            raise TokenStoreError("unsupported command")
    except IssuedTokenDurabilityError as error:
        issued = error.issued
        if not error.delivered:
            _emit(
                {
                    "durability": "uncertain",
                    "id": issued.record.id,
                    "label": issued.record.label,
                    "outlets": issued.record.outlets,
                    "scope": issued.record.scope,
                    "token": issued.plaintext,
                }
            )
        print(
            "warning: token committed, but directory durability is uncertain; "
            "preserve this credential and inspect the store before retrying",
            file=sys.stderr,
        )
        return 3
    except (TokenStoreError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
