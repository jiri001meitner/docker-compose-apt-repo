"""repo-admin: manage accounts and tokens, publish the export for repo-auth.

The SQLite database is the source of truth. After every change the export
(``clients.json``) is rewritten atomically; the auth service only reads it.
Tokens are shown exactly once (``token add``) and stored only as SHA-256.

Exit codes: 0 ok, 1 usage or validation error, 2 not found.
Commands meant for automation print ``OK`` or ``CHANGED`` on the last line.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from repo_common.timeutil import format_utc

from .accounts import (
    AccountChanges,
    AccountSpec,
    Admin,
    AdminError,
    canonical_scopes,
    parse_valid_until,
)

DEFAULT_DB = "/data/db/repo.sqlite3"
DEFAULT_EXPORT = "/data/export/clients.json"
ACCOUNT_COLUMNS = ["id", "name", "email", "scopes", "valid_until", "blocked", "note"]
TOKEN_COLUMNS = ["login", "account_id", "label", "created", "revoked"]


@dataclass(slots=True)
class Outcome:
    """What a command reports once the export is written.

    ``secret`` (a new token) is printed only after the export is in place, so
    a token is never shown for a change that did not take effect. ``changed``
    becomes the ``OK``/``CHANGED`` line of automation commands.
    """

    changed: bool | None = None
    secret: str | None = None
    output: str | None = None


type Command = Callable[[Admin, argparse.Namespace], Outcome]
# `add_parser` of a subparsers object (its class is private to argparse).
type AddParser = Callable[..., argparse.ArgumentParser]


def _rows(rows: list[sqlite3.Row], columns: list[str]) -> str:
    lines = ["\t".join(columns)]
    lines += ["\t".join("" if row[c] is None else str(row[c]) for c in columns) for row in rows]
    return "\n".join(lines)


def _spec(args: argparse.Namespace) -> AccountSpec:
    return AccountSpec(
        name=args.name,
        scopes=canonical_scopes(args.scope),
        valid_until=None if args.unlimited else parse_valid_until(args.valid_until),
        email=getattr(args, "email", None),
        note=getattr(args, "note", None),
    )


def _account_add(admin: Admin, args: argparse.Namespace) -> Outcome:
    admin.account_add(args.id, _spec(args))
    return Outcome()


def _account_ensure(admin: Admin, args: argparse.Namespace) -> Outcome:
    return Outcome(changed=admin.account_ensure(args.id, _spec(args)))


def _account_set(admin: Admin, args: argparse.Namespace) -> Outcome:
    changes = AccountChanges(
        name=args.name,
        email=args.email,
        scopes=canonical_scopes(args.scope) if args.scope is not None else None,
        valid_until=parse_valid_until(args.valid_until) if args.valid_until else None,
        unlimited=args.unlimited,
        note=args.note,
    )
    admin.account_set(args.id, changes)
    return Outcome()


def _account_extend(admin: Admin, args: argparse.Namespace) -> Outcome:
    return Outcome(output=format_utc(admin.account_extend(args.id, args.days)))


def _account_block(admin: Admin, args: argparse.Namespace) -> Outcome:
    admin.account_block(args.id, args.cmd == "block")
    return Outcome()


def _account_delete(admin: Admin, args: argparse.Namespace) -> Outcome:
    admin.account_delete(args.id)
    return Outcome()


def _account_list(admin: Admin, _args: argparse.Namespace) -> Outcome:
    return Outcome(output=_rows(admin.accounts(), ACCOUNT_COLUMNS))


def _token_add(admin: Admin, args: argparse.Namespace) -> Outcome:
    token = admin.token_add(args.account, args.login, args.label)
    return Outcome(secret=f"{args.login} {token}")


def _token_rotate(admin: Admin, args: argparse.Namespace) -> Outcome:
    return Outcome(secret=f"{args.login} {admin.token_rotate(args.login)}")


def _token_revoke(admin: Admin, args: argparse.Namespace) -> Outcome:
    admin.token_revoke(args.login)
    return Outcome()


def read_wanted_tokens(text: str) -> dict[str, str]:
    """Parse ``{login: token}`` from the stdin of ``token sync``."""
    try:
        wanted = json.loads(text)
    except ValueError as exc:
        raise AdminError(f"stdin is not JSON: {exc}") from exc
    if not isinstance(wanted, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in wanted.items()
    ):
        raise AdminError("stdin must be a JSON object {login: token}")
    return wanted


def _token_sync(admin: Admin, args: argparse.Namespace) -> Outcome:
    wanted = read_wanted_tokens(sys.stdin.read())
    return Outcome(changed=admin.token_sync(args.account, wanted))


def _token_list(admin: Admin, args: argparse.Namespace) -> Outcome:
    return Outcome(output=_rows(admin.tokens(args.account), TOKEN_COLUMNS))


def _export(_admin: Admin, _args: argparse.Namespace) -> Outcome:
    # The export is written after every command; `run` reports its result.
    return Outcome()


COMMANDS: dict[tuple[str, str | None], Command] = {
    ("account", "add"): _account_add,
    ("account", "ensure"): _account_ensure,
    ("account", "set"): _account_set,
    ("account", "extend"): _account_extend,
    ("account", "block"): _account_block,
    ("account", "unblock"): _account_block,
    ("account", "delete"): _account_delete,
    ("account", "list"): _account_list,
    ("token", "add"): _token_add,
    ("token", "rotate"): _token_rotate,
    ("token", "revoke"): _token_revoke,
    ("token", "sync"): _token_sync,
    ("token", "list"): _token_list,
    ("export", None): _export,
}


def _end_options(parser: argparse.ArgumentParser, *, required: bool) -> None:
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument("--valid-until", help="YYYY-MM-DD (end of that day, UTC) or ISO 8601")
    group.add_argument("--unlimited", action="store_true")


def _account_parsers(add_parser: AddParser) -> None:
    acc = add_parser("account").add_subparsers(dest="cmd", required=True)
    for name, help_text in (("add", None), ("ensure", "create or update; prints OK/CHANGED")):
        a = acc.add_parser(name, help=help_text)
        a.add_argument("id")
        a.add_argument("--name", required=True)
        a.add_argument("--scope", action="append", default=[])
        if name == "add":
            a.add_argument("--email")
            a.add_argument("--note")
        _end_options(a, required=True)
    a = acc.add_parser("set")
    a.add_argument("id")
    a.add_argument("--name")
    a.add_argument("--email")
    a.add_argument("--scope", action="append")
    a.add_argument("--note")
    _end_options(a, required=False)
    a = acc.add_parser("extend")
    a.add_argument("id")
    a.add_argument("--days", type=int, required=True)
    for name in ("block", "unblock", "delete"):
        acc.add_parser(name).add_argument("id")
    acc.add_parser("list")


def _token_parsers(add_parser: AddParser) -> None:
    tok = add_parser("token").add_subparsers(dest="cmd", required=True)
    t = tok.add_parser("add", help="new token, printed once")
    t.add_argument("account")
    t.add_argument("--login", required=True)
    t.add_argument("--label")
    tok.add_parser("rotate", help="new token for a login, printed once").add_argument("login")
    tok.add_parser("revoke").add_argument("login")
    sync = tok.add_parser("sync", help="set managed tokens from JSON {login: token} on stdin")
    sync.add_argument("account")
    tok.add_parser("list").add_argument("account", nargs="?")


def build_parser() -> argparse.ArgumentParser:
    """Command line of repo-admin."""
    p = argparse.ArgumentParser(
        prog="repo-admin", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--db", default=os.environ.get("REPO_ADMIN_DB", DEFAULT_DB))
    p.add_argument("--export", default=os.environ.get("REPO_AUTH_EXPORT", DEFAULT_EXPORT))
    sub = p.add_subparsers(dest="area", required=True)
    _account_parsers(sub.add_parser)
    _token_parsers(sub.add_parser)
    sub.add_parser("export", help="rewrite the export now; prints OK/CHANGED")
    return p


def _print(outcome: Outcome) -> None:
    if outcome.secret is not None:
        print(outcome.secret)
    if outcome.changed is not None:
        print("CHANGED" if outcome.changed else "OK")


def run(argv: Sequence[str] | None = None) -> int:
    """Run one command; returns the exit code."""
    args = build_parser().parse_args(argv)
    command = COMMANDS[(args.area, getattr(args, "cmd", None))]
    admin = Admin(args.db, args.export)
    try:
        outcome = command(admin, args)
        if outcome.output is not None:
            print(outcome.output)  # e.g. the new end date, already committed
        export_changed = admin.write_export()
    except AdminError as exc:
        print(f"repo-admin: {exc}", file=sys.stderr)
        return exc.exit_code
    finally:
        admin.close()
    if command is _export:
        outcome.changed = export_changed
    _print(outcome)
    return 0


def main() -> None:
    """Entry point of the ``repo-admin`` command."""
    raise SystemExit(run())


if __name__ == "__main__":
    main()
