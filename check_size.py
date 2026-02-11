from __future__ import annotations

import argparse
import base64
import getpass
import imaplib
import os
import re
from dataclasses import dataclass
from typing import Iterator

LIST_RE = re.compile(rb'\((?P<flags>.*?)\) "(?P<delimiter>.*?)" (?P<name>.+)')
SIZE_RE = re.compile(rb"RFC822\.SIZE (\d+)")
DEFAULT_SERVER = "imap.dpoczta.pl"


@dataclass
class Mailbox:
    encoded_name: str
    display_name: str


def decode_imap_utf7(value: str) -> str:
    """Decode IMAP modified UTF-7 mailbox names."""
    result: list[str] = []
    i = 0
    while i < len(value):
        if value[i] != "&":
            result.append(value[i])
            i += 1
            continue

        end = value.find("-", i)
        if end == -1:
            end = len(value)
        if end == i + 1:
            result.append("&")
            i = end + 1
            continue

        chunk = value[i + 1 : end].replace(",", "/")
        padding = "=" * (-len(chunk) % 4)
        decoded = base64.b64decode(chunk + padding)
        result.append(decoded.decode("utf-16-be", errors="replace"))
        i = end + 1

    return "".join(result)


def format_bytes(size: int) -> str:
    labels = ("B", "KB", "MB", "GB", "TB", "PB")
    value = float(size)
    idx = 0
    while value >= 1024 and idx < len(labels) - 1:
        value /= 1024
        idx += 1
    return f"{value:.2f} {labels[idx]}"


def batched(items: list[bytes], batch_size: int) -> Iterator[list[bytes]]:
    for i in range(0, len(items), batch_size):
        yield items[i : i + batch_size]


def parse_mailbox_line(line: bytes) -> Mailbox | None:
    match = LIST_RE.match(line)
    if not match:
        return None

    name = match.group("name").strip()
    if name.startswith(b'"') and name.endswith(b'"'):
        name = name[1:-1]
    name = name.replace(br"\\", b"\\").replace(br"\"", b'"')

    encoded_name = name.decode("utf-8", errors="replace")
    display_name = decode_imap_utf7(encoded_name)
    return Mailbox(encoded_name=encoded_name, display_name=display_name)


def quote_mailbox(name: str) -> str:
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def list_mailboxes(client: imaplib.IMAP4_SSL) -> list[Mailbox]:
    status, data = client.list()
    if status != "OK" or not data:
        raise RuntimeError("Nie udalo sie pobrac listy folderow.")

    mailboxes: list[Mailbox] = []
    for line in data:
        if not line:
            continue
        mailbox = parse_mailbox_line(line)
        if mailbox:
            mailboxes.append(mailbox)

    return mailboxes


def get_all_message_ids(client: imaplib.IMAP4_SSL) -> list[bytes]:
    status, data = client.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        return []
    return data[0].split()


def mailbox_size_bytes(
    client: imaplib.IMAP4_SSL,
    mailbox_name: str,
    batch_size: int,
) -> tuple[int, int]:
    status, _ = client.select(quote_mailbox(mailbox_name), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Nie udalo sie otworzyc folderu: {mailbox_name}")

    message_ids = get_all_message_ids(client)
    if not message_ids:
        return 0, 0

    folder_size = 0
    for batch in batched(message_ids, batch_size):
        ids = b",".join(batch)
        status, data = client.fetch(ids, "(RFC822.SIZE)")
        if status != "OK" or not data:
            continue

        for item in data:
            payload: bytes | None = None

            if isinstance(item, (bytes, bytearray)):
                payload = bytes(item)
            elif isinstance(item, tuple) and item:
                head = item[0]
                if isinstance(head, (bytes, bytearray)):
                    payload = bytes(head)

            if payload is None:
                continue

            match = SIZE_RE.search(payload)
            if match:
                folder_size += int(match.group(1))

    return len(message_ids), folder_size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sprawdz rozmiar calej skrzynki IMAP (np. dhosting)."
    )
    parser.add_argument(
        "--server",
        default=os.environ.get("IMAP_SERVER", DEFAULT_SERVER),
        help=f"Serwer IMAP (domyslnie: {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("IMAP_USER"),
        help="Login skrzynki (lub zmienna IMAP_USER).",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("IMAP_PASS"),
        help="Haslo skrzynki (lub zmienna IMAP_PASS).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=300,
        help="Ile maili pobierac na jedno zapytanie FETCH (domyslnie: 300).",
    )
    return parser


def resolve_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    return getpass.getpass("Haslo IMAP: ")


def run(args: argparse.Namespace) -> int:
    if not args.user:
        print("Brak loginu. Podaj --user albo ustaw IMAP_USER.")
        return 2
    if args.batch_size < 1:
        print("--batch-size musi byc >= 1")
        return 2

    password = resolve_password(args.password)
    total_bytes = 0
    total_messages = 0

    print(f"Laczenie z serwerem: {args.server}")
    client = imaplib.IMAP4_SSL(args.server)

    try:
        client.login(args.user, password)
        mailboxes = list_mailboxes(client)

        print(f"{'FOLDER':<40} {'MAILI':>10} {'ROZMIAR':>14}")
        print("-" * 68)

        for mailbox in mailboxes:
            try:
                count, size = mailbox_size_bytes(
                    client=client,
                    mailbox_name=mailbox.encoded_name,
                    batch_size=args.batch_size,
                )
            except Exception as exc:
                print(f"{mailbox.display_name:<40} {'-':>10} {'BLAD':>14} ({exc})")
                continue

            total_messages += count
            total_bytes += size
            print(f"{mailbox.display_name:<40} {count:>10} {format_bytes(size):>14}")

        print("-" * 68)
        print(f"{'SUMA':<40} {total_messages:>10} {format_bytes(total_bytes):>14}")
        return 0
    finally:
        try:
            client.logout()
        except Exception:
            pass


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except imaplib.IMAP4.error as exc:
        print(f"Blad IMAP: {exc}")
        return 1
    except Exception as exc:
        print(f"Nieoczekiwany blad: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
