from __future__ import annotations

import argparse
import base64
import getpass
import imaplib
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

LIST_RE = re.compile(rb'\((?P<flags>.*?)\) "(?P<delimiter>.*?)" (?P<name>.+)')
MESSAGES_RE = re.compile(rb"MESSAGES\s+(\d+)")
DEFAULT_SERVER = "imap.dpoczta.pl"
INVALID_PATH_CHARS = '<>:"/\\|?*'
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"


@dataclass
class Mailbox:
    encoded_name: str
    display_name: str


@dataclass
class BackupStats:
    local_saved: int = 0
    local_skipped: int = 0
    drive_saved: int = 0
    drive_skipped: int = 0
    failed: int = 0


@dataclass
class GlobalProgress:
    total_messages: int = 0
    processed_messages: int = 0
    started_at: float = field(default_factory=time.monotonic)


class GoogleDriveUploader:
    def __init__(
        self,
        root_folder_id: str,
        client_secret_path: Path,
        token_path: Path,
    ) -> None:
        self.root_folder_id = root_folder_id
        self.client_secret_path = client_secret_path
        self.token_path = token_path
        self._service = self._build_service()
        self._folder_cache: dict[tuple[str, str], str] = {}
        self._files_cache: dict[str, dict[str, str]] = {}

    def _build_service(self):
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from googleapiclient.discovery import build
        except ImportError as exc:
            raise RuntimeError(
                "Brak bibliotek Google API. Zainstaluj: "
                "pip install google-api-python-client "
                "google-auth-httplib2 google-auth-oauthlib"
            ) from exc

        if not self.client_secret_path.exists():
            raise RuntimeError(
                f"Brak pliku OAuth klienta: {self.client_secret_path}"
            )

        creds = None
        if self.token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(
                    str(self.token_path), [DRIVE_SCOPE]
                )
            except Exception:
                creds = None

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(self.client_secret_path), [DRIVE_SCOPE]
                )
                creds = flow.run_local_server(port=0)
            self.token_path.write_text(creds.to_json(), encoding="utf-8")

        return build("drive", "v3", credentials=creds, cache_discovery=False)

    @staticmethod
    def _query_literal(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"

    def ensure_folder(self, name: str, parent_id: str) -> str:
        cache_key = (parent_id, name)
        cached = self._folder_cache.get(cache_key)
        if cached:
            return cached

        query = (
            "mimeType='application/vnd.google-apps.folder' and trashed=false and "
            f"name={self._query_literal(name)} and "
            f"{self._query_literal(parent_id)} in parents"
        )
        response = (
            self._service.files()
            .list(
                q=query,
                fields="files(id,name)",
                pageSize=1,
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
            )
            .execute()
        )
        files = response.get("files", [])
        if files:
            folder_id = files[0]["id"]
            self._folder_cache[cache_key] = folder_id
            return folder_id

        metadata = {
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [parent_id],
        }
        created = (
            self._service.files()
            .create(
                body=metadata,
                fields="id",
                supportsAllDrives=True,
            )
            .execute()
        )
        folder_id = created["id"]
        self._folder_cache[cache_key] = folder_id
        return folder_id

    def _load_folder_files(self, folder_id: str) -> dict[str, str]:
        cached = self._files_cache.get(folder_id)
        if cached is not None:
            return cached

        query = (
            "trashed=false and mimeType!='application/vnd.google-apps.folder' and "
            f"{self._query_literal(folder_id)} in parents"
        )
        files_by_name: dict[str, str] = {}
        page_token = None

        while True:
            response = (
                self._service.files()
                .list(
                    q=query,
                    fields="nextPageToken,files(id,name)",
                    pageSize=1000,
                    pageToken=page_token,
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                )
                .execute()
            )
            for file_item in response.get("files", []):
                name = file_item.get("name")
                file_id = file_item.get("id")
                if name and file_id and name not in files_by_name:
                    files_by_name[name] = file_id

            page_token = response.get("nextPageToken")
            if not page_token:
                break

        self._files_cache[folder_id] = files_by_name
        return files_by_name

    def upload_message(
        self,
        folder_id: str,
        file_name: str,
        raw_message: bytes,
        overwrite: bool,
    ) -> tuple[int, int]:
        from googleapiclient.http import MediaInMemoryUpload

        files_by_name = self._load_folder_files(folder_id)
        existing_id = files_by_name.get(file_name)

        if existing_id and not overwrite:
            return 0, 1

        media = MediaInMemoryUpload(
            raw_message,
            mimetype="message/rfc822",
            resumable=False,
        )

        if existing_id:
            (
                self._service.files()
                .update(
                    fileId=existing_id,
                    media_body=media,
                    supportsAllDrives=True,
                )
                .execute()
            )
            return 1, 0

        metadata = {"name": file_name, "parents": [folder_id]}
        created = (
            self._service.files()
            .create(
                body=metadata,
                media_body=media,
                fields="id",
                supportsAllDrives=True,
            )
            .execute()
        )
        created_id = created.get("id")
        if created_id:
            files_by_name[file_name] = created_id
        return 1, 0


def decode_imap_utf7(value: str) -> str:
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


def safe_path_name(name: str) -> str:
    cleaned = "".join("_" if ch in INVALID_PATH_CHARS else ch for ch in name)
    cleaned = cleaned.strip().strip(".")
    return cleaned or "_"


def extract_message_bytes(fetch_data: list[object]) -> bytes | None:
    for item in fetch_data:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return None


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


def get_all_uids(client: imaplib.IMAP4_SSL) -> list[bytes]:
    status, data = client.uid("search", None, "ALL")
    if status != "OK" or not data or not data[0]:
        return []
    return data[0].split()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pobierz cala poczte IMAP do lokalnych plikow .eml"
    )
    parser.add_argument(
        "--server",
        default=os.environ.get("IMAP_SERVER", DEFAULT_SERVER),
        help=f"Serwer IMAP (domyslnie: {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("IMAP_USER"),
        help="Login skrzynki (lub IMAP_USER).",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("IMAP_PASS"),
        help="Haslo skrzynki (lub IMAP_PASS).",
    )
    parser.add_argument(
        "--output",
        default="mail_backup",
        help="Katalog docelowy backupu (domyslnie: mail_backup).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Nadpisz juz pobrane pliki .eml.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=50,
        help="Co ile zapisanych maili wypisac postep (domyslnie: 50).",
    )
    parser.add_argument(
        "--gdrive-folder-id",
        default=os.environ.get("GDRIVE_FOLDER_ID"),
        help="ID folderu docelowego na Google Drive.",
    )
    parser.add_argument(
        "--gdrive-client-secret",
        default=os.environ.get("GDRIVE_CLIENT_SECRET", "gdrive_client_secret.json"),
        help=(
            "Plik credentials OAuth z Google Cloud "
            "(domyslnie: gdrive_client_secret.json)."
        ),
    )
    parser.add_argument(
        "--gdrive-token",
        default=os.environ.get("GDRIVE_TOKEN", "gdrive_token.json"),
        help="Plik z zapisanym tokenem OAuth (domyslnie: gdrive_token.json).",
    )
    parser.add_argument(
        "--gdrive-only",
        action="store_true",
        help="Wysylaj tylko na Google Drive (bez zapisu lokalnego).",
    )
    parser.add_argument(
        "--progress-log",
        default=os.environ.get("BACKUP_PROGRESS_LOG", "backup_progress.log"),
        help=(
            "Plik logu postepu (domyslnie: backup_progress.log). "
            "Podaj pusty, aby nie zapisywac."
        ),
    )
    parser.add_argument(
        "--no-progress-log",
        action="store_true",
        help="Nie zapisuj postepu do pliku.",
    )
    return parser


def resolve_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    return getpass.getpass("Haslo IMAP: ")


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    if seconds < 0:
        seconds = 0

    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, sec = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {sec:02d}s"
    if minutes:
        return f"{minutes}m {sec:02d}s"
    return f"{sec}s"


def estimate_rate_and_eta(
    done: int,
    total: int,
    started_at: float,
) -> tuple[float, float | None]:
    elapsed = max(time.monotonic() - started_at, 1e-6)
    rate = done / elapsed
    if done <= 0 or total <= 0 or rate <= 0:
        return rate, None
    remaining = max(total - done, 0)
    return rate, remaining / rate


def build_emitter(
    progress_log_path: Path | None,
) -> tuple[Callable[[str], None], Callable[[], None]]:
    handle = None
    if progress_log_path is not None:
        progress_log_path.parent.mkdir(parents=True, exist_ok=True)
        handle = progress_log_path.open("a", encoding="utf-8")

    def emit(message: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{stamp}] {message}"
        print(line)
        if handle is not None:
            handle.write(line + "\n")
            handle.flush()

    def close() -> None:
        if handle is not None:
            handle.close()

    return emit, close


def format_stats(
    stats: BackupStats,
    local_enabled: bool,
    drive_enabled: bool,
) -> str:
    parts: list[str] = []
    if local_enabled:
        parts.append(f"lokalne_zapisane={stats.local_saved}")
        parts.append(f"lokalne_pominiete={stats.local_skipped}")
    if drive_enabled:
        parts.append(f"drive_zapisane={stats.drive_saved}")
        parts.append(f"drive_pominiete={stats.drive_skipped}")
    parts.append(f"bledy={stats.failed}")
    return ", ".join(parts)


def create_drive_uploader(
    folder_id: str,
    client_secret: str,
    token_file: str,
) -> GoogleDriveUploader:
    return GoogleDriveUploader(
        root_folder_id=folder_id,
        client_secret_path=Path(client_secret).resolve(),
        token_path=Path(token_file).resolve(),
    )


def mailbox_message_count(
    client: imaplib.IMAP4_SSL,
    mailbox_name: str,
) -> int:
    status, data = client.status(quote_mailbox(mailbox_name), "(MESSAGES)")
    if status == "OK" and data:
        for item in data:
            if isinstance(item, (bytes, bytearray)):
                match = MESSAGES_RE.search(bytes(item))
                if match:
                    return int(match.group(1))

    status, _ = client.select(quote_mailbox(mailbox_name), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Nie udalo sie policzyc folderu: {mailbox_name}")
    return len(get_all_uids(client))


def format_progress_line(
    stats: BackupStats,
    local_enabled: bool,
    drive_enabled: bool,
    mailbox_name: str,
    folder_done: int,
    folder_total: int,
    folder_started_at: float,
    global_progress: GlobalProgress | None,
) -> str:
    folder_rate, folder_eta = estimate_rate_and_eta(
        done=folder_done,
        total=folder_total,
        started_at=folder_started_at,
    )
    parts = [
        f"{mailbox_name}: {folder_done}/{folder_total}",
        f"folder_eta={format_duration(folder_eta)}",
        f"folder_rate={folder_rate:.2f}/s",
        format_stats(stats, local_enabled, drive_enabled),
    ]

    if global_progress is not None and global_progress.total_messages > 0:
        global_rate, global_eta = estimate_rate_and_eta(
            done=global_progress.processed_messages,
            total=global_progress.total_messages,
            started_at=global_progress.started_at,
        )
        done = global_progress.processed_messages
        total = global_progress.total_messages
        pct = (done / total) * 100 if total else 0.0
        parts.append(f"global={done}/{total} ({pct:.1f}%)")
        parts.append(f"global_eta={format_duration(global_eta)}")
        parts.append(f"global_rate={global_rate:.2f}/s")

    return ", ".join(parts)


def download_mailbox(
    client: imaplib.IMAP4_SSL,
    mailbox: Mailbox,
    output_root: Path | None,
    drive_uploader: GoogleDriveUploader | None,
    overwrite: bool,
    progress_every: int,
    emit: Callable[[str], None],
    global_progress: GlobalProgress | None,
    estimated_count: int | None,
) -> BackupStats:
    status, _ = client.select(quote_mailbox(mailbox.encoded_name), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Nie udalo sie otworzyc folderu: {mailbox.display_name}")

    uids = get_all_uids(client)
    if not uids:
        return BackupStats()

    if global_progress is not None:
        known_count = estimated_count if estimated_count is not None else 0
        global_progress.total_messages += len(uids) - known_count

    folder_name = safe_path_name(mailbox.display_name)
    folder_path: Path | None = None
    if output_root is not None:
        folder_path = output_root / folder_name
        folder_path.mkdir(parents=True, exist_ok=True)

    drive_folder_id: str | None = None
    if drive_uploader is not None:
        drive_folder_id = drive_uploader.ensure_folder(
            name=folder_name,
            parent_id=drive_uploader.root_folder_id,
        )

    local_enabled = folder_path is not None
    drive_enabled = drive_uploader is not None
    stats = BackupStats()
    folder_started_at = time.monotonic()

    for idx, uid in enumerate(uids, start=1):
        uid_str = uid.decode("ascii", errors="ignore")

        status, data = client.uid("fetch", uid, "(RFC822)")
        if status != "OK" or not data:
            stats.failed += 1
            continue

        raw_message = extract_message_bytes(data)
        if raw_message is None:
            stats.failed += 1
            continue

        if folder_path is not None:
            try:
                target = folder_path / f"{uid_str}.eml"
                if target.exists() and not overwrite:
                    stats.local_skipped += 1
                else:
                    target.write_bytes(raw_message)
                    stats.local_saved += 1
            except Exception:
                stats.failed += 1

        if drive_uploader is not None and drive_folder_id is not None:
            try:
                drive_saved, drive_skipped = drive_uploader.upload_message(
                    folder_id=drive_folder_id,
                    file_name=f"{uid_str}.eml",
                    raw_message=raw_message,
                    overwrite=overwrite,
                )
                stats.drive_saved += drive_saved
                stats.drive_skipped += drive_skipped
            except Exception:
                stats.failed += 1

        if global_progress is not None:
            global_progress.processed_messages += 1

        if progress_every > 0 and (idx % progress_every == 0 or idx == len(uids)):
            emit(
                "  "
                + format_progress_line(
                    stats=stats,
                    local_enabled=local_enabled,
                    drive_enabled=drive_enabled,
                    mailbox_name=mailbox.display_name,
                    folder_done=idx,
                    folder_total=len(uids),
                    folder_started_at=folder_started_at,
                    global_progress=global_progress,
                )
            )

    return stats


def run(args: argparse.Namespace) -> int:
    if not args.user:
        print("Brak loginu. Podaj --user albo ustaw IMAP_USER.")
        return 2
    if args.progress_every < 0:
        print("--progress-every musi byc >= 0")
        return 2
    if args.gdrive_only and not args.gdrive_folder_id:
        print("Dla --gdrive-only podaj --gdrive-folder-id.")
        return 2

    password = resolve_password(args.password)
    drive_enabled = bool(args.gdrive_folder_id)
    local_enabled = not args.gdrive_only
    if not local_enabled and not drive_enabled:
        print("Brak miejsca docelowego backupu.")
        return 2

    progress_log_path: Path | None = None
    if not args.no_progress_log:
        raw_path = (args.progress_log or "").strip()
        if raw_path:
            progress_log_path = Path(raw_path).resolve()

    emit, close_emitter = build_emitter(progress_log_path)

    output_root: Path | None = None
    if local_enabled:
        output_root = Path(args.output).resolve()
        output_root.mkdir(parents=True, exist_ok=True)

    try:
        if progress_log_path is not None:
            emit(f"Log postepu: {progress_log_path}")

        drive_uploader: GoogleDriveUploader | None = None
        if drive_enabled:
            try:
                drive_uploader = create_drive_uploader(
                    folder_id=args.gdrive_folder_id,
                    client_secret=args.gdrive_client_secret,
                    token_file=args.gdrive_token,
                )
            except Exception as exc:
                emit(f"Blad konfiguracji Google Drive: {exc}")
                return 2

        total_stats = BackupStats()
        emit(f"Laczenie z serwerem: {args.server}")
        client = imaplib.IMAP4_SSL(args.server)

        try:
            client.login(args.user, password)
            mailboxes = list_mailboxes(client)

            if local_enabled and output_root is not None:
                emit(f"Backup lokalny do: {output_root}")
            if drive_enabled and args.gdrive_folder_id:
                emit(
                    "Backup na Google Drive do folderu ID: "
                    f"{args.gdrive_folder_id}"
                )

            emit(f"Liczenie maili do ETA ({len(mailboxes)} folderow)...")
            estimated_total = 0
            mailbox_counts: dict[str, int | None] = {}
            for idx, mailbox in enumerate(mailboxes, start=1):
                try:
                    count = mailbox_message_count(client, mailbox.encoded_name)
                    mailbox_counts[mailbox.encoded_name] = count
                    estimated_total += count
                except Exception as exc:
                    mailbox_counts[mailbox.encoded_name] = None
                    emit(
                        "  UWAGA: pomijam ETA dla folderu "
                        f"{mailbox.display_name} ({exc})"
                    )

                if idx % 10 == 0 or idx == len(mailboxes):
                    emit(
                        "  Liczenie ETA: "
                        f"{idx}/{len(mailboxes)} folderow, maile={estimated_total}"
                    )

            global_progress = GlobalProgress(total_messages=estimated_total)
            emit(f"Start transferu. Szacowana liczba maili: {estimated_total}")

            for mailbox in mailboxes:
                estimated_count = mailbox_counts.get(mailbox.encoded_name)
                if estimated_count is None:
                    emit(f"Folder: {mailbox.display_name} (liczba maili: nieznana)")
                else:
                    emit(
                        f"Folder: {mailbox.display_name} "
                        f"(liczba maili: {estimated_count})"
                    )

                try:
                    stats = download_mailbox(
                        client=client,
                        mailbox=mailbox,
                        output_root=output_root,
                        drive_uploader=drive_uploader,
                        overwrite=args.overwrite,
                        progress_every=args.progress_every,
                        emit=emit,
                        global_progress=global_progress,
                        estimated_count=estimated_count,
                    )
                except Exception as exc:
                    emit(f"  BLAD: {exc}")
                    total_stats.failed += 1
                    continue

                total_stats.local_saved += stats.local_saved
                total_stats.local_skipped += stats.local_skipped
                total_stats.drive_saved += stats.drive_saved
                total_stats.drive_skipped += stats.drive_skipped
                total_stats.failed += stats.failed
                emit(f"  OK: {format_stats(stats, local_enabled, drive_enabled)}")

            elapsed = time.monotonic() - global_progress.started_at
            emit("-" * 60)
            emit(f"KONIEC: {format_stats(total_stats, local_enabled, drive_enabled)}")
            emit(f"Czas transferu: {format_duration(elapsed)}")
            return 0
        finally:
            try:
                client.logout()
            except Exception:
                pass
    finally:
        close_emitter()


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
