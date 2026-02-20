from __future__ import annotations

import argparse
import io
import os
import re
from collections import deque
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template_string, request

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
UID_FILE_RE = re.compile(r"^(?P<uid>\d+)\.eml$")


INDEX_HTML = """<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Drive Mail Browser</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --panel: #ffffff;
      --line: #d9dee4;
      --text: #1f2933;
      --muted: #66788a;
      --accent: #0b6e4f;
      --accent-soft: #d7efe7;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      color: var(--text);
      background: linear-gradient(180deg, #f9fbfc 0%, #eef2f6 100%);
      height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr;
    }
    header {
      padding: 10px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    header h1 {
      font-size: 16px;
      margin: 0;
      font-weight: 700;
    }
    .muted { color: var(--muted); font-size: 12px; }
    main {
      min-height: 0;
      display: grid;
      grid-template-columns: 280px 360px 1fr;
      gap: 10px;
      padding: 10px;
    }
    .panel {
      min-height: 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
      display: grid;
      grid-template-rows: auto 1fr auto;
    }
    .panel h2 {
      margin: 0;
      font-size: 13px;
      padding: 10px;
      border-bottom: 1px solid var(--line);
      letter-spacing: 0.2px;
    }
    .scroll {
      overflow: auto;
      min-height: 0;
    }
    .folder-btn {
      width: 100%;
      text-align: left;
      border: 0;
      background: transparent;
      padding: 8px 10px;
      border-bottom: 1px solid #eff2f5;
      cursor: pointer;
      font-size: 13px;
      color: var(--text);
    }
    .folder-btn:hover { background: #f5f8fb; }
    .folder-btn.active { background: var(--accent-soft); color: #084c38; font-weight: 600; }
    .msg-row {
      border-bottom: 1px solid #eff2f5;
      padding: 8px 10px;
      cursor: pointer;
    }
    .msg-row:hover { background: #f5f8fb; }
    .msg-row.active { background: #e9f6ff; }
    .msg-subject {
      font-weight: 600;
      font-size: 13px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .msg-meta {
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .toolbar {
      padding: 8px 10px;
      border-top: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 8px;
    }
    button.small {
      border: 1px solid var(--line);
      background: #fff;
      padding: 6px 8px;
      border-radius: 7px;
      cursor: pointer;
      font-size: 12px;
    }
    button.small:hover { background: #f4f7f9; }
    .viewer {
      min-height: 0;
      overflow: auto;
      padding: 14px;
      font-size: 14px;
      line-height: 1.45;
    }
    .viewer h3 {
      margin: 0 0 8px 0;
      font-size: 18px;
      line-height: 1.2;
    }
    .viewer .mail-meta {
      margin: 4px 0;
      color: #334e68;
      font-size: 13px;
    }
    .viewer pre {
      margin: 10px 0 0 0;
      background: #f4f7fa;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
    }
    iframe.mail-html {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      min-height: 420px;
      background: white;
    }
    .status {
      padding: 8px 10px;
      color: var(--muted);
      font-size: 12px;
      border-top: 1px solid var(--line);
    }
    @media (max-width: 1100px) {
      main { grid-template-columns: 240px 320px 1fr; }
    }
    @media (max-width: 900px) {
      main {
        grid-template-columns: 1fr;
        grid-template-rows: 240px 320px 1fr;
      }
    }
  </style>
</head>
<body>
  <header>
    <h1>Drive Mail Browser</h1>
    <div class="muted" id="headerInfo">Ladowanie...</div>
  </header>
  <main>
    <section class="panel">
      <h2>Foldery</h2>
      <div class="scroll" id="folderList"></div>
      <div class="status" id="folderStatus">...</div>
    </section>
    <section class="panel">
      <h2>Wiadomosci</h2>
      <div class="scroll" id="messageList"></div>
      <div class="toolbar">
        <button class="small" id="prevBtn">Poprzednia</button>
        <div class="muted" id="pageInfo">Strona 1</div>
        <button class="small" id="nextBtn">Nastepna</button>
      </div>
      <div class="status" id="messageStatus">...</div>
    </section>
    <section class="panel">
      <h2>Podglad</h2>
      <div class="viewer" id="viewer">
        Wybierz folder i wiadomosc.
      </div>
      <div class="status" id="viewerStatus">...</div>
    </section>
  </main>
  <script>
    const state = {
      rootId: null,
      selectedFolderId: null,
      selectedFolderPath: "",
      selectedFileId: null,
      page: 1,
      pageSize: 50,
      totalMessages: 0,
    };

    const folderList = document.getElementById("folderList");
    const messageList = document.getElementById("messageList");
    const viewer = document.getElementById("viewer");
    const folderStatus = document.getElementById("folderStatus");
    const messageStatus = document.getElementById("messageStatus");
    const viewerStatus = document.getElementById("viewerStatus");
    const pageInfo = document.getElementById("pageInfo");
    const headerInfo = document.getElementById("headerInfo");
    const prevBtn = document.getElementById("prevBtn");
    const nextBtn = document.getElementById("nextBtn");

    function esc(v) {
      return (v ?? "").replace(/[&<>"']/g, (m) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;" }[m]));
    }

    function fmtBytes(size) {
      const n = Number(size || 0);
      if (!n) return "0 B";
      const units = ["B", "KB", "MB", "GB"];
      let idx = 0;
      let val = n;
      while (val >= 1024 && idx < units.length - 1) {
        val /= 1024;
        idx += 1;
      }
      return `${val.toFixed(val >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
    }

    async function loadFolders() {
      folderStatus.textContent = "Ladowanie folderow...";
      const res = await fetch("/api/folders");
      const data = await res.json();
      state.rootId = data.root_id;
      headerInfo.textContent = `Root Drive: ${data.root_name} (${data.items.length} folderow)`;
      folderList.innerHTML = "";
      data.items.forEach((item) => {
        const btn = document.createElement("button");
        btn.className = "folder-btn";
        btn.textContent = item.path;
        btn.dataset.id = item.id;
        btn.addEventListener("click", () => selectFolder(item.id, item.path));
        folderList.appendChild(btn);
      });
      folderStatus.textContent = `Foldery: ${data.items.length}`;
      const rootItem = data.items.find((x) => x.id === state.rootId) || data.items[0];
      if (rootItem) selectFolder(rootItem.id, rootItem.path);
    }

    function updateFolderSelection() {
      [...folderList.querySelectorAll(".folder-btn")].forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.id === state.selectedFolderId);
      });
    }

    function updateMessageSelection() {
      [...messageList.querySelectorAll(".msg-row")].forEach((row) => {
        row.classList.toggle("active", row.dataset.id === state.selectedFileId);
      });
    }

    async function selectFolder(folderId, folderPath) {
      state.selectedFolderId = folderId;
      state.selectedFolderPath = folderPath;
      state.page = 1;
      state.selectedFileId = null;
      updateFolderSelection();
      viewer.innerHTML = "Wybierz wiadomosc.";
      viewerStatus.textContent = `Folder: ${folderPath}`;
      await loadMessages();
    }

    async function loadMessages() {
      if (!state.selectedFolderId) return;
      messageStatus.textContent = "Ladowanie wiadomosci...";
      const url = `/api/messages?folder_id=${encodeURIComponent(state.selectedFolderId)}&page=${state.page}&page_size=${state.pageSize}`;
      const res = await fetch(url);
      const data = await res.json();
      state.totalMessages = data.total;
      messageList.innerHTML = "";
      if (!data.items.length) {
        messageList.innerHTML = '<div class="msg-row">Brak wiadomosci w tym folderze.</div>';
      } else {
        data.items.forEach((item) => {
          const row = document.createElement("div");
          row.className = "msg-row";
          row.dataset.id = item.id;
          row.innerHTML = `
            <div class="msg-subject">${esc(item.name)}</div>
            <div class="msg-meta">Zmieniono: ${esc(item.modified_time || "-")} | Rozmiar: ${esc(fmtBytes(item.size))}</div>
          `;
          row.addEventListener("click", () => openMessage(item.id, item.name));
          messageList.appendChild(row);
        });
      }
      const from = data.total ? ((state.page - 1) * state.pageSize + 1) : 0;
      const to = Math.min(state.page * state.pageSize, data.total);
      pageInfo.textContent = `Strona ${state.page} (${from}-${to} / ${data.total})`;
      messageStatus.textContent = `Folder: ${state.selectedFolderPath}`;
      prevBtn.disabled = state.page <= 1;
      nextBtn.disabled = to >= data.total;
      updateMessageSelection();
    }

    async function openMessage(fileId, fileName) {
      state.selectedFileId = fileId;
      updateMessageSelection();
      viewerStatus.textContent = `Ladowanie ${fileName}...`;
      const res = await fetch(`/api/message/${encodeURIComponent(fileId)}`);
      const data = await res.json();
      if (data.error) {
        viewer.innerHTML = `<pre>${esc(data.error)}</pre>`;
        viewerStatus.textContent = "Blad";
        return;
      }

      const htmlPart = data.body_html
        ? `<iframe class="mail-html" sandbox="" srcdoc="${esc(data.body_html)}"></iframe>`
        : "";
      const textPart = data.body_text
        ? `<pre>${esc(data.body_text)}</pre>`
        : "<div class='muted'>Brak tekstowej tresci.</div>";

      viewer.innerHTML = `
        <h3>${esc(data.subject || "(brak tematu)")}</h3>
        <div class="mail-meta"><strong>Od:</strong> ${esc(data.from)}</div>
        <div class="mail-meta"><strong>Do:</strong> ${esc(data.to)}</div>
        <div class="mail-meta"><strong>Data:</strong> ${esc(data.date)}</div>
        <div class="mail-meta"><strong>Plik:</strong> ${esc(data.file_name)} (${esc(fmtBytes(data.size))})</div>
        <div class="mail-meta">
          <a href="/api/message/${encodeURIComponent(fileId)}/raw" target="_blank" rel="noopener">Pobierz oryginalny .eml</a>
        </div>
        ${htmlPart}
        ${textPart}
      `;
      viewerStatus.textContent = `Otwarte: ${fileName}`;
    }

    prevBtn.addEventListener("click", async () => {
      if (state.page <= 1) return;
      state.page -= 1;
      await loadMessages();
    });

    nextBtn.addEventListener("click", async () => {
      const maxPage = Math.ceil(state.totalMessages / state.pageSize);
      if (state.page >= maxPage) return;
      state.page += 1;
      await loadMessages();
    });

    loadFolders().catch((err) => {
      headerInfo.textContent = "Blad ladowania";
      folderStatus.textContent = String(err);
      messageStatus.textContent = String(err);
      viewerStatus.textContent = String(err);
    });
  </script>
</body>
</html>
"""


def decode_mime_header(raw_value: str | None) -> str:
    if not raw_value:
        return ""
    try:
        return str(make_header(decode_header(raw_value)))
    except Exception:
        return raw_value


def uid_from_eml_file_name(file_name: str) -> int | None:
    match = UID_FILE_RE.match(file_name)
    if not match:
        return None
    return int(match.group("uid"))


def extract_message_bodies(message) -> tuple[str, str]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            continue

        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            payload = part.get_content()
        except Exception:
            continue

        if not isinstance(payload, str):
            continue
        if content_type == "text/plain":
            plain_parts.append(payload)
        else:
            html_parts.append(payload)

    return "\n\n".join(plain_parts).strip(), "\n<hr>\n".join(html_parts).strip()


class GoogleDriveMailReader:
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
        self._root_name = self._get_folder_name(root_folder_id)

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
            raise RuntimeError(f"Brak pliku OAuth klienta: {self.client_secret_path}")

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

    def _get_folder_name(self, folder_id: str) -> str:
        metadata = (
            self._service.files()
            .get(
                fileId=folder_id,
                fields="id,name",
                supportsAllDrives=True,
            )
            .execute()
        )
        return metadata.get("name") or folder_id

    def _list_subfolders(self, parent_id: str) -> list[dict[str, str]]:
        query = (
            "mimeType='application/vnd.google-apps.folder' and trashed=false and "
            f"{self._query_literal(parent_id)} in parents"
        )
        result: list[dict[str, str]] = []
        page_token = None
        while True:
            response = (
                self._service.files()
                .list(
                    q=query,
                    fields="nextPageToken,files(id,name,parents)",
                    pageSize=1000,
                    pageToken=page_token,
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                )
                .execute()
            )
            for item in response.get("files", []):
                folder_id = item.get("id")
                folder_name = item.get("name")
                if folder_id and folder_name:
                    result.append({"id": folder_id, "name": folder_name})
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        return result

    def list_folder_tree(self) -> list[dict[str, str | None]]:
        items: list[dict[str, str | None]] = [
            {
                "id": self.root_folder_id,
                "name": self._root_name,
                "path": self._root_name,
                "parent_id": None,
            }
        ]

        queue: deque[tuple[str, str]] = deque([(self.root_folder_id, self._root_name)])
        while queue:
            parent_id, parent_path = queue.popleft()
            children = self._list_subfolders(parent_id)
            children.sort(key=lambda item: item["name"].lower())
            for child in children:
                child_path = f"{parent_path}/{child['name']}"
                items.append(
                    {
                        "id": child["id"],
                        "name": child["name"],
                        "path": child_path,
                        "parent_id": parent_id,
                    }
                )
                queue.append((child["id"], child_path))

        return items

    def list_messages(
        self,
        folder_id: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        query = (
            "trashed=false and mimeType!='application/vnd.google-apps.folder' and "
            f"{self._query_literal(folder_id)} in parents"
        )
        files: list[dict[str, Any]] = []
        page_token = None

        while True:
            response = (
                self._service.files()
                .list(
                    q=query,
                    fields="nextPageToken,files(id,name,size,modifiedTime)",
                    pageSize=1000,
                    pageToken=page_token,
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                )
                .execute()
            )
            for item in response.get("files", []):
                name = item.get("name") or ""
                if not name.lower().endswith(".eml"):
                    continue
                files.append(item)
            page_token = response.get("nextPageToken")
            if not page_token:
                break

        def sort_key(item: dict[str, Any]) -> tuple[int, int | str]:
            name = item.get("name") or ""
            uid = uid_from_eml_file_name(name)
            if uid is not None:
                return (1, uid)
            return (0, name.lower())

        files.sort(key=sort_key, reverse=True)

        total = len(files)
        start = max((page - 1) * page_size, 0)
        end = start + page_size
        page_items = files[start:end]

        items: list[dict[str, Any]] = []
        for item in page_items:
            items.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "size": int(item.get("size") or 0),
                    "modified_time": item.get("modifiedTime"),
                }
            )

        return {"total": total, "items": items}

    def download_file_bytes(self, file_id: str) -> bytes:
        from googleapiclient.http import MediaIoBaseDownload

        request_obj = self._service.files().get_media(
            fileId=file_id,
            supportsAllDrives=True,
        )
        buffer = io.BytesIO()
        downloader = MediaIoBaseDownload(buffer, request_obj)

        done = False
        while not done:
            _, done = downloader.next_chunk()

        return buffer.getvalue()

    def get_message_details(self, file_id: str) -> dict[str, Any]:
        metadata = (
            self._service.files()
            .get(
                fileId=file_id,
                fields="id,name,size,modifiedTime",
                supportsAllDrives=True,
            )
            .execute()
        )

        raw_bytes = self.download_file_bytes(file_id)
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        body_text, body_html = extract_message_bodies(message)

        return {
            "id": metadata.get("id"),
            "file_name": metadata.get("name") or file_id,
            "size": int(metadata.get("size") or len(raw_bytes)),
            "modified_time": metadata.get("modifiedTime"),
            "subject": decode_mime_header(message.get("Subject")),
            "from": decode_mime_header(message.get("From")),
            "to": decode_mime_header(message.get("To")),
            "date": decode_mime_header(message.get("Date")),
            "body_text": body_text,
            "body_html": body_html,
        }

    @property
    def root_name(self) -> str:
        return self._root_name


def build_app(reader: GoogleDriveMailReader) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return render_template_string(INDEX_HTML)

    @app.get("/api/folders")
    def api_folders():
        items = reader.list_folder_tree()
        return jsonify(
            {
                "root_id": reader.root_folder_id,
                "root_name": reader.root_name,
                "items": items,
            }
        )

    @app.get("/api/messages")
    def api_messages():
        folder_id = request.args.get("folder_id") or reader.root_folder_id
        try:
            page = int(request.args.get("page", "1"))
        except ValueError:
            page = 1
        try:
            page_size = int(request.args.get("page_size", "50"))
        except ValueError:
            page_size = 50

        page = max(page, 1)
        page_size = min(max(page_size, 1), 200)
        return jsonify(reader.list_messages(folder_id, page, page_size))

    @app.get("/api/message/<file_id>")
    def api_message(file_id: str):
        try:
            return jsonify(reader.get_message_details(file_id))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/message/<file_id>/raw")
    def api_message_raw(file_id: str):
        metadata = (
            reader._service.files()
            .get(
                fileId=file_id,
                fields="id,name",
                supportsAllDrives=True,
            )
            .execute()
        )
        file_name = metadata.get("name") or f"{file_id}.eml"
        raw_bytes = reader.download_file_bytes(file_id)
        return Response(
            raw_bytes,
            mimetype="message/rfc822",
            headers={
                "Content-Disposition": f'attachment; filename="{file_name}"',
            },
        )

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Lokalny podglad maili .eml zapisanych w Google Drive "
            "(folder backupu IMAP)."
        )
    )
    parser.add_argument(
        "--gdrive-folder-id",
        default=os.environ.get("GDRIVE_FOLDER_ID"),
        help="ID folderu root z backupem maili na Google Drive.",
    )
    parser.add_argument(
        "--gdrive-client-secret",
        default=os.environ.get("GDRIVE_CLIENT_SECRET", "gdrive_client_secret.json"),
        help="Plik credentials OAuth z Google Cloud.",
    )
    parser.add_argument(
        "--gdrive-token",
        default=os.environ.get("GDRIVE_TOKEN", "gdrive_token.json"),
        help="Plik z tokenem OAuth dla Google Drive.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host serwera HTTP (domyslnie: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="Port serwera HTTP (domyslnie: 8787).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.gdrive_folder_id:
        print("Podaj --gdrive-folder-id albo ustaw GDRIVE_FOLDER_ID.")
        return 2
    if args.port < 1 or args.port > 65535:
        print("--port musi byc w zakresie 1..65535.")
        return 2

    reader = GoogleDriveMailReader(
        root_folder_id=args.gdrive_folder_id,
        client_secret_path=Path(args.gdrive_client_secret).resolve(),
        token_path=Path(args.gdrive_token).resolve(),
    )
    app = build_app(reader)
    print(f"Uruchamiam podglad: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
