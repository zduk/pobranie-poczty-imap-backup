# Pobranie poczty (IMAP backup)

Skrypty do:
- sprawdzania rozmiaru skrzynki IMAP (`check_size.py`)
- pobierania maili do `.eml` (`download_mail.py`)
- opcjonalnego backupu bezposrednio na Google Drive (`download_mail.py`)
- przegladania backupu `.eml` z Google Drive w lokalnej przegladarce (`drive_mail_browser.py`)

## Szybki start

```bash
python -m pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib Flask
python download_mail.py --user TWOJ_LOGIN --gdrive-folder-id ID_FOLDERU_NA_DRIVE --gdrive-only
```

Pierwsze uruchomienie Google Drive poprosi o logowanie OAuth i zapisze token do `gdrive_token.json`.

## Aktualizacja tylko nowych maili

`download_mail.py` domyslnie dziala przyrostowo:
- wykrywa ostatnie UID z backupu (lokalnie i/lub w Google Drive),
- pobiera tylko nowsze maile.

Przyklad:

```bash
python download_mail.py --user TWOJ_LOGIN --gdrive-folder-id ID_FOLDERU_NA_DRIVE --gdrive-only
```

Opcje:
- `--full-scan` - pelny skan wszystkich maili (wolniejsze).
- `--since-uid N` - pobieranie od UID `N` (inclusive).

## Podglad maili z Google Drive (jak lekka skrzynka)

Uruchom lokalny serwer:

```bash
python drive_mail_browser.py --gdrive-folder-id ID_FOLDERU_NA_DRIVE
```

Nastepnie otworz:

```text
http://127.0.0.1:8787
```

Co dostajesz:
- drzewo folderow z backupu,
- liste wiadomosci `.eml` w folderze,
- podglad naglowkow i tresci maila,
- pobranie oryginalnego pliku `.eml`.
