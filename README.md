# Pobranie poczty (IMAP backup)

Skrypty do:
- sprawdzania rozmiaru skrzynki IMAP (`check_size.py`)
- pobierania maili do `.eml` (`download_mail.py`)
- opcjonalnego backupu bezposrednio na Google Drive (`download_mail.py`)

## Szybki start

```bash
python -m pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
python download_mail.py --user TWOJ_LOGIN --gdrive-folder-id ID_FOLDERU_NA_DRIVE --gdrive-only
```

Pierwsze uruchomienie Google Drive poprosi o logowanie OAuth i zapisze token do `gdrive_token.json`.
