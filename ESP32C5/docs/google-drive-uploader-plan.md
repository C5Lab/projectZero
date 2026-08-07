# Google Drive uploader — implementation handoff

**Status: planned only. No Google Drive uploader code has been added yet.**

This document records the agreed scope and the remaining implementation work for the ESP-IDF Google Drive uploader.

## Agreed scope

- Target: ESP32-C5 firmware running on ESP-IDF 6.x.
- Transport: native `esp_http_client` only, with `esp_crt_bundle_attach` enabled for every Google HTTPS request.
- Storage: files are read from the mounted SD card at `/sdcard` and must be streamed. Never load an entire upload into RAM.
- Upload method: Google Drive API v3 resumable uploads.
- Upload buffer: read the SD card in small blocks (default 8 KiB); upload chunks are 256 KiB, except for the final chunk.
- Security: never log OAuth secrets, access tokens, refresh tokens, or resumable session URLs.
- Supported batch source: **only direct files in `/sdcard/lab/wardrives`**.
- Batch filter: **only final `*.kml` files**. Do not recurse into subdirectories and do not touch archives such as `wardrives/uploaded/`. Ignore hidden files and `*.inprogress.kml` files.
- Both single-file upload and batch upload are required.

## Credentials and OAuth provisioning

Two provisioning paths must be supported.

### 1. On-device OAuth Device Authorization Flow

The firmware must provide an OAuth Device Flow command. It requests a device code from Google, prints the verification URL and the case-sensitive user code, then polls until the user approves the request on a phone or computer.

The Google Cloud OAuth client must use the **TVs and Limited Input devices** application type. Request the scope:

```text
https://www.googleapis.com/auth/drive.file
```

On success, persist the client configuration and refresh token in NVS. Keep the short-lived access token in RAM only.

### 2. Manual JSON bootstrap/import

A user may instead prepare this confidential file on the SD card:

```text
/sdcard/lab/google_drive.json
```

Expected fields:

```json
{
  "client_id": "123456789.apps.googleusercontent.com",
  "client_secret": "GOCSPX-xxxxxxxx",
  "refresh_token": "1//xxxxxxxxxxxxxxxx",
  "folder_id": "1AbCdEfGhIjKlMnOp",
  "scope": "https://www.googleapis.com/auth/drive.file"
}
```

The firmware must validate and import this configuration into NVS. After a successful import, the JSON file remains confidential. The documentation must recommend removing it from the SD card unless the user explicitly wants to keep it as an offline backup.

The final component README must contain an English, click-by-click guide explaining how to:

1. Create a Google Cloud project.
2. Enable the Google Drive API.
3. Configure the OAuth consent screen and production/testing status.
4. Create the correct OAuth client.
5. Obtain a refresh token for the `drive.file` scope.
6. Create `google_drive.json` without printing secrets to the terminal.
7. Copy the file to `/sdcard/lab/google_drive.json`.
8. Use the Device Flow alternative.

## Proposed CLI

Exact parser details can be finalized during implementation, but the intended commands are:

```text
gdrive_auth start
gdrive_auth status
gdrive_auth import
gdrive_auth forget

gdrive_upload <file> [remote_name]
gdrive_upload [file ... | all]
gdrive_resume
gdrive_status
gdrive_cancel
```

Rules:

- `gdrive_upload <file> [remote_name]` uploads one explicit regular file under `/sdcard/`.
- `gdrive_upload` without file arguments scans only `/sdcard/lab/wardrives` and uploads pending final KML files.
- `gdrive_upload all` reprocesses all eligible final KML files in that same directory.
- At most one active resumable upload exists at any time.
- `gdrive_cancel` keeps resumable state so `gdrive_resume` can continue later.

## State and batch tracking

Use two independent persistent states.

1. `/sdcard/lab/.gdrive_upload_state.json` tracks the one currently active resumable upload. It stores the local path, remote name, folder ID, file identity, resumable session URL, total size, and the server-confirmed byte offset. Save it only after Google confirms progress.
2. The existing wardrive completion manifest (`/sdcard/lab/wardrives/upload_state.csv`) should gain a `gdrive` service entry for final batch results. This lets the no-argument batch skip completed KML files just as the WiGLE and WDGWars uploaders do.

The active-upload state must identify a file beyond size alone (for example size plus modification time and/or a streaming hash). This prevents resuming an upload against a different local file with the same size.

State writes must be crash-safe. The original `tmp -> remove old -> rename` concept has a power-loss window; prefer a small two-slot journal with generation number and CRC, or another scheme that never silently loses the only recoverable state.

## Upload state machine

```text
load/import configuration
        -> obtain or refresh access token
        -> create resumable session
        -> persist active state
        -> query session status
        -> seek to confirmed offset
        -> stream one 256 KiB chunk as 8 KiB writes
        -> process 308 Range response
        -> persist confirmed offset
        -> repeat
        -> process 200/201 result
        -> delete active state and mark batch result done
```

Important rules:

- Use `esp_http_client_open(client, chunk_length)` and repeatedly call `fread()` plus `esp_http_client_write()` until every 8 KiB buffer has been fully written.
- A successful local write does not confirm remote progress. Only `308 Resume Incomplete` and its `Range` header determine the next offset.
- After timeout, connection loss, 5xx, or a `401`, refresh credentials as appropriate, then query the resumable session before sending more data. Do not blindly resend a chunk.
- A `404` for the session means create a new session and restart from byte zero.
- Retry `429`, temporary 5xx, and transient network failures with bounded exponential backoff and jitter.
- Parse 403 error reasons: rate limits are retryable; permission, folder, and quota errors are not.
- Treat OAuth `invalid_grant` as a durable error and require new authorization.

## Component layout

Create a dedicated component rather than extending the large uploader blocks in `main/main.c`:

```text
components/google_drive_uploader/
├── CMakeLists.txt
├── idf_component.yml
├── include/google_drive_uploader.h
├── google_drive_uploader.c
├── google_drive_auth.c
├── google_drive_http.c
├── google_drive_upload.c
├── google_drive_state.c
└── README.md
```

The component needs a singleton context, a mutex, cancellation state, bounded response buffers, and cleanup for every file and HTTP client handle. The public API should remain independent of console commands; `main/main.c` should only register the commands and adapt progress logs/OLED output.

Use this repository's component names and configuration rather than blindly copying the original prompt's CMake example. In particular, use the installed `espressif__cjson` dependency and preserve certificate-bundle verification.

## Tests and verification still required

- JSON configuration parsing and required-field validation.
- URL-form encoding.
- OAuth and Device Flow response parsing.
- Content-Range construction and Range parsing.
- File identity validation.
- Crash-safe state write/read behavior.
- Resumable status-query offsets.
- Retry decisions, cancellation, and `invalid_grant` handling.
- Directory filter: only direct final KML files in `/sdcard/lab/wardrives`.
- Build against the project's ESP-IDF 6.x environment.

## Implementation prerequisites

Before testing against a real account, create a Google Cloud project, enable Drive API, and create a **TVs and Limited Input devices** OAuth client. The Drive folder ID must refer to a folder writable by the authenticated Google account.

Useful official references:

- https://developers.google.com/identity/protocols/oauth2/limited-input-device
- https://developers.google.com/workspace/drive/api/guides/manage-uploads
- https://developers.google.com/workspace/drive/api/guides/api-specific-auth
- https://developers.google.com/identity/protocols/oauth2
