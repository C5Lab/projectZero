# JanOS USB file manager protocol (`FS/1`)

`fs` runs in the JanOS application console on UART0. It does not run in the ROM
download mode. The console starts at 115200 baud after each boot. One client must
own the serial port at a time; finish flashing and release that port before using
the file manager.

All paths are relative to `/sdcard/lab`. The current FatFS API uses OEM code
page 437. Encode the **raw filesystem path bytes** with standard RFC 4648
Base64, including `=` padding, and pass the encoded value as one CLI argument.
`name64` likewise contains the raw bytes returned by `readdir`, so a browser
should keep those bytes for later `ls`/`get` and decode CP437 only for display.
New upload names must be encoded into CP437; reject characters that cannot be
represented rather than sending UTF-8 bytes. `-` means the root directory for
`ls` only. The firmware rejects
absolute paths, empty path segments, `.` and `..` segments, backslashes, control
bytes, segments ending in a dot or space, and paths too long for
its 192-byte absolute path buffer. These rules also avoid FAT aliases of the
reserved `.fs-part` and `.fs-backup` upload files; suffixes are checked without
case sensitivity.
For mutations, `fs put` and `fs rm` additionally reject `~` anywhere in the
relative path with `ERROR code=unsafe_alias` before mounting SD. FAT 8.3 short
names can use `~` to address a `.fs-part` or `.fs-backup` recovery file through
another name.
Existing such files remain visible through `ls` and readable through `get`.
The console has a 256-byte command-line limit, which may further restrict long
Base64 paths. File names in listings use the same Base64 encoding.

## Discovery and listing

```text
fs hello
[FS/1] HELLO root=/sdcard/lab encoding=cp437 get=ftb1 put=ftb1_ack32 bsize=1024 rm=file_empty_dir cleanup=part_only
[FS/1] END

fs ls -
[FS/1] BEGIN
[FS/1] ITEM type=d size=0 name64=aGFuZHNoYWtlcw==
[FS/1] ITEM type=f size=18162 name64=d3BzX3Bpbi5iaW4=
[FS/1] END status=ok
```

`type=d` denotes a directory; `type=f` denotes a regular file. The list may
contain hidden files. Ignore `.` and `..` entries. On failure the command emits
`[FS/1] ERROR code=<token>` followed by `[FS/1] END`. A client must discard any
partial listing if it sees `ERROR` before the end marker.

`fs hello` does not mount the SD card or initialize Wi-Fi. It is a lightweight
test that the JanOS application console is accepting commands.

## Download

```text
fs get <base64-path>
```

On success `fs get` delegates to `send_file` with offset `0` and block size
`1024`. The response is the existing `[FT]` header and FTB/1 binary download
protocol, including per-block ACK/NAK/CAN and final CRC32. See
[Console UART and binary file transfer](command-manual.md#console-uart-and-binary-file-transfer).
Before delegation, path, mount and regular-file errors use `[FS/1] ERROR` and
`[FS/1] END`.

## Upload

```text
fs put <base64-path> <decimal-size> <eight-hex-digit-crc32> [replace]
[FS/1] READY size=<size> offset=0 crc32=<CRC32> bsize=1024 ack_size=32 rx_ms=<ms> prepare_ms=10000
[FS/1] END

```

The blank line after `END` is the boundary between text and binary. `size`
counts bytes and is limited to `UINT32_MAX`; CRC32 is the standard reflected
CRC32 used by FTB/1. Each upload starts at offset zero; there is no resume.
After `READY`, send one 16-byte FTB/1 header and up to 1024 payload bytes per
block:

```text
"FTB\x01" | uint32_le index | uint32_le length | uint32_le payload_crc32 | payload
```

The board answers every block with the 32-byte FTA/1 ACK32 frame documented in
[CRACK/1 file synchronization](crack_worker_protocol.md#file-synchronization).
Wait for the reply before sending the next block. Its index, status, committed
offset and frame CRC let the sender distinguish ACK, NAK and CAN without relying
on timing alone. `rx_ms` is the board's header/payload receive timeout; the
first header byte has `prepare_ms=10000` to allow the browser to switch from
line parsing to binary mode. A single CAN byte at a header boundary cancels an
unfinished upload.

After sending exactly `size` payload bytes, send a normal FTB/1 header with the
next index, length zero and CRC zero. The board verifies the full-file CRC,
flushes and closes the staged file, publishes it, and replies with the FIN ACK32
frame. It then listens for a repeated FIN for up to seven seconds so a lost FIN
ACK can be recovered. A CAN byte after a successful FIN ends that linger early
without deleting the published file. The terminal response is:

```text
[FS/1] DONE size=<size> crc32=<CRC32>
[FS/1] END
```

Failures use `[FS/1] ERROR code=<token>` and `[FS/1] END`. Without `replace`,
an existing target produces `code=exists` before `READY`. Upload data is written
to a `.fs-part` file. A failed transfer deletes that partial file and preserves
the previous target. With `replace`, the old target is moved to `.fs-backup`
before the staged file is moved into place; an ordinary second-rename failure
rolls the old target back. FAT does not provide a fully atomic multi-rename
transaction across a power loss. A sudden power cut in the swap window can
leave the old file under its `.fs-backup` name.

The next `fs get`, `fs put` or `fs rm` for that file target performs recovery
before accessing it. If the target is missing but `.fs-backup` exists, JanOS
restores the backup.
If both exist, it keeps the published target and removes the backup. It also
removes an abandoned `.fs-part`; the REPL handles only one command at a time.
`fs put` and `fs rm` report `ERROR code=recovered_retry` after any recovery;
neither starts its requested mutation in that call. The client should refresh
and let the user retry. If recovery fails, the response is
`ERROR code=recovery_failed`; the files remain available for inspection. A
successful replacement for which backup cleanup failed reports
`[FS/1] DONE ... backup_pending=1`; its new target is published, while the old
copy remains under `.fs-backup` until the next recovery attempt. `fs get` can
download a `.fs-backup` or `.fs-part` file directly without treating its suffix
as another recovery target. `fs put` refuses those reserved suffixes. Live file
users may need to reopen data or reboot after replacement (in particular the
OUI database can remain open in JanOS).

## Delete

```text
fs rm <base64-path>
[FS/1] DONE type=f
[FS/1] END
```

`fs rm` removes exactly one regular file (`type=f`) or one empty directory
(`type=d`) beneath `/sdcard/lab`. It never deletes recursively. The root sentinel
`-` is invalid for deletion. The path uses the same raw CP437 bytes and standard
Base64 as `ls` and `get`. The command rejects paths ending in `.fs-part` or
`.fs-backup` regardless of ASCII case, and rejects `~` in any segment to prevent
FAT short-name aliases from addressing those recovery files. Before removing a
regular file or a missing target, it checks the corresponding stage and backup.
If recovery changes anything, it returns `ERROR code=recovered_retry` without
deleting the target; refresh the listing before requesting deletion again.

Errors use `[FS/1] ERROR code=<token>` followed by `[FS/1] END`. Relevant codes
include `invalid_path`, `bad_base64`, `path_too_long`, `unsafe_alias`,
`reserved_path`, `sd_unavailable`, `not_found`, `stat_failed`, `dir_not_empty`,
`unsupported_type`, `delete_failed`, `recovery_failed` and `recovered_retry`.
An empty directory reports `DONE type=d`. JanOS attempts an SD metadata sync
after a successful removal. `DONE` confirms that the filesystem accepted the
removal; it does not guarantee durability across sudden power loss. A running
feature with an open file handle may continue using that handle until it is
reopened or the board restarts.

## Abandoned upload cleanup

```text
fs cleanup <base64-path-to-a-.fs-part-file>
[FS/1] CLEANED type=part
[FS/1] END
```

This command is available when `fs hello` advertises `cleanup=part_only`. It
accepts only a relative path whose final file name ends in `.fs-part` (ASCII
case-insensitive) and has a nonempty name before that suffix. The same Base64,
CP437, path traversal, root and FAT short-name alias restrictions apply as for
`fs rm`. It removes exactly that one regular staging file and syncs SD metadata.
It does not invoke transfer recovery and does not change the target file or a
`.fs-backup` file. `fs rm` continues to reject both recovery suffixes.

The response is `ERROR code=not_stage` for any other valid path,
`unsupported_type` for a directory, or `not_found` if the stage has already
disappeared. Other path, SD and removal failures use the same error framing as
`fs rm`. If a `.fs-backup` is present, it remains for normal recovery on a later
`fs get`, `fs put` or `fs rm` of the target. The console processes one command
at a time, so cleanup cannot run in parallel with an active FS/1 upload.

The upload handler temporarily owns UART0 input and locks console stdout during
binary transfer. Do not send another CLI command or run a second serial monitor
until the terminal `END`. It also suspends the console baud-rate idle fallback
for the duration of the transfer. FS/1 text is printed using LF; the configured
UART console converts it to CRLF on the wire. FTB/1 and FTA/1 binary frames are
written directly and are not line-ending-translated.
