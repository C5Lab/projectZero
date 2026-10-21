# JanOS distributed crack worker (`CRACK/1`)

`crack_worker` turns an ESP32-C5 Monster into one worker controlled by Tab5.
Tab5 remains the source of truth: files are copied to a content-addressed cache
on the worker SD card and reused on later jobs.

## Commands

```text
crack_worker capabilities
crack_worker probe <wordlist|capture> <size> <crc32-hex>
crack_worker receive <wordlist|capture> <size> <crc32-hex> [block-size [ack32]]
crack_worker reset <wordlist|capture> <size> <crc32-hex>
crack_worker diag
crack_worker start <job-id> <capture-size> <capture-crc32> <wordlist-size> <wordlist-crc32> <start-byte> <end-byte>
crack_worker status [job-id]
crack_worker cancel [job-id]
```

The capture is a 393-byte-record HCCAPX file, not a PCAP. A capture may contain
up to 16 records. Wordlists are streamed from SD and are never loaded into RAM.
`end-byte=0` means EOF. For a non-zero start the worker advances to the next
complete line; a line belongs to the shard in which its first byte occurs.

## File synchronization

The cache paths are derived only from the declared content identity:

```text
/sdcard/lab/crack_worker/wordlists/<size>_<crc32>.txt
/sdcard/lab/crack_worker/captures/<size>_<crc32>.hccapx
```

`probe` returns `state=present` or `state=missing`. `receive` responds with a
`READY` line containing `offset`, `prefix_crc`, `bsize`, `rx_ms`, `ack_size`,
and `prepare_ms=<calculated>`. ACK32 additionally negotiates
`ack_wait_ms=2000`, `next_header_ms=7000`, and `finish_linger_ms=7000`.
These fixed values are protocol-4 requirements. This lets
Tab5 resume a `.part` file after checking that its own prefix has the same CRC.
If that prefix differs, Tab5 sends CAN and calls `reset` before retrying from
zero. JanOS durably checkpoints the expected file identity, confirmed offset,
prefix CRC and block size in an adjacent `.part.meta` file. Checkpoints are
written every 256 KiB, on the final data block, and on a controlled transfer
failure. Replayed blocks do not write, hash, checkpoint or advance progress.
After a reboot,
bytes beyond the last checkpoint are truncated and transfer resumes without a
full prefix scan, including for multi-megabyte wordlists. A legacy `.part`
without metadata is imported by scanning at most 1 MiB; a larger legacy partial
restarts safely from zero. `reset`, a known-bad full CRC, and successful rename
remove both `.part` and `.part.meta`. After a complete CRC verification JanOS
writes a crash-safe `.verified`
marker containing the format version, size, CRC and modification time. Later
boots validate that marker in O(1). Older entries without a marker are treated
as untrusted and transferred once more; this avoids an uncancellable full-file
scan in the console command. Changed or malformed entries lose both the file
and marker. Target firmware uses the ROM CRC32 implementation while validating
incoming transfer blocks.
The binary stream then uses the existing JanOS transfer block format:

```text
"FTB\x01" | uint32_le index | uint32_le length | uint32_le payload_crc32 | payload
```

By default JanOS answers every valid block with ACK (`0x06`), requests a retry
with NAK (`0x15`), and aborts with CAN (`0x18`). A legacy five- or six-argument
`receive` call always uses these one-byte replies. A seven-argument command may
use only the `ack32` reply-mode token; an unknown token is rejected. In ACK32
mode `READY` reports `ack_size=32` (otherwise it reports `ack_size=1`) and every
block reply is the following exact 32-byte frame:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | ASCII `FTA` followed by version byte `0x01` |
| 4 | 4 | block index, little-endian |
| 8 | 1 | status: ACK `0x06`, NAK `0x15`, or CAN `0x18` |
| 9 | 3 | reserved, zero |
| 12 | 8 | committed file offset, little-endian |
| 20 | 4 | CRC32 of bytes 0 through 19, little-endian |
| 24 | 8 | reserved, zero |

For ACK, the frame contains the received block index and its newly committed
offset. For NAK or CAN, it contains the rejected or expected index and the last
valid offset. In byte mode JanOS flushes the completed `.part`, checks the full
CRC32, and atomically renames it immediately. Grove/M-BUS keep their 8192-byte
blocks, byte replies and existing timeouts. USB requests 1024-byte blocks and
ACK32 with the following additional protocol-4 rules.

### ACK32 replay, finish and cancellation

JanOS remembers only the last committed data block's index, length, header CRC
and post-commit offset. An exact immediate-previous header is a replay, including
after the final data ACK. JanOS consumes the declared payload in full and resends
the saved ACK without revalidating the duplicate payload CRC or applying storage
or progress effects. The committed original is authoritative. Short duplicate
payloads, malformed headers, stale/future indices, and mismatched replay metadata
abort the transfer. Each receive command starts with empty replay metadata and
index zero, even when its file offset resumes above zero.

At EOF the receiver remains in FIN_WAIT. The sender finishes with the normal
16-byte FTB/1 header, index equal to the next expected data index, length zero
and CRC zero, with no payload. Only this exact zero-length tuple is valid. JanOS
checks the full CRC, flushes/closes and atomically publishes the file once,
then sends the FIN ACK with the file size as committed offset. Failed
finalization sends CAN and never a FIN ACK.

After FIN ACK, JanOS waits for 7000 ms of quiet in FIN_LINGER. An identical FIN
only resends its ACK and restarts that quiet period; it never republishes the
file. Only after quiet expiry does JanOS print SYNCED, END and return to the CLI.
This accommodates an initial FIN plus two retries at 2000 ms per attempt.

The first header byte after READY has a preparation deadline in both byte-ACK
and ACK32 modes of
`10000 + ceil(resume_offset / 262144) * 1000` milliseconds. If it exceeds 600000,
JanOS reopens/truncates `.part` to zero, removes the old checkpoint, resets file
position and CRC/offset/index/replay state, then offers offset zero with
`prepare_ms=10000`. The longer preparation deadline applies only until the first
header byte arrives. Byte-ACK then uses `rx_ms`; after every ACK32 or NAK32, the
next first-header-byte wait is 7000 ms starting after the reply is enqueued.
Header remainders and payloads use `rx_ms`, so a partial frame still fails
promptly. In ACK32 mode Tab5 reserves 1000 ms of the preparation deadline to
send its first header and never sends one late.

A single CAN byte at a header boundary cancels PREPARING, DATA or FIN_WAIT with
the normal error/END response. In FIN_LINGER it ends the wait successfully and
prints SYNCED; the published file is preserved. CAN is never interpreted inside
a header remainder or payload. A failed or cancelled transfer keeps its partial
file unless its full CRC is known to be wrong. If every FIN ACK is lost, the
already published file remains a valid cache hit for the next command.

Before sending DIAG after a failure, Tab5 must drain residual ACK32 and terminal
END/prompt through the receiver's current deadline plus 3000 ms. It must not send
CAN or text after a partial forward write or uncertain deadline. If no CLI
boundary appears, it marks the worker lost and falls back locally.

After a transfer failure Tab5 can issue `crack_worker diag`. JanOS returns the
last receive phase and exact byte counters, for example:

```text
[CRACK/1] DIAG phase=payload reason=payload_timeout header_got=16 header_expected=16 payload_got=496 payload_expected=1024 offset=1024 block=0 baud=115200
```

Tab5 requests this automatically after a USB block timeout. A zero-byte header
points at the host/bridge OUT path, a short header at short-packet handling, a
partial payload at a stalled block transfer, and a complete payload without an
ACK at the return path.

## Job lifecycle

Machine-readable output is prefixed with `[CRACK/1]`:

```text
[CRACK/1] ACCEPTED job=...
[CRACK/1] STARTED job=... start=... end=...
[CRACK/1] STATUS job=... state=running checked=... safe_offset=...
[CRACK/1] DONE job=... result=found ssid_hex=... password_hex=...
[CRACK/1] DONE job=... result=not_found|cancelled|error ...
```

SSID and password are hexadecimal so whitespace and console metacharacters
cannot corrupt parsing. Only one cracking job runs per worker. The global
JanOS `stop` command also requests cancellation.

`start` is idempotent for the most recently retained job. Repeating the same
job ID with the same capture, wordlist, and byte range returns `ACCEPTED` with
`replay=1` and the current `state` without creating another task. Reusing that
job ID with a different assignment returns `job_conflict`; a different job
while one is running remains `busy`. `STATUS` additionally reports
`phase=starting|cracking|terminal|idle` and `progress_age_ms=N`. These optional
health fields are diagnostic; safe resume decisions still use `safe_offset`.

JanOS remains on the unmerged development version `1.7.5`; protocol capability version 4 is the compatibility
gate and advertises exactly `protocol=4 sync=ftb1 ack=byte,frame32
replay=last_block finish=fin32`. A protocol-4 worker missing any mandatory token,
or a protocol-3 worker, is incompatible with the new distributed sender.
The optional `start=idempotent health=phase,progress_age_ms` capability tokens
advertise replay-safe job creation and richer status diagnostics.
Capability version 2 defines `safe_offset` as the first byte not yet
fully accounted for. It advances after an invalid line is skipped or after a
candidate has completed verification, never while a candidate is in flight.
The compute task runs below the console REPL priority so `status` and `cancel`
remain responsive during PBKDF2 work.

## Read-only artifact inventory (`ARTIFACT/1`)

The current JanOS 1.7.5 development tree adds an independent inventory command. Its capabilities advertise
`artifact_inventory=1`. The existing `CRACK/1 protocol=4` capability string and
all transfer behavior remain unchanged; clients discover inventory separately.

```text
artifact_inventory capabilities
artifact_inventory list <request-id> <scope> <cursor> <limit>
artifact_inventory inspect <request-id> <snapshot-id> <entry-id>
artifact_inventory cancel <request-id>
```

Request IDs contain 1–32 ASCII letters, digits, `_` or `-`. Integers are unsigned
decimal with no sign, whitespace or suffix, and are checked before conversion.
The only scopes are `handshakes` (`/sdcard/lab/handshakes`) and `pcaps`
(`/sdcard/lab/pcaps`); a client cannot supply a path. Neither scope is recursive.
Directory entries that are not regular files are omitted. Host tests also reject
symlinks; the device's FatFs has no symlinks.

`list` with cursor `0` creates a new metadata snapshot. A subsequent nonzero
cursor addresses the retained snapshot for that scope. Entries are sorted by
raw filename bytes within that snapshot; entry IDs are one-based, cursors are
zero-based offsets, and `next` is the next offset. `limit` is 1–32. Every refresh
invalidates earlier entry IDs and inspection cache entries. Clients must discard
snapshot IDs across a device reboot or connection reset. Only one snapshot is
retained. Snapshot IDs never wrap during a boot.

A snapshot retains at most 256 entries and visits at most 4096 directory entries.
A larger directory produces the retained entries and `END status=error
reason=limit_reached`; `more` describes only the retained snapshot, so that
response must not be treated as a complete directory inventory. Listings use
directory metadata and never read or hash file contents. Raw filename bytes are
lowercase hex, including whitespace and non-UTF-8 bytes. Names are at most 255
bytes, paths at most 511 bytes, and protocol lines less than 1024 bytes excluding
CR/LF. Filename suffixes `.hccapx` and `.pcap` are matched case-sensitively;
other regular files have `format=unknown`.

### Exact records

Records are single lines with the following field order. Values have no spaces.
`R` is a request ID, `N` a decimal snapshot ID, `E` an entry ID, and `U64` an
unsigned decimal value. Capabilities uses the synthetic request/snapshot ID `0`.

```text
[ARTIFACT/1] CAPABILITIES req=0 snapshot=0 artifact_inventory=1 scopes=handshakes,pcaps page_max=32 entries_max=256 name_max=255 line_max=1024 inspect_max=16777216 validator=hccapx_v1
[ARTIFACT/1] BEGIN req=R snapshot=N scope=handshakes cursor=0 limit=32
[ARTIFACT/1] ITEM req=R snapshot=N entry=E name_hex=HEX size=U64 mtime=U64 format=hccapx validation=unknown reason=cache_stale
[ARTIFACT/1] ACCEPTED req=R snapshot=N entry=E
[ARTIFACT/1] PROGRESS req=R snapshot=N entry=E bytes=U64 total=U64
[ARTIFACT/1] RESULT req=R snapshot=N entry=E validation=valid reason=ok crc32=1234abcd bytes=U64
[ARTIFACT/1] END req=R snapshot=N status=ok reason=ok next=0 more=0 count=0
```

`format` is `hccapx|pcap|unknown`, `validation` is `valid|invalid|unknown`,
`status` is `ok|error|cancelled`, and `more` is `0|1`. `mtime` is the filesystem
modification time in seconds, or zero when unavailable. A completed full read
returns eight lowercase CRC32 hex digits (IEEE CRC32); an incomplete inspection
returns `crc32=none`. CRC32 identifies bytes, not their trustworthiness.

Each accepted capabilities, list or inspect request emits exactly one `END`.
A successful inspection operation ends with `status=ok reason=ok` even when its
`RESULT` is structurally invalid or unsupported: use RESULT for file validation.
Operational failures use `status=error`; cancellation uses `status=cancelled`.
Malformed commands produce a single `END req=0 snapshot=0 status=error
reason=invalid_field next=0 more=0 count=0` and do not start work.

There is one active inventory operation. A different request while it is busy
gets one `END ... snapshot=0 status=error reason=busy`; allocation failure before
a snapshot exists likewise uses the caller's request ID with `snapshot=0`.
Repeated use of its live request ID
is coalesced without another response or operation. `cancel R` sets a flag only
for matching active request `R`; the original operation supplies RESULT/END.
Cancelling an unknown or already completed ID has no protocol output and cannot
emit a duplicate terminal record. The adapter atomically closes cancellation
acceptance before the terminal result; a cancellation accepted just before that
boundary is rechecked before cache/RESULT/END commit. Inspection runs in a low-priority background
task so the console can receive cancellation. Listing is synchronously bounded.

### Inspection and cache semantics

Inspection opens source bytes in `rb` mode, uses 4096-byte chunks, performs a
non-sleeping scheduler yield after each chunk, polls cancellation and a 30-second
deadline, and reads at most 16 MiB. Progress is emitted every 64 KiB and at
completion, avoiding a line-rate bottleneck on large files.
The deadline is cooperative: an underlying filesystem call must return before
the next check. It verifies file metadata at snapshot lookup, open, and completion,
including the open file and pathname. A changed or replaced file returns
`unknown/changed` with no completed CRC. These metadata checks are limited by
FatFs timestamp granularity; they cannot detect an external same-size rewrite
that preserves all observable metadata during the inspection.

The HCCAPX validator accepts at most the same 16 records advertised by the
worker and checks 393-byte record boundaries, signature/version,
message-pair range, SSID length, key version, EAPOL length/type, declared payload
length and matching key-version bits. `valid/ok` means structurally consistent,
not proof that credentials can be recovered. Raw PCAP always remains
`unknown/unsupported_validator` on this release; Tab5 performs final validation.

Stable RESULT reason codes are:

| Reason | Validation and meaning |
| --- | --- |
| `ok` | `valid`: supported HCCAPX records passed structural checks |
| `empty` | `invalid`: an HCCAPX file has no bytes |
| `invalid_length` | `invalid`: shorter than one HCCAPX record |
| `truncated_record` | `invalid`: trailing partial HCCAPX record |
| `invalid_field` | `invalid`: a supported HCCAPX record has an inconsistent field |
| `unsupported_format` | `unknown`: unsupported suffix, signature or version |
| `unsupported_validator` | `unknown`: PCAP awaits validation on Tab5 |
| `io_error` | `unknown`: filesystem access failed |
| `changed` | `unknown`: metadata changed or a read ended early |
| `cancelled` | `unknown`: the matching request was cancelled |
| `timeout` | `unknown`: the cooperative deadline elapsed |
| `limit_reached` | `invalid` after a complete HCCAPX read with more than 16 records; `unknown` when the generic 16 MiB inspection limit prevents a complete read |
| `cache_stale` | `unknown`: snapshot/entry/cache is unavailable or invalid |

`busy`, `invalid_field`, `io_error`, `timeout`, `cancelled`, `cache_stale`, and
`limit_reached` are also terminal reasons for command, list or scheduling errors.

The inspection cache is volatile RAM attached to the current snapshot, with
bounds-checked codes and a CRC over cached metadata/result fields. Listing uses
it only when its integrity and current source metadata match. Stale/corrupt
cache becomes `unknown/cache_stale`; refresh/reboot discards it. This cache is
separate from transfer `.verified` markers and neither reads nor writes them.
Inventory never deletes, renames, truncates, repairs or rewrites source files.
It also avoids the SD initialization helper, which creates directories/test
files; inventory requires the device's normal SD mount to have completed.

Host verification (no firmware build):

```sh
python3 tests/test_artifact_inventory_contract.py
python3 tests/test_crack_worker_diagnostics.py
python3 tests/test_crack_worker_job_replay.py
```

The inventory runner compiles both the pure core and the actual console adapter
extracted from `main.c`, exercises request lifecycle/cancellation, and checks
source bytes, file-open modes, metadata-only listing, bounds and cache failures.
