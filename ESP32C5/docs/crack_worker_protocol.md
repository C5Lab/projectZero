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

JanOS version is `1.7.5`; protocol capability version 4 is the compatibility
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
