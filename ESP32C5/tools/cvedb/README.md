# JCVE/1 offline catalog builder

`build_catalog.py` converts one reviewed local JSON manifest into the bounded,
read-only `JCVE/1` catalog consumed by JanOS. The tool performs no network I/O.
Every manifest source must exactly match `sources.lock.json` after canonical
ordering and validation. The checked lock and fixture are test-only; they do
not assert a current router vulnerability and must not be shipped as a
production catalog.

## Source governance and offline release

The checked `janos-router-cve-sources-lock-v1` schema is deliberately limited
to `status: test-fixture-only`. A production release uses a reviewed source lock
v2. Each locked source has a matching governance record whose authority is
`official-vendor`, `cna`, or `cisa`, plus an explicit redistribution boolean.
Every catalog source already carries its canonical HTTPS URL, retrieval UTC,
an immutable revision, lower-case SHA-256 and license. An immutable revision or
dated snapshot is accepted only as a lower-case 40- or 64-hex revision or
`snapshot-YYYYMMDDTHHMMSSZ-<64-hex-digest>` with a real UTC calendar timestamp.
Branch, tag, remote and ref names, ambiguous short hashes, upper-case hashes
and malformed snapshot tokens are rejected. A source marked for redistribution
additionally names a nonempty relative license file that exists beside the
lock; path traversal and missing files are rejected.
The build report includes `source_lock_schema`, `source_lock_status`, and
`source_lock_sha256` over canonical JSON for the complete lock, including its
governance rows.

The complete offline release sequence is documented in
`docs/router-cve-catalog.md`. The release owner fetches pinned official material
outside firmware, reviews exact aliases/rules, builds and independently parses
the deterministic catalog, signs with an external production key, verifies
both hashes and key ID, transfers the pair with the existing FS tooling, then
runs `router_audit db verify` and `router_audit db install`. Firmware performs
no download and this repository contains no production trust anchor or private
key.

```powershell
python -B -m tools.cvedb.build_catalog `
  --manifest tests/fixtures/router_cve_manifest_v1.json `
  --lock tools/cvedb/sources.lock.json `
  --output catalog-v1.bin `
  --report catalog-v1.report.json
```

## Frozen binary layout

All integers are little-endian. The header is exactly 192 bytes:

| Offset | Field |
|---:|---|
| 0 | `magic[4] = "JCVE"` |
| 4 | `version u16 = 1` |
| 6 | `header_size u16 = 192` |
| 8 | `flags u32 = 0` |
| 12 | `file_size u32` |
| 16 | payload `crc32 u32` |
| 20 | reserved `u32 = 0` |
| 24 | `created_epoch u64` |
| 32 | `expires_epoch u64` |
| 40 | monotonic catalog `serial u64` |
| 48 | payload SHA-256 `[32]` |
| 80 | canonical provenance SHA-256 `[32]` |
| 112 | opaque signing `key_id[16]` |
| 128 | six `{absolute_offset u32, count_or_size u32}` descriptors |
| 176 | reserved `[16] = 0` |

Descriptors are ordered as sources, models, aliases, advisories, exact
firmware rules, and string table. The first five use element counts; the last
uses byte size. Sections are contiguous in descriptor order and cover every
payload byte. Fixed record sizes are 24, 16, 8, 32, and 12 bytes respectively.
The final string table contains at most 2048 deduplicated
`u8 length + printable ASCII bytes` entries;
all record string fields are 32-bit offsets relative to that table.
Duplicate values at different offsets are rejected as noncanonical. Source
hashes use exactly 64 lower-case hexadecimal characters. Provenance URLs use
the exact lower-case `https://` scheme and canonical lower-case ASCII authority;
whitespace/control characters, userinfo, query strings, fragments, port 0,
explicit default port 443, and DNS labels beginning or ending with `-` are rejected
rather than normalized. Paths use the exact subset
`[A-Za-z0-9._~:@/-]*`: `@` and `:` are allowed in the path component, while
percent encoding and other delimiters are rejected. An alias may equal its own
primary model, but may never name another model's primary identity. The
printable-ASCII rule is deliberate:
version 1 avoids a second Unicode-normalization implementation in firmware;
non-ASCII router identity remains evidence for manual review, never an exact
catalog match.

ESP32-safe format limits are 16 sources, 128 models, 256 aliases, 256
advisories, 1024 exact firmware rules, 256 rules per model, 128 advisories per
model, and four million validation work units. The 4 MiB outer file envelope
remains frozen, but these lower section/work limits are enforced before nested
validation. Firmware reads the file once into an allocator-owned immutable
snapshot in 512-byte chunks; snapshot allocation failure aborts open with
`CAPACITY`. It never falls back to rereading mutable storage.

String deduplication hashes every byte into a bounded 64-bit index, merge-sorts
the index in `O(n log n)`, and performs byte-for-byte comparison whenever hash
and length match. Hashing, sort comparisons, and collision bytes are included
in the validation-work counter; hash equality is never treated as string
equality.

Fixed records are:

- source, 24 B: six `u32` string offsets for source ID, HTTPS URL,
  retrieval UTC, license, revision, and pinned SHA-256 text;
- model, 16 B: vendor offset, model offset, first firmware-rule index, and
  firmware-rule count;
- alias, 8 B: normalized alias offset and model index;
- advisory, 32 B: source index; CVE, URL, publication date, severity,
  optional KEV date, and fixed-version string offsets; then one EOL flag byte
  and three zero reserved bytes (`0xffffffff` is the only absent-string value);
- firmware rule, 12 B: model index, advisory index, and exact normalized
  firmware string offset.

The format is capped at 4 MiB. It uses exact normalized model, alias, and
firmware values only. It contains evidence links and reviewed provenance, not
an assertion that a detected router is vulnerable or exploitable.

## Detached signature and install policy

`sign_catalog.py` consumes an already-reviewed local catalog plus an external
P-256 PEM private key. A private key below the repository root is refused;
`--test-key` only relaxes that rule for `tests/fixtures`. No private key is
stored by this repository. The signer delegates the private-key operation to
the explicitly selected OpenSSL executable, canonicalizes ECDSA to low-S, and
writes the detached result atomically. It prints only catalog SHA-256, key ID,
and output path.

`JCSG/1` is `80 + der_size` bytes. Its little-endian header is:

| Offset | Field |
|---:|---|
| 0 | `magic[4] = "JCSG"` |
| 4 | `version u16 = 1` |
| 6 | `header_size u16 = 80` |
| 8 | `flags u32 = 0` |
| 12 | exact signature file size `u32` |
| 16 | `key_id[16]`, equal to the catalog key ID |
| 32 | SHA-256 of the complete JCVE file `[32]` |
| 64 | strict DER size `u16`, 8 through 72 |
| 66 | reserved `[14] = 0` |
| 80 | exact DER ECDSA signature |

The verifier rejects long-form/trailing DER, negative, zero, redundant or
out-of-range integers, non-P-256 keys, and high-S signatures before calling
the production Mbed TLS verifier. The bounded registry accepts at most four
unique nonzero key IDs. This repository deliberately ships no production
trust anchor: an empty or not-yet-release-provisioned registry returns
`UNKNOWN_KEY`; test keys remain injected by host tests and are not production
defaults.

Production callers transfer one immutable PSRAM allocation with
`router_cve_verify_owned` or `router_cve_install_catalog_owned`. Both catalog
and tiny signature handles are cleared before any callback and consumed on
every return. Hashing, ECDSA verification, slot I/O, and the JCVE parser use
that same catalog allocation. The owned install path writes the inactive slot,
checked-syncs it, rereads it into the same allocation, and transfers that exact
readback to the parser before publishing a journal. It performs no second
catalog-sized allocation. The copying `router_cve_verify_bytes` and
`router_cve_install_catalog` APIs remain for source compatibility, but the
production command adapter must use the owned APIs for a 4 MiB catalog.
Installed-pair verification uses `router_cve_install_recover_owned`: it still
cross-checks the exact trusted NVS commit, named journal, hashes, and pair, but
reads the pair into caller-owned capacities and transfers that same catalog
allocation to the parser. The legacy scratch recovery API remains compatible
and is not the production 4 MiB path.

Installation uses two catalog/signature slots and two 128-byte CRC-protected
pointer journals. A journal is published atomically only after the inactive
pair has been reread and fully verified. One trusted NVS commit record is then
advanced with compare-and-swap while the installer lock is held. That record
binds slot, generation, monotonic serial, both file hashes, key ID, and the
time-unknown flag. Recovery follows only the journal exactly named by that
record; a newer pre-commit journal is inert. A mismatched or unreadable
journal, pair, digest, key, serial, generation, slot, or time flag fails closed.
Journal publication or commit uncertainty is reported as
`PUBLISHED_UNCERTAIN`, never as a definite rollback. Unknown system time
requires the explicit allow policy, is persisted in the trusted commit, and
remains visible after trusted time becomes available. Recovery preserves the
specific `TIME_UNKNOWN`, `STALE`, and `NOT_YET_VALID` results for an otherwise
valid committed pair. These host fault tests do not prove FAT, NVS, power-loss,
or ESP32 timing behavior.
