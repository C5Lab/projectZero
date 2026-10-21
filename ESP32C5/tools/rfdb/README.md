# RF database tooling

This directory contains original JanOS tooling for reproducible, separately
distributed RF database artifacts. It does not contain downloaded database
inputs or generated runtime `.bin` files.

## Provenance lock

`sources.lock.json` is validated by `provenance.py`. Every populated source
record must use an immutable revision, an HTTPS URL, an exact SHA-256 digest,
an SPDX license identifier supported by this project, and a safe local input
filename. Floating names such as `main`, `master`, and `HEAD` are rejected.

The checked-in lock pins the Wireshark vendor input and the two WPS candidate
sources to immutable revisions and exact hashes. A source update must resolve
new immutable revisions and calculate hashes; partially populated records are
invalid.

## Source bundle

After locked inputs have been placed in a local input directory, create the
corresponding deterministic source archive with:

```powershell
python tools/rfdb/build_source_bundle.py `
  --root . `
  --inputs path/to/verified-inputs `
  --output rfdb-source.tar
```

The uncompressed TAR contains verified inputs, generator scripts, the
canonical lock, license texts, notices, build instructions, and a SHA-256
manifest. All TAR ownership and time metadata is normalized. Optional Zstandard
compression is a release-packaging operation and must not alter archive
contents.

Each released `vendors.bin` or `wps_pin.bin` must be accompanied through the
same release channel by the matching source archive.

## Vendor format fixture

`vendor_format.py` implements the host-side `JVND` v3 format. It supports
sorted 24-, 28-, and 36-bit prefix indexes, a shared UTF-8 name table, payload
CRC32, and a 32-bit source-lock identifier. It accepts both the legacy
Wireshark text `manuf` representation used by fixtures and the current
generated `epan/manuf-data.c` tables used by the locked production source.
Rebuild the checked test fixture with:

```powershell
python tools/rfdb/vendor_format.py `
  --input tests/fixtures/vendor_manuf_sample.txt `
  --output tests/fixtures/vendors_v3.bin `
  --source-id 00000000
```

The production wrapper builds offline by default from a previously verified
cache entry:

```powershell
python tools/rfdb/build_vendor_db.py `
  --lock tools/rfdb/sources.lock.json `
  --cache .cache/rfdb `
  --output out/vendors.bin `
  --report out/vendors.report.json
```

It refuses a missing cache or hash mismatch. Network access is possible only
with the explicit `--refresh-source` option, and downloaded bytes are checked
against the existing lock before the cache is updated. The builder never
changes `sources.lock.json`; adding or replacing a locked record is a separate,
explicit provenance operation.

## WPS PIN database

`wps_format.py` defines the compact `JWPS` v2 artifact and retains read support
for strict legacy v1 artifacts. The production wrapper
builds from the two verified WPS inputs and reports malformed, duplicate,
unknown-algorithm, and unsupported Arcadyan rows:

```powershell
python tools/rfdb/build_wps_pin_db.py `
  --lock tools/rfdb/sources.lock.json `
  --cache .cache/rfdb `
  --output out/wps_pin.bin `
  --report out/wps_pin.report.json `
  --allow-unsupported-report
```

The explicit flag allows publishing an artifact that reports, but never runs,
the unsupported Arcadyan algorithm. `JWPS` v2 stores every accepted source PIN
as a literal eight-digit `u32le`, so source values with a non-standard checksum
are retained and reported rather than silently corrected or removed. Seven-
digit source values still receive their standard checksum. Strict validation
remains mandatory for an explicitly entered user PIN. Legacy `JWPS` v1 stores
only checksum-valid seven-digit bodies in `u24le` and derives the checksum on
lookup.
