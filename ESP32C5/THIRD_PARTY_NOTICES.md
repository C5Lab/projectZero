# Third-Party Notices

The original source code within the `ESP32C5/` subproject is licensed under
Apache-2.0. This subproject-level license does not replace the MIT license at
the parent repository root; the parent repository remains licensed under MIT.
Files carrying their own notices retain those notices and are not relicensed
by the `ESP32C5/LICENSE`.

## RF database artifacts

The following database artifacts are separate runtime data files. They are not
embedded in the JanOS firmware image.

| Artifact | Runtime path | Data source | License | Corresponding source |
|---|---|---|---|---|
| `vendors.bin` | `/sdcard/lab/vendors.bin` | pinned Wireshark `epan/manuf-data.c`; Wifite3 behavior reference | GPL-2.0-or-later | matching `rfdb-source-<revision>.tar.zst` |
| `wps_pin.bin` | `/sdcard/lab/wps_pin.bin` | pinned Airgeddon `known_pins.db` and Default-WPS-PINs `pins.csv` | GPL-3.0-only | matching `rfdb-source-<revision>.tar.zst` |

Wifite3 v0.4.3 is credited as the behavior reference for longest-prefix vendor
lookup and ranked WPS candidates. JanOS does not copy its Python implementation.
Exact revisions and SHA-256 values are recorded in
`tools/rfdb/sources.lock.json` before a database is released.

### Wireshark vendor source

- Project: Wireshark
- Imported file: `epan/manuf-data.c`
- Revision: `0451baac5b807b69db16a8d027fb5f199cc0ad5a`
- Source SHA-256: `9e311f92985979b92c948949c20934120bbed7015fd5344f7999e91650532c87`
- License: `GPL-2.0-or-later`
- Transformation: parse the generated `/24`, `/28`, and `/36` tables; preserve
  the full vendor name; truncate names to 60 UTF-8 bytes; intern names; sort
  prefixes; encode the checksummed `JVND` v3 runtime artifact.
- Wifite3 role: behavioral reference for longest-prefix matching only.

### Airgeddon known WPS PIN source

- Project: airgeddon
- Imported file: `known_pins.db`
- Revision: `700ad7d63df04e565bcd14d2aec6f935fcec5185`
- Source SHA-256: `b9e681d9345e424e0d87eecc4ac2e5e4ca19f450e9b91fb25a0fa8648dac346b`
- License: `GPL-3.0-only`
- Transformation: normalize OUI keys; preserve first-seen candidate order;
  complete seven-digit PIN checksums; preserve literal eight-digit source values
  (including values with a non-standard WPS checksum); deduplicate candidates;
  encode accepted records in `JWPS`.

### Default-WPS-PINs source

- Project: Default-WPS-PINs
- Imported file: `pins.csv`
- Revision: `56a23e58a86a6ad9e8edd74cec4113c77f55a240`
- Source SHA-256: `07e8266b3640f93d49d2b040ef7e710bd2b34c7f4a2b7ef99af1b12e119a999d`
- License: `GPL-3.0-only`
- Transformation: merge OUI candidates in source order; normalize documented
  algorithm aliases; preserve unsupported Arcadyan mappings as a reserved bit
  and visible report entry; encode accepted records in `JWPS`.

The current generated WPS artifact is `JWPS` v2, 18,162 bytes, SHA-256
`1017ec33b8b4bd0917a4d6691bca44e4716557f87c1069da94ec0dba97cedcb4`.
It contains 605 static OUIs and 3,101 ordered OUI/PIN associations. The build
report records 855 accepted source rows and 764 unique associations whose
literal eight-digit value does not pass the standard WPS checksum.

Full license texts are available in:

- `LICENSES/Apache-2.0.txt`
- `LICENSES/GPL-2.0-only.txt`
- `LICENSES/GPL-2.0-or-later.txt`
- `LICENSES/GPL-3.0-only.txt`

