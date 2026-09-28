# Wi-Fi Analyzer device validation follow-up

## Evidence provided by the user

The user built and ran JanOS. Captures show successful 2.4 GHz and 5 GHz scans,
a both-band Detailed scan (54 APs), a Passive scan restricted to channels 1/6/11
(23 APs), limit-four truncation (38 found, 4 returned), rejection of concurrent
scans, cooperative cancellation, and clear followed by zero analyzer PSRAM bytes.
These observations do not cover all failure paths or establish Tab5 runtime behavior.

Two narrow channel-64 scans returned no APs. They cannot validate width metadata.
A channel-36 scan returned six APs with consistent 80 MHz / 5210 MHz geometry.

## 160 MHz geometry correction

An earlier AP record reported primary 64, width 160, secondary below, and center
5290 MHz. The original offset-only geometry validation accepted this tuple.
5290 is an 80 MHz segment center, not a supported complete 160 MHz block center.
This would have shifted a 160 MHz chart footprint by 40 MHz.

JanOS now requires a complete 160 MHz center of 5250, 5570 or 5815 MHz, together
with the existing primary/secondary checks. Unsupported/inconsistent geometry
becomes all-null while BSSID, SSID, RSSI, primary and other AP fields remain.
The code does not guess a replacement center from the primary channel and does
not assume undocumented semantics for `vht_ch_freq2`. The exact raw SDK cause
remains unconfirmed; capability metadata stays `sdk_unverified`.

The Tab5 reader and both Python reference validators enforce the same constraint.
Use the updated JanOS with the updated Tab5; an old 160/5290 wire record is now
rejected rather than rendered. Valid unknown geometry still commits normally.

This is advertised AP geometry, not C5 receive/transmit bandwidth or measured
airtime. The supported centers are a geometry rule, not a regulatory permission.

## Verification and next device check

Regression tests first demonstrated that the old validator accepted the captured
invalid tuple. Python tests also exercise all 24 primaries in the three supported
160 MHz blocks. Portable C harnesses cover unknown fallback/serialization and
host rejection, but were authored only: no C compilation or execution was run.

Verification after this correction: 57 JanOS Python/reference/source checks and
61 Tab5 Python/reference/source checks passed. Tree-sitter parsed 21 JanOS and
33 Tab5 files/fragments without grammar diagnostics; both synthetic captures
produced one snapshot, two terminal records and no errors. These checks do not
execute either production C implementation. The earlier hardware results above
predate this correction; the new firmware still needs the user's build and check.

After the user's next JanOS build and flash, run:

```text
wifi_analyzer scan --band 5 --profile detailed --limit 64
wifi_analyzer status
```

If the same primary-64 AP again reports ambiguous SDK metadata, expect
`bandwidth`, `secondary`, `center1_mhz` and `center2_mhz` to be null. Its AP row
must remain present; Tab5 should draw an unknown-width primary marker. A verified
full center of 5250 may still be reported as 160 MHz. Confirm that known 80 MHz
APs retain their geometry, then proceed to the Tab5 build/device acceptance list.
