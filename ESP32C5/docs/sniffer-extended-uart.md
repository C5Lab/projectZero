# JanOS passive sniffer UART extension, version 1

Scope: ESP32-C5 JanOS only. The extension consumes received frames during normal
sniffing. Reading results never invokes `inspect_network`, starts a scan, changes
channels, sends probes/deauthentication, or reconnects a station. `inspect_network`
remains its existing independent command. Existing initial scan behavior of
`start_sniffer` is unchanged; use selected mode or `start_sniffer_noscan` to reuse
scan results without initiating another scan.

## Commands and compatibility

```text
show_sniffer_results
show_sniffer_results_vendor
show_sniffer_results extended
show_sniffer_results_vendor extended
```

Only the exact single optional argument `extended` enables version 1. Other
arguments retain the historical ignored-argument behavior. Without it, UART AP
and client output is byte-identical for identical records. APs remain sorted by
client count descending, with stable ties; broadcast/own BSSIDs and APs with no
clients remain filtered. Clients retain insertion order and one leading space.
No metadata lines occur between APs and their clients.

The untouched prefix templates are:

```text
<legacy SSID>, CH<decimal channel>: <decimal client count>
 <uppercase colon-separated client MAC>
<legacy SSID>, CH<decimal channel>: <decimal client count> [<Vendor>]
 <uppercase colon-separated client MAC> [<Vendor>]
```

The discovered SSID never replaces `<legacy SSID>`. Empty legacy names and
historical `Unknown_XXXX`/`MGMT_XXXX` placeholders remain possible. Existing
scan merging may update the legacy SSID as it did before this extension; passive
SSID discovery does not. Vendors retain their existing position and labels.
The original command bodies are frozen in
`tests/fixtures/sniffer_legacy_commands.c` and executed against the modified
bodies in host tests, including empty SSIDs, punctuation, vendors, filters and ties.

## Wire grammar and limits

Every suffix starts with ` | ext_ver=1 | `; all further fields use exactly
` | ` (space, vertical bar, space). Each field is a fixed ASCII `key=value`.
No spaces occur inside extension values. Keys and enumerated values are
case-sensitive. Integers are decimal, without units embedded in the value.
Hex values use uppercase digits, two digits per byte, no `0x` or whitespace.
BSSID/MAC uses six uppercase byte pairs separated by colons.

Selectors use **eight hex digits for the complete four bytes, in wire order**:
`000FAC04` means OUI `00:0F:AC`, type `04`. Unknown OUIs/types are retained exactly.
Lists use commas: `000FAC02,000FAC08`. Their advertised order is preserved.
They are not inferred negotiated security suites or client security profiles.

Conservative full-record bounds, **including CRLF and excluding NUL**:

| Record | Maximum bytes | Parser buffer including NUL |
|---|---:|---:|
| AP, including vendor variant | 2432 | 2433 |
| Client, including vendor variant | 192 | 193 |

These constants are exported in `sniffer_extended.h`. They include the existing
32-byte SSID and vendor label capped by JanOS at 60 bytes. The AP suffix buffer is
2304 bytes including NUL; the client suffix buffer is 96 bytes including NUL.
The maximum-value fixture currently produces a 1658-byte suffix; the bounds
are deliberately conservative. Formatter capacity failures return an empty
suffix rather than a partial record; production capacities cover all legal data.
UART may map C `\n` to `\r\n`; a reader accepts both.

New SSID/WPS text is **binary**, not assumed UTF-8. SSID is at most 32 bytes.
Decode hex into bytes, keeping embedded NUL, CR/LF, punctuation and arbitrary
octets. A present empty WPS text attribute is `key_hex=`; an omitted attribute is
`key_hex=unknown`. WPS text retains at most 64 bytes per attribute.

The legacy prefix remains raw by compatibility requirement, and can itself
contain delimiters or control bytes from legacy SSIDs/vendor files. A future
Tab5 reader should use the suffix marker and extension fields for identity/name,
not split a legacy SSID on commas or assume it is safe UTF-8. This extension does
not repair arbitrary control bytes already present in legacy output. Fixture
SSID CR/LF and NUL are introduced through discovery, leaving the old prefix empty.

## AP fields (always emitted in this order)

| Key | Values and meaning |
|---|---|
| `ext_ver` | `1` |
| `bssid` | Complete BSSID; stable identity independent of SSID/channel |
| `rssi` | Signed dBm from AP-transmitted radio frames or existing scan RX metadata; `unknown` if only client frames revealed the AP |
| `age_ms` | Unsigned milliseconds since the latest AP observation in extension metadata, or `unknown` if no observation; captures/scans count as observations |
| `hidden` | `1`: complete beacon contained zero-length or all-zero SSID; `0`: complete beacon contained nonhidden SSID; `unknown`: no qualifying beacon |
| `resolved_ssid_hex` | 2–64 hex digits for a discovered nonempty SSID; `unknown` when not discovered |
| `ssid_source` | `beacon`, `probe_resp`, `assoc_req`, `reassoc_req`, `unknown` |
| `profile_source` | `beacon`, `probe_resp`, `unknown`; source of latest advertisement/profile attempt |
| `frame_status` | `unknown`, `valid`, `invalid`; latest advertisement parsing result, including security/WPS body errors |
| `privacy` | `0`, `1`, `unknown`; beacon/probe-response Capability Information privacy bit, independent of RSN/WPA |
| `rsn_status` | `unknown`, `absent`, `valid`, `invalid` |
| `rsn_group` | One complete selector; `unknown` or `absent` |
| `rsn_pairwise` | Comma-separated complete selectors; `unknown` or `absent` |
| `rsn_akm` | Comma-separated complete selectors; `unknown` or `absent` |
| `rsn_group_mgmt` | Encoded group management selector; `unknown` when not encoded; `absent` when RSN IE itself is absent |
| `pmf_capable` | `0`, `1`, `unknown`; RSN capability bit 7 |
| `pmf_required` | `0`, `1`, `unknown`; RSN capability bit 6, independent of capability bit 7 |
| `rsn_truncated` | `1` if pairwise/AKM list exceeded stored capacity, otherwise `0` |
| `wpa_status` | `unknown`, `absent`, `valid`, `invalid`; legacy WPA Vendor IE `00:50:F2:01` |
| `wpa_group` | One complete selector; `unknown` or `absent` |
| `wpa_pairwise` | Comma-separated complete selectors; `unknown` or `absent` |
| `wpa_akm` | Comma-separated complete selectors; `unknown` or `absent` |
| `wpa_truncated` | `1` if a selector list exceeded stored capacity, otherwise `0` |
| `wps_status` | `unknown`, `absent`, `valid`, `invalid`; WPS Vendor IE `00:50:F2:04` |
| `wps_present` | `1` when a complete WPS IE was observed, even if its TLVs are invalid; `0` for confirmed absence; otherwise `unknown` |
| `wps_state` | `1` (not configured), `2` (configured), `unknown` |
| `wps_config_methods` | Decimal unsigned 16-bit bitmask, 0–65535; `unknown` if omitted |
| `wps_setup_locked` | `0`, `1`, `unknown` |
| `wps_selected_registrar` | `0`, `1`, `unknown` |
| `wps_manufacturer_hex` | Manufacturer bytes in hex; `unknown` if omitted/invalid |
| `wps_manufacturer_truncated` | `0` or `1` |
| `wps_model_name_hex` | Model Name bytes in hex; `unknown` if omitted/invalid |
| `wps_model_name_truncated` | `0` or `1` |
| `wps_model_number_hex` | Model Number bytes in hex; `unknown` if omitted/invalid |
| `wps_model_number_truncated` | `0` or `1` |
| `wps_device_name_hex` | Device Name bytes in hex; `unknown` if omitted/invalid |
| `wps_device_name_truncated` | `0` or `1` |
| `wps_truncated` | `1` if any text was shortened or WPS aggregate exceeded parser capacity; otherwise `0` |

## Client fields

| Key | Values and meaning |
|---|---|
| `ext_ver` | `1` |
| `rssi` | Signed dBm from a **client-transmitted** radio frame; `unknown` if client was observed only as the destination of AP frames |
| `age_ms` | Unsigned milliseconds since existing client `last_seen`; either direction counts as a client observation |

AP/client RSSI retains the last applicable transmitter measurement, not an
average. An AP-to-client packet does not overwrite the client's extended RSSI;
a client-to-AP packet does not overwrite the AP's extended RSSI. Legacy internal
RSSI fields retain their earlier behavior and are not printed by old commands.
RSSI measurement age can differ from `age_ms`, which refers to the last record
observation, not specifically to the last RSSI sample.

## Unknown, absence and damaged frames

- `unknown`: no qualifying capture, optional attribute not encoded, or data
  unusable. It never means disabled, false, open, or PIN available.
- `absent`: the IE was missing from a completely bounded beacon/probe response
  with a valid SSID element. Absence of RSN/WPA alone does not prove open security;
  inspect `privacy` too, and keep scan-derived legacy `authmode` separate.
- `valid`: the IE body was parsed successfully. Selector fields omitted by
  permitted trailing defaults remain `unknown`; no selectors are invented.
  Omitted RSN capabilities default to zero, so valid RSN without capability bytes
  has PMF capable/required `0`. Group management default ciphers are not invented.
- `invalid`: damaged/truncated/duplicate IE, unsupported version, malformed
  selector count, or invalid WPS TLV. Its scalar/list values become `unknown`.
  Complete malformed WPS still proves `wps_present=1`.

Missing optional WPS attributes are unknown even when `wps_present=0`. Presence
of WPS neither demonstrates vulnerability nor confirms PIN usability. No WPS
method is attempted. Boolean `unknown` must not be coerced to `false`.

Profiles reflect the **latest advertisement attempt**. A damaged advertisement
sets profile states to `invalid` instead of preserving a misleading apparently
current complete profile; the next complete advertisement restores valid/absent
states. SSID discovery and hidden-beacon evidence are independent and survive a
damaged advertisement. Empty/all-zero hidden beacons never erase a discovered
name. Zero-valued nonempty binary SSIDs in association/reassociation/probe
responses are preserved as bytes, without inferring hiddenness.

## Parser, storage and lifecycle

Management header is 24 bytes. IE offsets are 28 (association request), 34
(reassociation request), 36 (beacon/probe response). Association destination
must equal BSSID and the client transmitter must be a nonzero unicast address
distinct from BSSID. Advertisement transmitter must equal its unicast BSSID.
Fragmented, protected or ordered management frames are not interpreted as these
plain management bodies. Probe requests are stored separately and never used
to infer an AP name. Client-advertised security IEs do not populate AP security.

The public IDF `wifi_promiscuous_pkt_t` API defines payload extent with `sig_len`.
The callback excludes the four FCS bytes from that extent and checks RX success.
If `dump_len` is populated and shorter than `sig_len - 4`, it bounds parsing and
marks the observation incomplete. An unset zero `dump_len` does not mean an empty
payload: parsing uses the public API's `sig_len - 4`. A larger `dump_len`
does not cause rejection or extend this conservative payload bound: a Monster
reported `sig_len=604`, `dump_len=608`, `rx_state=0` for otherwise accepted RX.
Lengths below the header minimum are rejected. The parser checks all header/fixed/body/IE/TLV lengths;
SSID over 32 bytes, duplicate SSIDs/security IEs and invalid WPS attributes are
rejected. WPA/RSN PMKID lengths and optional group management selector are checked.

Limits: 100 APs, 50 clients per AP (existing limits); 8 pairwise and 8 AKM selectors
**per protocol**; four WPS text values of at most 64 bytes each. Excess selector
entries are fully length-validated, then only the first 8 are retained, with
`*_truncated=1`. Multiple WPS IE payloads are concatenated in frame order, allowing
TLVs split across IEs. Aggregate WPS payload limit is 512 bytes: excess becomes
`wps_status=invalid`, `wps_present=1`, `wps_truncated=1`; optional values are unknown.
Truncation markers describe storage limits, not how complete a radio capture was.
The existing AP/client capacity policy (ignore additions when full) is unchanged.

The extension adds no allocation, logging or text formatting in the packet
callback. Legacy packet-based and task-based channel hopping are preserved.
Packet-count announcements are printed by the channel task. A shared mutex guards
AP/client/probe table mutation and reset; the RX task tries it with zero wait and
skips a packet when busy. Result commands allocate a bounded PSRAM snapshot before
locking, copy under the mutex, release it, then sort/format/vendor-lookup/print.
Concurrent capture does not change a snapshot mid-output. Capture may miss frames
during a snapshot copy; passive observation is inherently incomplete.

`stop` preserves records and discovered names. Normal/selected start preserves
records by BSSID. Selected capture preserves legacy behavior: it also continues observing
previously stored BSSIDs on monitored channels. `clear_sniffer_results` resets APs, clients,
probes, profiles and counters; subsequently created records initialize unknown
metadata. Changing an SSID never creates another BSSID entry or discards clients.

Extension AP timestamps use `uint32_t` milliseconds from
`esp_timer_get_time()/1000`, independently of legacy AP `last_seen`.
Scan timestamps seed extension observations.
Snapshot age uses unsigned subtraction, handling counter wrap correctly for
intervals below 2^32 ms (~49.7 days); older ages alias modulo that period. A valid
observation at timestamp zero is not treated as unknown. Stopped captures continue
aging. No OS fingerprint, profile history, deauth/disassoc statistics or client
security analysis is introduced.

## Executable fixtures and verification

Fixture outputs, **synthetic rather than captured from hardware**:

- [`sniffer_extended_uart.txt`](../tests/fixtures/sniffer_extended_uart.txt)
- [`sniffer_extended_vendor_uart.txt`](../tests/fixtures/sniffer_extended_vendor_uart.txt)

Both files contain actual serializer output, one AP plus one client per group.
AP 1: hidden beacon, RSN with two AKMs/two pairwise ciphers (including unknown
OUI/type), PMF optional, then association discovery `HomeA`.
AP 2: hidden beacon with WPS and omitted optional attributes, then reassociation
discovery of binary `Home|B\r\n\x00\xFF`.
AP 3: association only, `HomeC`; hidden/profile/AP RSSI stay unknown.
All old prefixes are empty; the vendor fixture puts `[Fixture Vendor]` before
the suffix. They can be fed directly to a future Tab5 suffix parser.

Run in Linux/WSL with Python 3 and GCC:

```sh
python3 -m unittest discover -s tests -p test_sniffer_extended.py -v
```

Tests compile the **production C parser**, actual production callback, scan/reset/
snapshot helpers and command bodies. Only radio/RTOS/clock/vendor dependencies
are replaced. Parser/callback tests use AddressSanitizer and UBSan. Coverage
includes both PMF modes, legacy WPA, selector limits, WPS fragmentation/limits,
missing optional attributes, wrong transmitter addresses, 32-byte binary SSIDs,
every truncation point of a fixture, 5000 deterministic malformed bodies,
driver-short dumps, selected/normal modes, stop/restart/reset preservation,
snapshot isolation and transmitter RSSI provenance. This is host behavior
verification, not proof of hardware reception, radio scheduling or FreeRTOS timing.

Regenerate fixture UART files:

```sh
gcc -std=c11 -Wall -Wextra -Werror -I main tests/sniffer_extended_test.c main/sniffer_extended.c -o /tmp/janos-sniffer-examples
/tmp/janos-sniffer-examples --examples > tests/fixtures/sniffer_extended_uart.txt
/tmp/janos-sniffer-examples --examples vendor > tests/fixtures/sniffer_extended_vendor_uart.txt
```

## Recorded verification (2026-10-05)

- Windows ESP-IDF **6.0.2**, ESP32-C5: `idf.py build` succeeded (exit 0), including
  production parser/callback compilation and linking. Smallest OTA slot
  `0x3F0000`, approximately 42% free.
- Debian WSL/GCC: `python3 -m unittest discover -s tests -p 'test_*.py' -v`:
  **145 tests passed**, including the six new sniffer tests. C parser and RX
  integration fixtures passed with ASan/UBSan, without sanitizer diagnostics.
- Legacy commands compared as actual output bytes, not merely source inspection
  or an assertion that extension fields are at the end. Vendor and empty-name
  fixtures pass. Full extended examples match the supplied fixture files.
- Independent review findings (invalid association transmitters, short radio
  dump metadata and all-zero binary SSIDs) have regression coverage and fixes.
- The build emits SDK Kconfig notes/default-value notices from the existing
  configuration; it does not emit C compiler errors/warnings for this change.
  No automatic flashing, deployment or Tab5 modification was performed.
- Limits: host doubles do not reproduce FreeRTOS scheduling, actual C5 RX
  delivery or radio performance. Manual hardware acceptance above remains for
  the user, including confirmation of driver length metadata and reception of
  each hidden AP's management frames.

### Diagnosing no clients

After `start_sniffer`, generate client traffic or voluntarily reconnect, then run:

```text
sniffer_debug
stop
show_sniffer_results extended
```

`sniffer_debug` reads a coherent `[SnifferRX]` snapshot, without logging from RX:
`rx`, `mgmt`, `data` count packets processed after taking the table mutex;
`bad_length`, `rx_error`, `selected_reject` count respective rejection causes;
`matched` counts frames assigned to a known/created eligible AP (not unique
clients). `short_dump` counts populated truncated dumps, `zero_dump` counts
unset dump metadata. `lock_busy` counts callbacks skipped due to table contention.
`sig_len`, `dump_len`, `rx_state`, `channel` describe the last processed packet.
`[SnifferCapture] pipeline=legacy-v2` identifies the restored collection pipeline;
`packets` is the shared atomic packet counter, and `aps`/`clients` are actual
stored record counts copied under the table mutex.
`[SnifferSSID]` distinguishes association/reassociation/probe-response reception
(`assoc_rx`, `reassoc_rx`, `probe_resp_rx`) after RX length/state validation.
For requests, `request_rejected` counts parser/header/address rejections;
`request_incomplete` counts accepted headers with incomplete bodies/dumps;
`request_untracked` counts parsed requests with no stored target BSSID;
`request_named` counts complete, nonempty SSID observations applied to a stored
AP, including repeated names. These are global observations, not unique APs. Incomplete and untracked counts
can overlap; they do not partition all received requests.
`[SnifferSSIDLast]` reports the last request BSSID, parser acceptance, completeness,
SSID byte length and that request's `sig_len`/`dump_len`, independently of later
beacons. No request line is printed before the first request observation.
Counters persist across stop/start and reset on `clear_sniffer_results`.
If `rx=0`, check radio/channel/reception. If `selected_reject` grows, confirm the
client's actual BSSID and band against selected scan records. Nonzero `zero_dump`
alone is supported and is no longer grounds to discard a packet.

An initial adapter used `dump_len` as the only payload bound, causing every
packet with `dump_len=0` to be discarded. Regression fixtures now cover unset
dump metadata for both management and encrypted data, while preserving shorter
nonzero dump rejection. This reproduces an adapter bug; device diagnostics are
still necessary to determine whether that bug caused a particular hardware run.

A subsequent Monster log showed `bad_length=969` for `rx=969`, with
`sig_len=604` and `dump_len=608`. Rejecting `dump_len > sig_len` caused this
extension rejection. A regression fixture now executes the production callback
and results command with that exact metadata and synthetic unicast DATA, checking
both the stored client and its extended UART output. This proves the adapter
correction; an empty device client list still needs device validation.

When manually flashing an app image, use the newly compiled
`build/projectZero.bin`, or a copy explicitly verified to be identical in
`binaries-esp32c5/projectZero.bin`.
An older release/bin cannot validate current workspace changes.

## Ręczny test na trzech własnych ukrytych AP

1. Zapisz BSSID, kanał i faktyczny SSID każdego AP A/B/C oraz MAC ich własnych
   klientów. Ustaw ukrywanie SSID. Podłącz klientów i wygeneruj zwykły ruch.
2. Zatrzymaj poprzednią operację i przygotuj listę AP:

   ```text
   stop
   clear_sniffer_results
   scan_networks
   ```

   Poczekaj na `Scan results printed`. Wybierz indeksy odpowiadające **BSSID**, nie
   pustej nazwie; np. jeśli A/B/C mają indeksy 1/3/5:

   ```text
   select_networks 1 3 5
   start_sniffer
   ```

   Ten start korzysta z wyboru bez kolejnego skanu. Sniffer przeskakuje między
   wybranymi kanałami, więc przechwycenie association może wymagać powtórzenia.
3. Sprawdź wszystkie cztery warianty:

   ```text
   show_sniffer_results
   show_sniffer_results_vendor
   show_sniffer_results extended
   show_sniffer_results_vendor extended
   ```

   AP pojawia się dopiero, gdy sniffer wykryje klienta. Stare komendy mają wyłącznie
   stare linie. Extended ma dokładnie te same prefiksy, klienta tuż pod AP, pełny
   `bssid`, RSSI/age i pola statusu. Vendor jest przed ` | ext_ver=1`.
   Dla odebranego ukrytego beacona oczekuj `hidden=1`; bez takiego beacona
   `hidden=unknown`. Brak przechwycenia nazwy to `resolved_ssid_hex=unknown`.
4. Jeśli nazwa pozostaje unknown, **dobrowolnie rozłącz i połącz własnego klienta**
   kolejno z A/B/C, gdy sniffer nasłuchuje ich kanałów. Nie używaj deauth ani
   `start_sniffer_dog`. Po przechwyceniu oczekuj hex właściwej nazwy oraz
   `ssid_source=assoc_req` lub `reassoc_req` (ewentualnie `probe_resp`).
   Dotychczasowy pusty/placeholderowy prefiks zostaje taki sam.
5. Porównaj `bssid` z konfiguracją każdego AP; sprawdź jego klientów po MAC.
   Klient, który sam przełączył się między AP, może być zachowany przy obu AP
   jako historyczna obserwacja — sniffer nie deklaruje aktualnej asocjacji.
   Obce Probe Request nie może zmienić nazwy AP.
6. Poczekaj na kolejne ukryte beacony i ponów extended: nazwa ma przetrwać,
   `hidden=1` ma pozostać. Nieoczekiwane unknown w profilu może oznaczać, że ramki
   nie odebrano, a `invalid` oznacza uszkodzoną/niekompletną próbę odczytu.
   WPS bez atrybutu Setup Locked/Selected Registrar raportuje `unknown`.
7. Sprawdź zachowanie po zatrzymaniu i restarcie:

   ```text
   stop
   show_sniffer_results extended
   start_sniffer
   show_sniffer_results_vendor extended
   stop
   unselect_networks
   start_sniffer_noscan
   show_sniffer_results extended
   stop
   clear_sniffer_results
   show_sniffer_results extended
   ```

   Po stop dane pozostają, a age rośnie. Restart nie dubluje BSSID ani nie kasuje
   klientów/nazwy. Po clear oczekuj komunikatu o braku danych. Ostatni start
   `start_sniffer_noscan` sprawdza tryb zwykły bez kolejnego skanu; jego istniejące
   scalanie danych skanu może historycznie aktualizować stary SSID.

Urządzenie nie jest automatycznie flashowane. Test odbioru sprzętowego wykonuje użytkownik.

## Targeted hidden-SSID device validation

Use the index for a known hidden AP from `show_scan_results`:

```text
stop
scan_networks
show_scan_results
select_networks <hidden_AP_index>
clear_sniffer_results
start_sniffer
sniffer_debug
```

Wait for scan completion before reading/selecting an index. Selecting one AP
keeps monitoring its channel; confirm the channel list contains only that channel.
On your own client, manually disconnect and reconnect to that hidden AP, then:

```text
sniffer_debug
show_sniffer_results extended
```

Success is `hidden=1`, nonunknown `resolved_ssid_hex` and a corresponding
`ssid_source` (`assoc_req`, `reassoc_req` or `probe_resp`). A later hidden beacon
must preserve the name. If request counters stay zero, reception of name-bearing
requests is unconfirmed; DATA/client discovery alone does not reveal the SSID.
If requests increase, rejection/incompleteness/untracked counters and the last
request BSSID identify the next boundary to inspect. A nonzero `request_named`
for another AP does not prove discovery of the selected hidden AP.
The firmware remains passive and never triggers a reconnect or sends discovery.
