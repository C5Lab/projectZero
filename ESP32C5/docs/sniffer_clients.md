# Opt-in sniffer identity API (schema version 1)

All existing command text, arguments and result formats are unchanged, including
plain, vendor and extended sniffer output. New consumers use separate commands.
Names/channels below are sidecar metadata; generated legacy labels are never
reported as real SSIDs. This API requires updated JanOS and does not negotiate a
fallback to SSID matching.

## show_sniffer_clients

No arguments. A coherent snapshot is emitted as flat JSON Lines:

```json
{"schema_version":1,"record_type":"sniffer_clients_begin","aps":1,"clients":1}
{"schema_version":1,"record_type":"sniffer_ap","bssid":"02:00:00:00:00:01","channel":6,"ssid_hex":"5061646479735456","ssid_source":"scan"}
{"schema_version":1,"record_type":"sniffer_client","bssid":"02:00:00:00:00:01","station":"04:00:00:00:00:02"}
{"schema_version":1,"record_type":"sniffer_clients_end","aps":1,"clients":1}
```

APs with clients are listed in database order, followed by their clients. Limits
are 100 APs / 50 clients per AP (5000 total). Count fields describe emitted
records, excluding own/broadcast APs. Every JSON line is under 1024 bytes.
Receivers must ignore console echo, prompts and unrelated radio logs, validate
counts and wait for end before enabling a target. A missing end is an incomplete
snapshot, not an empty successful list. A tick between records lets receivers
drain UART. Maximum list transfer may take over a minute at 115200 baud.

SSID is up to 32 arbitrary bytes encoded as hex, never raw JSON text. Empty hex
means unavailable. Sources: `beacon`, `probe_response`, `association`,
`reassociation`, `scan`, `none`. Complete received SSIDs take precedence over
cached scan SSIDs. Hidden/empty or malformed frames never erase a resolved name.
Generated `Unknown_...` / `MGMT_...` legacy labels do not enter the scan-name
sidecar. A genuine scanned SSID with either prefix is still a genuine name.
Channel is the latest receiver channel or cached scan channel; zero means unknown.

Errors have `record_type=sniffer_clients`, `status=error` and `reason`.

## start_deauth_station <BSSID> <station MAC>

Looks up the exact pair in the sniffer database, validates its channel and own
addresses before stopping active operations. Does not require scan results,
change network/station selections, or insert fake scan records. Uses a dedicated
target in the existing deauth worker and the existing raw-frame sender; legacy
broadcast/CSA branches are never entered by this command.

```json
{"schema_version":1,"record_type":"station_deauth","status":"started","bssid":"02:00:00:00:00:01","station":"04:00:00:00:00:02"}
{"schema_version":1,"record_type":"station_deauth","status":"error","reason":"client_not_found"}
```

Other reasons: `invalid_arguments`, `not_ready`, `channel_unknown`,
`invalid_target`, `stop_failed`, `radio_error`, `channel_unavailable`, `no_memory`.
The ordinary console admission layer may also reject a command as busy before
its handler executes. Clients must handle missing acceptance and send `stop` on
cancel/timeout. A successful acknowledgement confirms a running worker, not that
the station disconnected (e.g. PMF can prevent disconnection).

`stop` stops this mode too. Existing stop output is unchanged. Every five minutes,
this mode checks the target BSSID passively across supported channels, without
running a scan or overwriting the legacy scan cache. If not heard, it retains the
last known channel. Radio restrictions still apply.

## Verification

Run `python3 -m unittest discover -s tests -p 'test_sniffer*.py'`.
The tests replay frozen legacy output/capture fixtures, check unchanged legacy
command bodies, and execute the new command handlers against radio doubles.
Hardware confirmation with an older client and on both bands remains necessary.
