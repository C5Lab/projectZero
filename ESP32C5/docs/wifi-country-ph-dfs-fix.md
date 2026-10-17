# Wi-Fi country `PH` and handshake radio compatibility

## Current behavior

JanOS persistently configures `PH` as the default Wi-Fi country profile. The
handshake engine uses the original single radio contract for every channel:

```text
Wi-Fi mode: WIFI_MODE_APSTA
raw TX interface: WIFI_IF_AP
```

The temporary per-channel hybrid that switched DFS channels to STA and sent
through `WIFI_IF_STA` has been removed. It was introduced as a workaround for
DFS channel failures observed with ESP-IDF 6.0.2, but it changed established
handshaker behavior and is not part of the current design. The target runtime
for validating the restored APSTA path is ESP-IDF 6.0.1.

This rollback is intentionally narrow. D-UCB scheduling, protected-BSSID
filtering, channel and mode read-back, promiscuous callback synchronization,
capture serialization and stop cleanup remain in place.

## Persistent `PH` country policy

The default policy record contains:

```text
country: PH
policy: manual
2.4 GHz start channel: 1
2.4 GHz channel count: 14
```

The selected profile is stored in NVS:

```text
namespace: wifi_country
key: profile
```

When the namespace or key is missing, malformed or unreadable, JanOS falls
back to `PH`. For `PH`, JanOS applies an explicit `wifi_country_t` record with
`schan=1`, `nchan=14` and `WIFI_COUNTRY_POLICY_MANUAL`. Other supported country
codes use `esp_wifi_set_country_code()` in manual mode.

## Read-back and lifecycle

After applying a profile JanOS calls `esp_wifi_get_country()` and verifies:

- the two-character country code;
- manual policy mode;
- for `PH`, start channel `1` and channel count `14`.

The configured profile is reapplied after Wi-Fi initialization, after returning
from BLE or IEEE 802.15.4, before starting the handshake engine and after
legacy Wi-Fi reset/reinitialization paths.

## Country CLI

```text
wifi_country status
wifi_country list
wifi_country set <CC>
wifi_country reset
```

`set` and `reset` persist the choice in NVS and apply it after reboot. `reset`
restores `PH`.

## Handshake startup and D-UCB

`start_handshake` performs the following sequence:

1. initialize Wi-Fi if needed;
2. reapply and verify the configured country;
3. establish APSTA mode once;
4. start either selected-target processing or automatic Sniffer + D-UCB;
5. set and read back each requested channel;
6. verify APSTA and the current channel before raw TX;
7. send targeted frames through `WIFI_IF_AP` only.

Automatic D-UCB no longer transitions between STA and APSTA as the selected
channel changes. A channel that the active ESP-IDF/driver combination rejects
is treated as an unavailable arm: it receives zero reward and no frame is
transmitted. This prevents a failed channel switch from causing TX on a stale
channel.

The country selection does not bypass hardware, driver or local regulatory
restrictions. DFS behavior must be validated on the exact ESP-IDF version and
hardware used by the firmware.

## Version note

This document records the handshaker rollback only. The production WPS
transport currently retains its separate compile-time ESP-IDF 6.0.1 guard.
Changing that WPS compatibility boundary is a distinct task and is not implied
by selecting ESP-IDF 6.0.1 for handshaker validation.

## Relevant implementation files

- `main/wifi_country_policy.c` and `main/wifi_country_policy.h` — country
  profile validation and serialization;
- `main/main.c` — NVS storage, CLI, Wi-Fi lifecycle, APSTA setup, D-UCB and
  targeted raw TX;
- `main/handshake_tx_telemetry.c` — atomic per-run deauthentication TX-completion
  counters reported after callback unregistration;
- `main/attack_handshake.c` — selected-target capture and AP-interface TX;
- `tests/wifi_country_policy_test.c` — country-policy unit tests;
- `tests/test_wifi_analyzer_integration.py` — integration invariants for the
  single APSTA handshake path;
- `tests/test_handshake_tx_telemetry.py` — portable counter reset and result
  classification test;
- `docs/command-manual.md` — public CLI reference.
