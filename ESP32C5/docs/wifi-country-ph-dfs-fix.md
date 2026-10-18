# Wi-Fi country `PA` and handshake radio compatibility

## Current behavior

JanOS persistently configures `PA` as the default Wi-Fi country profile. The
handshake engine uses the original single radio contract for every channel:

```text
Wi-Fi mode: WIFI_MODE_APSTA
raw TX interface: WIFI_IF_AP
```

The temporary per-channel hybrid that switched DFS channels to STA and sent
through `WIFI_IF_STA` has been removed. It was introduced as a workaround for
DFS channel failures observed with ESP-IDF 6.0.2, but it changed established
handshaker behavior and is not part of the current design. That 6.0.1 rollback
observation is historical. The private WPS adapter is verified for ESP-IDF
6.0.0 and 6.0.1; later patches remain rejected by its build guard.

This rollback is intentionally narrow. D-UCB scheduling, protected-BSSID
filtering, channel and mode read-back, promiscuous callback synchronization,
capture serialization and stop cleanup remain in place.

## Persistent `PA` country policy

The default policy record contains:

```text
country: PA
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
back to `PA`. For `PA`, JanOS applies an explicit `wifi_country_t` record with
`schan=1`, `nchan=14` and `WIFI_COUNTRY_POLICY_MANUAL`. Other supported country
codes use `esp_wifi_set_country_code()` in manual mode. JanOS accepts all 176
profiles from the ESP-IDF 6.0 ESP32-C5 regulatory table, including territories,
`EU` and the world-safe profile `01`. The complete list is available through
`wifi_country list`.

### `RU` profile in ESP-IDF 6.0.0

`RU` is already one of those 176 profiles; it is not a JanOS extension or an
alias. JanOS normalizes `ru` to `RU`, stores the three-byte policy record
`{version, 'R', 'U'}`, and applies it through the ordinary
`esp_wifi_set_country_code("RU", false)` path after reboot.

For the ESP32-C5 regulatory table shipped by the pinned ESP-IDF 6.0.0 source,
the `RU` entry covers:

- 2.4 GHz channels 1–13;
- 5 GHz channels 36–64;
- 5 GHz channels 132–165.

It does **not** provide one continuous 5 GHz range: channels 100–128 are absent
from that profile. The table does not mark the two listed 5 GHz ranges as DFS,
but selecting `RU` still does not override ESP32-C5 hardware/driver constraints,
permit an independent SoftAP on a DFS channel, or make a channel legal at the
device's actual location. Treat the selected country as a regulatory input to
the driver, not as a DFS bypass.

## Read-back and lifecycle

After applying a profile JanOS calls `esp_wifi_get_country()` and verifies:

- the two-character country code;
- manual policy mode;
- for `PA`, start channel `1` and channel count `14`.

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
restores `PA`.

Example for the existing Russian profile:

```text
wifi_country set ru
# reboot the board
wifi_country status
```

After reboot, `status` should report both `configured_cc` and `active_cc` as
`RU`, with `active_policy` equal to `manual`. The active channel fields are the
driver read-back and remain the source of truth for that exact image and board.

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

The production WPS transport and current root-firmware validation are pinned to
ESP-IDF 6.0.0. Older 6.0.1/6.0.2 handshaker observations explain why the
temporary hybrid was removed; they are not active build instructions. Country
selection cannot override hardware, regulatory or driver channel rejection, so
DFS remains a target test for the exact guarded image.

## Relevant implementation files

- `main/wifi_country_policy.c` and `main/wifi_country_policy.h` — country
  profile validation and serialization;
- `main/wifi_country_driver.c` and `main/wifi_country_driver.h` — application
  through ESP-IDF plus manual-policy read-back verification;
- `main/main.c` — NVS storage, CLI, Wi-Fi lifecycle, APSTA setup, D-UCB and
  targeted raw TX;
- `main/handshake_tx_telemetry.c` — atomic per-run deauthentication TX-completion
  counters reported after callback unregistration;
- `main/attack_handshake.c` — selected-target capture and AP-interface TX;
- `tests/wifi_country_policy_test.c` — country-policy unit tests;
- `tests/wifi_country_driver_test.c` — portable PA/RU driver-boundary tests;
- `tests/test_wifi_analyzer_integration.py` — integration invariants for the
  single APSTA handshake path;
- `tests/test_handshake_tx_telemetry.py` — portable counter reset and result
  classification test;
- `docs/command-manual.md` — public CLI reference.
