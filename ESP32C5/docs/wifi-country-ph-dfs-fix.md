# Wi-Fi country `PH` and DFS handshake fix

## Summary

The fix has two separate parts:

1. JanOS persistently configures `PH` as the default Wi-Fi country profile.
2. The handshake engine uses a hybrid radio path because selecting `PH` alone
   does not remove the ESP-IDF restriction on DFS channels in AP/APSTA mode.

The working channel-100 path therefore comes from switching the handshake
engine to STA mode on DFS channels, not from bypassing DFS through the country
setting.

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

When the NVS namespace or key is missing, the stored record is malformed, or
the record cannot be read, JanOS falls back to `PH` rather than silently using
an unknown driver default.

For `PH`, JanOS applies an explicit `wifi_country_t` record through
`esp_wifi_set_country()`:

```c
wifi_country_t country = {
    .cc = "PH",
    .schan = 1,
    .nchan = 14,
    .policy = WIFI_COUNTRY_POLICY_MANUAL,
};
```

Other supported country codes use `esp_wifi_set_country_code()` in manual
mode.

## Read-back validation

Setting the country is not treated as sufficient proof that the driver
accepted it. JanOS immediately calls `esp_wifi_get_country()` and verifies:

- the two-character country code;
- manual policy mode;
- for `PH`, start channel `1` and channel count `14`.

A mismatch returns an error. This prevents startup or handshake processing
from continuing under a different regulatory configuration than the one
reported by JanOS.

## Reapplying the policy after Wi-Fi initialization

ESP-IDF can lose runtime country configuration after a Wi-Fi deinitialization
and subsequent initialization. JanOS therefore uses the following sequence:

```text
esp_wifi_init()
    -> apply configured country
    -> read back and validate country
    -> continue Wi-Fi startup
```

The configured profile is reapplied:

- during the central Wi-Fi initialization path;
- after switching back to Wi-Fi from BLE or IEEE 802.15.4;
- before starting the handshake engine;
- after legacy Wi-Fi reset/reinitialization paths.

This makes the setting global to JanOS Wi-Fi lifecycles rather than a one-time
handshake-only assignment.

## Country CLI

The production CLI provides:

```text
wifi_country status
wifi_country list
wifi_country set <CC>
wifi_country reset
```

Behavior:

- `status` reports the configured profile and, if Wi-Fi is active, the value
  read back from the driver;
- `list` reports the accepted two-character profiles;
- `set <CC>` validates, normalizes and persists a profile in NVS;
- `reset` persists the default `PH` profile;
- changes made by `set` or `reset` apply after reboot.

Example:

```text
wifi_country set PH
reboot
wifi_country status
```

## Why `PH` alone did not fix DFS

The earlier handshake implementation always selected APSTA mode and injected
frames through `WIFI_IF_AP`. ESP-IDF rejects DFS channel selection while an AP
interface is active, producing errors such as:

```text
Set channel to a DFS channel is not allowed in ap mode
```

Changing the country code does not remove this AP/APSTA restriction. The
handshake engine therefore needs a separate radio-mode policy.

## Hybrid handshake radio policy

JanOS classifies channels into two paths:

| Channel class | Channels | Wi-Fi mode | TX interface |
| --- | --- | --- | --- |
| Non-DFS | all channels outside the DFS ranges below | `WIFI_MODE_APSTA` | `WIFI_IF_AP` |
| DFS | `52-64`, `100-144` | `WIFI_MODE_STA` | `WIFI_IF_STA` |

This policy is used by both handshake workflows:

- explicitly selected target networks;
- automatic `start_handshake` Sniffer + D-UCB operation.

For every automatic D-UCB arm, JanOS:

1. chooses APSTA/AP or STA/STA from the channel number;
2. changes mode when necessary;
3. sets the requested channel;
4. reads back and verifies the active mode and channel;
5. rearms promiscuous capture after a mode transition;
6. transmits only when the selected arm is ready.

If raw transmission is rejected on a DFS target, the explicit-target workflow
can continue as passive capture and emits one fallback warning instead of
repeating driver errors.

## Result

The final behavior is:

```text
PH policy
    -> persistent and reapplied after Wi-Fi initialization
    -> manual channels 1-14 for 2.4 GHz
    -> verified through driver read-back

non-DFS handshake target
    -> APSTA mode
    -> WIFI_IF_AP transmission

DFS handshake target
    -> STA mode
    -> WIFI_IF_STA transmission
    -> passive fallback when raw TX is unavailable
```

The `PH` policy provides a deterministic country configuration, while the
hybrid STA/APSTA implementation is what resolves the ESP-IDF AP-mode problem
on DFS channels such as channel 100. Neither mechanism bypasses hardware,
driver or local regulatory restrictions.

## Relevant implementation files

- `main/wifi_country_policy.c` and `main/wifi_country_policy.h` — portable
  country-profile validation and serialization;
- `main/main.c` — NVS storage, application, read-back, CLI and Wi-Fi lifecycle
  integration;
- `main/handshake_radio_policy.c` and `main/handshake_radio_policy.h` — DFS
  classification and radio-path selection;
- `tests/wifi_country_policy_test.c` — country-policy unit tests;
- `tests/handshake_radio_policy_test.c` — DFS/non-DFS path tests;
- `tests/test_wifi_analyzer_integration.py` — JanOS integration and CLI checks;
- `docs/command-manual.md` — public CLI reference.

