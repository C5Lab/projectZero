# JanOS Capture Gateway

> **Product name:** JanOS GITM — **Gate-in-the-Middle**, an instrumented
> APSTA/NAPT gateway for authorized traffic analysis.
>
> **Technical feature name:** JanOS Capture Gateway (`capture_gateway`, `[CGW]`).
>
> **Status:** Phase 1 foundation plus the first Phase 3 client-inventory slice;
> the fixed 4096 kbps single-client path is hardware-validated with zero drops.
> Multi-client isolation and the remaining acceptance matrix are still pending.
>
> **Scope:** networks and client devices owned by the operator or tested with
> explicit authorization.

## 1. Purpose

JanOS Capture Gateway turns the ESP32-C5 into the actual IPv4 gateway for test
clients. A client joins a dedicated JanOS SoftAP, receives its address and
default route from JanOS, and reaches the Internet through the JanOS STA
connection and lwIP NAPT. JanOS records traffic on the downstream AP interface
before address translation, preserving the original client address in PCAP.

This complements ARP-spoof MITM rather than replacing it. Capture Gateway is the
controlled path for clients deliberately joined to the JanOS SSID. The existing
`start_pcap net` mode remains useful for inventorying traffic already present in
an organization (for example printers, computers and IoT devices sending clear
HTTP/JSON), although it is a best-effort laboratory mode and cannot guarantee
that another access point will deliver every client's traffic to JanOS.

```text
authorized test client
        |
        | dedicated Wi-Fi SSID
        v
JanOS SoftAP: 10.42.0.1/24
        |
        | AP netif hooks, both directions
        v
adaptive aggregate limiter (ceiling: 4096 kbps)
        |
        +----> downstream PCAP queue -> writer -> SD card
        |
        v
IPv4 routing + NAPT
        |
        v
JanOS STA -> upstream AP/router -> Internet
```

## 2. Terminology and guarantees

The feature is a routed **capture gateway**, not an HTTP/SOCKS proxy and not a
transparent TLS proxy. The realistic guarantee is:

> Capture all routed IPv4 packets observed by the JanOS downstream SoftAP netif
> for clients in `10.42.0.0/24` (src or dst in that subnet), while reporting
> every known recorder drop. DNS for SoftAP clients is proxied through
> `10.42.0.1` so upstream LAN resolvers are not SoftAP peers.

It does not promise every RF frame, traffic from clients attached to another
AP, decrypted HTTPS/QUIC/VPN content, or mathematically zero packet loss. A
capture with a non-zero drop counter is explicitly degraded.

## 3. Operator flow

Phase 1 deliberately reuses the existing, tested STA credential path:

```text
wifi_connect <upstream_ssid> <password|--saved>
capture_gateway start <capture_ssid> [capture_password] [--pcap-name <name>]
capture_gateway status
stop
```

### 3.0. Rogue lure + GITM (`start_rogue_gitm`)

When the SoftAP should mirror a known WPA2 SSID/password and optionally deauth
selected APs onto that mirror (instead of a captive portal), use:

```text
wifi_connect <upstream_ssid> <password|--saved>   # Internet uplink — NOT the deauth victim BSSID
scan_networks
select_networks <indices...>   # victim AP(s); same channel as STA; must not be the STA uplink BSSID
start_rogue_gitm <mirror_ssid> <mirror_password> [--pcap-name <name>]
capture_gateway status
stop
```

Happy path example: STA on `MYUPSTREAMWIFI`, deauth/select `TARGETWIFI` on the
same channel, SoftAP mirror named `TARGETWIFI`. Clients on the SoftAP get NAPT
Internet from the upstream STA. PCAP hooks only the SoftAP (`10.42.0.1` pre-NAT);
there is no ARP-spoof on the upstream LAN, so other `MYUPSTREAMWIFI` clients are
not recorded.

DHCP advertises DNS as `10.42.0.1`. JanOS runs a SoftAP DNS proxy that forwards
queries to the real upstream resolver over the STA path (outside the SoftAP PCAP
hook). Clients therefore talk DNS to `10.42.0.1`, not to `192.168.x.1` on the
upstream LAN. Gateway PCAP additionally filters to IPv4 frames where src or dst
is in `10.42.0.0/24`. Analyzer rows for upstream routers as DNS peers, or for
IPs that appear only inside DNS/mDNS payloads (e.g. `192.168.0.x` from a phone's
previous network), are expected noise from content decoding — not evidence of
upstream ARP MITM.

Status reports `dns=10.42.0.1`, `dns_proxy=on`, `upstream_dns=<resolver>`, and
`pcap_scope=softap_10_42` with `filter_drops`.

This command requires the same upstream STA IPv4 prerequisite as
`capture_gateway start`. It does **not** use `select_html` or a captive portal:
it starts the Capture Gateway session (SoftAP + NAPT + adaptive PCAP) and, when
networks are selected, runs same-channel deauth beside it without channel
hopping (STA+SoftAP stay parked). Cross-channel targets and selecting the
current STA uplink BSSID are refused before any SoftAP is created. Status and
stop remain the standard GITM contract (`[CGW]` / universal `stop`). Classic
`start_rogueap` (portal) is unchanged.

Omit `capture_password` to create an open capture SSID:

```text
capture_gateway start JanOS-Capture
```

Supply an 8-63 byte password to create a WPA2-PSK capture SSID:

```text
capture_gateway start JanOS-Capture correct-horse-battery-staple
```

Tab5 may provide the complete capture basename with a custom prefix and its own
date/time stamp:

```text
capture_gateway start JanOS-Capture --pcap-name office_20260812_143000
capture_gateway start JanOS-Capture correct-horse-battery-staple --pcap-name office_20260812_143000.pcap
```

The `.pcap` extension is appended when omitted. The name may contain ASCII
letters, digits, `.`, `_` and `-`, up to 95 characters including the extension.
It is always stored below `/sdcard/lab/pcaps`; path separators, leading dots and
other characters are rejected. An existing file is never overwritten: startup
fails and rolls the gateway back. Without `--pcap-name`, JanOS retains the
automatic `sniff_N.pcap` naming scheme.

Capture Gateway always applies a firmware-fixed aggregate ceiling of 4096 kbps
before forwarding packets. It counts IP packet bytes shared by both directions
and all downstream clients. This is a ceiling, not a guaranteed fixed rate. An
adaptive token bucket monitors the PCAP queue: below 50% it permits 4096 kbps, at
50% it halves the rate, at 75% it uses one quarter, and at 90% it pauses until
the queue returns to 50%. It is not a per-client quota and actual application
throughput will be lower because Wi-Fi/TCP overhead is not part of the ceiling.
The controller does not send a rate parameter. A full limiter queue is reported
separately as `rate_queue_drops` and must not be confused with recorder failures.

`capture_gateway start` is intentionally a single **start-and-forget** command.
It starts NAPT and arms the downstream PCAP recorder before printing the ready
status. It does not wait for a client. Client A may join immediately, client B
may join later, and either may disconnect without changing the recorder
lifecycle. The compatibility command `start_pcap gateway` is idempotent while
this automatically started recorder is active.

Requirements:

- the STA must already be associated and have a non-zero IPv4 address;
- capture SSID length is 1-32 bytes;
- an omitted password creates an open network; a supplied password must be
  8-63 bytes and creates a WPA2-PSK network;
- the downstream network is fixed to `10.42.0.0/24` in Phase 1;
- gateway start fails if the upstream subnet contains `10.42.0.1`, preventing
  an ambiguous route caused by overlapping upstream/downstream addressing;
- the AP channel follows the associated upstream AP because ESP32-C5 uses one
  physical Wi-Fi radio;
- the fixed adaptive 4096 kbps ceiling is aggregate across every client and both directions;
- `stop` finalizes PCAP before disabling NAPT and resetting Wi-Fi.

The universal `stop` command first restores the hooks so no new packets enter
the limiter, drains already accepted limiter packets with recorder backpressure,
drains the writer and only then removes the gateway. `capture_gateway stop`
refuses while its automatically
started recorder is active so the AP cannot disappear underneath a live hook.

### 3.1. Runtime sequence

1. `wifi_connect` establishes the STA uplink and obtains its IPv4 configuration.
2. One `capture_gateway start` command creates the open or WPA2 downstream AP,
   configures DHCP, DNS and NAPT, starts the limiter and arms the PCAP writer.
3. Only after every required part is ready does JanOS return
   `active=1 capture=active`. No client needs to be present at startup.
4. Any authorized client joining later receives a `10.42.0.x` address. Its
   upload and download packets pass through the AP hooks and the shared adaptive
   limiter. The normal ceiling is 4096 kbps for all clients combined.
5. The limiter task records the downstream-side packet, preserving the client
   address, and forwards it through routing/NAPT. Recorder pressure can reduce
   the effective ceiling or briefly pause forwarding instead of overrunning the
   SD writer.
6. `capture_gateway status` provides a bounded snapshot of gateway, clients,
   recorder, limiter and file-size state. Joining or leaving a client does not
   start or stop the capture.
7. Universal `stop` closes packet admission, drains accepted work, finalizes the
   PCAP, emits `[PCAP_FINAL]`, stops the gateway and finally resets Wi-Fi.

## 4. Phase 1 implementation

### 4.1. Dedicated component

`components/capture_gateway` owns:

- validation and configuration of the dedicated open or WPA2 SoftAP;
- downstream address `10.42.0.1/24` and DHCP server lifecycle;
- propagation of upstream DNS via a SoftAP DNS proxy (DHCP advertises `10.42.0.1`);
- default-route selection on the STA netif;
- `esp_netif_napt_enable()` / `esp_netif_napt_disable()` lifecycle;
- active/upstream/client status without storing either Wi-Fi password;
- refresh after STA reconnect or DHCP address renewal.

The component receives already-created AP and STA netif handles. It does not
initialize/deinitialize the Wi-Fi driver and does not write PCAP files.

### 4.2. Main integration

`main.c` owns:

- ensuring APSTA mode without duplicating STA credential handling;
- CLI commands and machine-readable `[CGW]` status lines;
- STA reconnect and AP client event forwarding;
- mutual exclusion with destructive Wi-Fi mode changes;
- downstream PCAP hooks and safe restoration of the exact hooked netif.

The recorder started by `capture_gateway start` uses classic PCAP linktype 1 and
hooks `WIFI_AP_DEF`:

- AP `input`: client-to-Internet packets before NAPT;
- AP `linkoutput`: reverse-NAPT Internet-to-client packets;
- no ARP poisoning;
- no second capture on the STA side, avoiding pre-/post-NAT duplicates.

The recorder copies frames preferentially into PSRAM, buffers up to 1024 frame
pointers, gives its writer a higher task priority and uses a 64 KiB stdio buffer
with explicit flush every 512 records. This absorbs short bursts substantially
better than the earlier 256-frame queue with a flush every 50 records. It still
uses one allocation per frame; Phase 2 retains a fixed-pool improvement.

`capture_gateway status` also reports `security=open|wpa2`, recorder state,
filename, `packets`, split recorder drop causes, queue depth/high-water, the
current serialized PCAP size as `file_bytes`, rate-limiter health, and one
`[CGW_CLIENT]` line with MAC and DHCP address for every client
currently associated with the SoftAP. This is live inventory, not a historical
list: after A disconnects its line disappears while B remains listed and the
global recorder remains active. Until isolation is implemented and verified,
the machine-readable status explicitly reports `client_isolation=off`.

### 4.3. Configuration

Phase 1 enables:

```text
CONFIG_LWIP_IP_FORWARD=y
CONFIG_LWIP_IPV4_NAPT=y
```

NAPT is enabled only on the downstream AP netif. The STA netif remains the
default upstream route.

## 5. Failure behavior

- Failure to obtain upstream IPv4 prevents gateway start.
- AP/DHCP/DNS/NAPT configuration is transactional: a failed start does not
  report the gateway as active.
- STA loss marks `upstream=down`; clients stay associated while JanOS attempts
  to reconnect using the existing STA configuration.
- A new STA address refreshes the default route and downstream DNS.
- Gateway stop refuses to run while its PCAP hook is active.
- Universal `stop` first restores PCAP hooks and drains the writer, then disables
  NAPT/DHCP and resets Wi-Fi.

## 6. Known Phase 1 limitations

- IPv4 only. IPv6 forwarding and router advertisements are not enabled.
- One radio means downstream and upstream share a channel and airtime. Every
  routed byte is received and transmitted, reducing throughput.
- The PCAP path still allocates once per frame (PSRAM preferred) and both the
  recorder and optional rate-limiter queues have finite depth.
- Traffic switched directly between SoftAP clients is not yet claimed as
  complete capture evidence.
- Client isolation is not yet implemented. The current ESP-IDF 6.0.1 build does not expose a
  public SoftAP client-isolation switch for this target, so isolation must not
  be inferred merely from having separate DHCP leases; it needs an explicit
  implementation and a two-client L2/L3 hardware test.
- TLS, QUIC, SSH and VPN payloads remain encrypted.
- AP netif hooking uses the existing lwIP integration approach and must be
  revalidated after ESP-IDF upgrades.

## 7. Hardening roadmap

### Phase 2 — recorder integrity

- fixed PSRAM frame pool instead of `malloc` per packet;
- total input-attempt/captured counters and a persistent degraded flag/manifest;
- `.part` file, explicit sync, atomic final rename and session manifest;
- size/time rotation and SD free-space guard;
- controlled recovery after upstream loss and power interruption.

### Phase 3 — multi-client operations

- current client inventory with MAC and DHCP address (**implemented**);
- hostname and per-client packet/byte/drop counters;
- per-client capture selection and limits;
- verified client isolation policy;
- Tab5 controls for start/status/stop, live counters and PCAP transfer;
- optional configurable downstream subnet and DNS policy.

### Phase 4 — performance and alternate uplink

- TCP/UDP throughput and latency envelope with capture on/off;
- slow/full SD and queue-saturation tests;
- Ethernet or second independent Wi-Fi uplink for higher reliability;
- explicit IPv6 design using routing, RA/NDP and firewall policy.

## 8. Integration contract for Tab5, Cardputer ADV and other controllers

This section defines the controller-facing contract. A controller should treat
JanOS as a line-oriented command device and should not reproduce the gateway or
PCAP logic locally. The controller owns forms, validation, date/time-based name
generation, progress presentation and subsequent file transfer. JanOS owns the
SoftAP, NAPT, capture lifecycle and the PCAP stored on its SD card.

### 8.1. Transport and command framing

- Transport is the existing JanOS console over UART or USB serial: 115200 baud,
  8 data bits, no parity, 1 stop bit for a raw UART connection.
- Send one UTF-8 command at a time terminated with `\r\n`.
- Accumulate received bytes into lines. A UART read is not guaranteed to contain
  one complete line and may contain several lines.
- Treat both `\r` and `\n` as line terminators and ignore empty lines.
- Serialize commands through one transport task. Do not let a status timer write
  to UART while a start, stop or file-transfer command is in progress.
- Arguments containing spaces must be surrounded with double quotes. Inside a
  quoted argument, escape `"` as `\"` and `\` as `\\`. Never allow CR or LF
  from a UI field to reach the command stream.

Example with an SSID containing a space:

```text
capture_gateway start "JanOS Lab" "eight char password" --pcap-name office_20260812_143000
```

The machine-readable response consists only of lines beginning with `[CGW]` or
`[CGW_CLIENT]`. ESP-IDF logs and human-readable JanOS messages may appear before,
after or between them. Integrations must ignore those unrelated lines.

### 8.2. Controller inputs

The minimum input model is:

| Field | Required | Validation | Sent to JanOS |
|---|---:|---|---|
| Upstream SSID | yes, unless already connected | valid Wi-Fi SSID | `wifi_connect` |
| Upstream password | depends on upstream | existing `wifi_connect` rules | `wifi_connect` |
| Capture SSID | yes | 1-32 bytes | first argument after `start` |
| Capture security | yes | `open` or `wpa2` | omit or include password |
| Capture password | WPA2 only | 8-63 bytes | optional positional argument |
| Custom prefix | optional | normalize to `[A-Za-z0-9._-]` | part of `--pcap-name` |
| Capture timestamp | recommended | controller clock | part of `--pcap-name` |

Tab5/ADV should generate the timestamp because the UI device normally has the
better real-time clock. A recommended basename is:

```text
<sanitized-prefix>_YYYYMMDD_HHMMSS
```

For example, prefix `iot-lab` at 2026-08-12 14:30:00 becomes
`iot-lab_20260812_143000.pcap`. Decide in the controller whether this represents
UTC or local time and label it consistently in the UI. JanOS does not interpret
the timestamp. If a name collision is reported, ask the operator for another
name or retry with a deterministic suffix such as `_01`; never silently replace
the earlier capture.

Supported start inputs are:

```text
# Open capture SSID, automatic filename
capture_gateway start <capture_ssid>

# WPA2 capture SSID, automatic filename
capture_gateway start <capture_ssid> <capture_password>

# Open capture SSID, controller-provided filename
capture_gateway start <capture_ssid> --pcap-name <basename>

# WPA2 capture SSID, controller-provided filename
capture_gateway start <capture_ssid> <capture_password> --pcap-name <basename>
```

Tab5/ADV must not expose or send a rate-limit input. JanOS owns the fixed 4096
kbps ceiling and its adaptive reductions; the controller only displays the
reported `rate_limit_kbps` and `rate_effective_kbps` values.

Do not send `start_pcap gateway` after a successful start. Gateway start already
arms the recorder before returning its status block.

### 8.3. Status request and response boundary

Input:

```text
capture_gateway status
```

Collect `[CGW]` and `[CGW_CLIENT]` lines until the exact line `[CGW] END`. Apply
the new snapshot to the UI only after this terminator arrives; this prevents a
partly received response from erasing an existing client list.

An active example is:

```text
[CGW] status active=1 upstream=1 napt=1 clients=2 channel=6
[CGW] ssid=JanOS Lab security=open upstream_ssid=Office WiFi
[CGW] ap_ip=10.42.0.1 sta_ip=192.168.1.27 dns=10.42.0.1 dns_proxy=on upstream_dns=192.168.1.1
[CGW] capture=active file=/sdcard/lab/pcaps/iot-lab_20260812_143000.pcap packets=18742 frames=18742 drops=0 file_bytes=9238164
[CGW] recorder drop_alloc=0 drop_queue=0 drop_write=0 queue_depth=3 queue_capacity=1024 queue_high_water=41
[CGW] rate_limit_kbps=4096 rate_effective_kbps=2048 adaptive=on throttle_events=3 pause_events=0 rate_queue_depth=27 rate_queue_capacity=1024 rate_queue_drops=0 rate_queue_high_water=545
[CGW] client_isolation=off
[CGW_CLIENT] mac=02:11:22:33:44:55 ip=10.42.0.2
[CGW_CLIENT] mac=02:AA:BB:CC:DD:EE ip=10.42.0.3
[CGW] END
```

An idle response is deliberately short:

```text
[CGW] status active=0
[CGW] END
```

Absence of an active-only field in an idle response means “not applicable”, not
zero. Clear the active session model when the complete idle block is received.

### 8.4. Output fields

| Field | Type and meaning |
|---|---|
| `active` | `0` or `1`; authoritative gateway lifecycle state |
| `upstream` | `0` or `1`; upstream STA currently has usable IPv4/DNS state |
| `napt` | `0` or `1`; IPv4 translation enabled on the downstream AP |
| `clients` | associated SoftAP client count at status-snapshot time |
| `channel` | shared APSTA Wi-Fi channel |
| `ssid` | capture SSID; may contain spaces |
| `security` | `open` or `wpa2` |
| `upstream_ssid` | current upstream SSID; may contain spaces |
| `ap_ip` | downstream gateway address, currently `10.42.0.1` |
| `sta_ip` | JanOS address on the upstream network |
| `dns` | DNS address advertised to SoftAP clients; normally `10.42.0.1` |
| `dns_proxy` | `on` when the SoftAP DNS forwarder is running |
| `upstream_dns` | real upstream resolver used by the DNS proxy |
| `capture` | `active` or `inactive` recorder state |
| `file` | full remote path on the JanOS SD card |
| `packets` | successfully serialized PCAP packet records (`uint32_t`) |
| `frames` | compatibility alias of `packets`; new code should use `packets` |
| `drops` | sum of known recorder allocation, recorder queue and writer failures (`uint32_t`) |
| `file_bytes` | logical serialized PCAP bytes, including the 24-byte header (`uint64_t`) |
| `drop_alloc` | packet-copy allocation failures; packets absent from PCAP |
| `drop_queue` | full recorder queue failures; packets absent from PCAP |
| `drop_write` | short PCAP record/header writes |
| `queue_depth` | recorder packets waiting for the writer at snapshot time |
| `queue_capacity` | recorder queue capacity, currently 1024 packets |
| `queue_high_water` | maximum recorder queue depth during this capture |
| `rate_limit_kbps` | firmware-fixed aggregate gateway ceiling; currently always `4096` while active |
| `rate_effective_kbps` | current adaptive ceiling; can be lower than `rate_limit_kbps`, and `0` during a protective pause |
| `adaptive` | currently always `on` for an active Capture Gateway |
| `throttle_events` | transitions to a lower non-zero rate caused by recorder pressure |
| `pause_events` | entries into the protective pause above 90% recorder depth |
| `rate_queue_depth` | packets currently delayed by the token bucket |
| `rate_queue_capacity` | limiter queue capacity, currently 1024 packets |
| `rate_queue_drops` | packets rejected because the limiter queue filled; separate from recorder `drops` |
| `rate_queue_high_water` | maximum limiter queue depth during this capture |
| `client_isolation` | currently `off`; do not infer isolation from client addresses |
| `[CGW_CLIENT] mac` | stable key for a currently associated client |
| `[CGW_CLIENT] ip` | current DHCP address; may briefly be `0.0.0.0` before assignment |

`file_bytes` is updated when the writer accepts bytes into the PCAP stream. The
FAT directory entry may lag until `fflush`/finalization, so do not start file
transfer until capture has stopped. Any `drops > 0` should change the UI from
healthy to **degraded**, while retaining the capture for investigation.

Use the split counters to locate the bottleneck: `drop_alloc` points to memory
pressure, `drop_queue` to a recorder producer/writer imbalance, and `drop_write`
to SD/filesystem failure. `queue_high_water == queue_capacity` is an early sign
that the writer is only just keeping up even if `drops` is still zero.
`rate_queue_drops > 0` means the adaptive shaping queue itself overloaded; the
UI should report this as network shaping degradation separately from PCAP writer
health. A healthy limited capture has both `drops=0` and `rate_queue_drops=0`.
An effective rate below the configured maximum with increasing
`throttle_events`/`pause_events` is expected protection, not recorder damage, as
long as both drop totals remain zero.

The `clients` count and repeated client rows are live observations taken through
different ESP-IDF APIs. A join/leave exactly during a status command can make
them differ for one poll; reconcile by MAC on the next poll rather than treating
that transient mismatch as corruption.

### 8.5. Parser requirements

- Match the exact prefixes `[CGW] ` and `[CGW_CLIENT] `, not substrings in log
  messages.
- For ordinary status lines, parse space-separated `key=value` fields and ignore
  unknown fields. New firmware may append fields.
- `ssid` and `upstream_ssid` can contain spaces. On the SSID line, extract
  `ssid` between `ssid=` and ` security=`, extract `security` between
  ` security=` and ` upstream_ssid=`, and treat the remainder as upstream SSID.
- The `file` value never contains spaces under the current safe-basename rules.
- Accumulate repeated `[CGW_CLIENT]` rows in a temporary map keyed by MAC.
- Accept fields in any order, let the last duplicate value win, and commit the
  snapshot only on `[CGW] END`.
- Use 64-bit parsing for `file_bytes`; do not store it in an LVGL label's
  temporary 32-bit integer.
- Do not treat `packets == 0` as an error immediately after start. A newly armed
  empty PCAP normally reports `file_bytes=24`.
- Do not parse passwords from output. JanOS never returns the capture password.

Minimal controller-side logic can follow this shape:

```text
on_line(line):
    if line == "[CGW] END":
        publish_complete_snapshot()
    else if line starts with "[CGW] status ":
        parse_status_fields_into_pending_snapshot()
    else if line starts with "[CGW] ssid=":
        parse_ssid_line_using_named_anchors()
    else if line starts with "[CGW] capture=":
        parse_capture_fields_with_u64_file_bytes()
    else if line starts with "[CGW] recorder ":
        parse_recorder_queue_and_split_drop_fields()
    else if line starts with "[CGW] rate_limit_kbps=":
        parse_rate_limiter_fields()
    else if line starts with "[CGW] client_isolation=":
        parse_capability()
    else if line starts with "[CGW_CLIENT] ":
        upsert_pending_client_by_mac()
```

A portable C model suitable for both Tab5 and ADV is:

```c
#define CGW_MAX_CLIENTS 10

typedef struct {
    char mac[18];
    char ip[16];
} cgw_client_t;

typedef struct {
    bool active, upstream, napt, capture_active;
    uint8_t channel, reported_client_count;
    char ssid[33], security[8], upstream_ssid[33];
    char ap_ip[16], sta_ip[16], dns[16];
    char remote_file[128], client_isolation[8];
    uint32_t packets, drops, drop_alloc, drop_queue, drop_write;
    uint32_t queue_depth, queue_capacity, queue_high_water;
    uint32_t rate_limit_kbps, rate_effective_kbps;
    uint32_t throttle_events, pause_events;
    uint32_t rate_queue_depth, rate_queue_capacity;
    uint32_t rate_queue_drops, rate_queue_high_water;
    uint64_t file_bytes;
    cgw_client_t clients[CGW_MAX_CLIENTS];
    size_t client_count;
} cgw_snapshot_t;
```

Keep separate `pending` and `visible` instances. Clear `pending` when the first
`[CGW] status` line of a new response arrives, populate it line by line, then
swap/copy it into `visible` only on `[CGW] END`. This pattern works with LVGL
because the UART task can post one complete immutable snapshot to the UI task;
the UART task must not call LVGL directly.

### 8.6. Recommended state machine

```text
IDLE
  -> CONNECTING_UPSTREAM  send wifi_connect, wait for SUCCESS and IPv4
  -> STARTING             send capture_gateway start ...
  -> RECOVERING_UPSTREAM  transient STA->APSTA loss; reconnect and retry start
  -> RUNNING              receive complete block with active=1,capture=active
  -> DEGRADED             RUNNING with upstream=0, drops>0 or rate_queue_drops>0
  -> STOPPING             send universal stop
  -> FINALIZED            observe [PCAP_FINAL], then confirm active=0
  -> IDLE
```

On opening the screen, always send `capture_gateway status` first. This lets a
restarted UI attach to an already running gateway without starting a second
session. While running, polling every 1-2 seconds is sufficient for client,
packet and size counters; avoid continuous command flooding.

For start completion, wait for a complete block ending in `[CGW] END` with both
`active=1` and `capture=active`. Gateway start can spend up to roughly 15 seconds
recovering the upstream STA before it initializes SD, so a controller timeout of
at least 25 seconds is appropriate. If the command reports a human-readable
error or times out without a complete active block, issue `capture_gateway
status`; only its complete response decides whether the gateway is running.

The `STA -> APSTA` transition can transiently drop the upstream association. A
successful hardware run may therefore look like this: the first start reports
`Capture Gateway: upstream did not recover after APSTA switch`, rolls back to
`active=0`, and the same flow succeeds after reconnecting the STA. Tab5/ADV must
handle this specific case as recoverable:

```text
capture_gateway status
# require the complete active=0 block
wifi_connect <upstream_ssid> <password|--saved>
# require SUCCESS plus non-zero DHCP IPv4
capture_gateway start <the same capture arguments>
```

Use at most two automatic recovery attempts after the initial start, with a
1-second delay before the first retry and 2 seconds before the second. Keep the
screen in `RECOVERING_UPSTREAM` and show the attempt number. Serialize the whole
sequence through the controller transport task; a status poll must not interleave
with `wifi_connect` or the retried start.

Reusing the requested PCAP basename is valid for this exact pre-recorder failure,
because SD/PCAP initialization has not started. If a retry instead reports that
the target file already exists, do not overwrite it: generate the documented
`_01` suffix or ask the operator. Do not automatically retry invalid arguments,
radio-busy, SD mount/write, existing-file or recorder-initialization failures.
After the retry budget is exhausted, remain in `IDLE`, preserve the diagnostic
text and offer an explicit Retry action.

### 8.7. Stop, finalization and file handoff

Normal input is the universal command:

```text
stop
```

Do not use `capture_gateway stop` during automatic gateway capture; it refuses
to remove the AP while the recorder hook is active. The universal command first
restores the hook, drains the writer, closes/syncs the PCAP, and then disables
the gateway.

Prefer the final machine-readable line:

```text
[PCAP_FINAL] file=/sdcard/lab/pcaps/test.pcap frames=174340 drops=0 drop_alloc=0 drop_queue=0 drop_write=0 rate_queue_drops=0 throttle_events=7 pause_events=1
```

It reports the counters after limiter and writer drain. For backward
compatibility, detect the substring `PCAP saved:` in older JanOS output and
extract the `/sdcard/...pcap` path. ESP-IDF log prefixes may precede it, so the
legacy line should not be compared from column zero. After `stop` returns
(or after receive silence if the transport does not expose the REPL prompt),
send `capture_gateway status` and require:

```text
[CGW] status active=0
[CGW] END
```

Only then enable “copy/open capture”. The `file` path remembered from the last
active snapshot is the remote JanOS SD path for the existing Tab5/ADV file
transfer flow. Transfer the finalized file to the controller SD and then open it
in ESPShark. Capture Gateway does not stream PCAP or decoded HTTP bodies live
over this status protocol.

The concrete HTTP handoff used by the current Tab5 implementation is:

1. Send `start_admin_portal <8-63-byte-password>` to JanOS.
2. Wait for the message containing `Admin portal started`, then connect the UI
   device to WPA2 SSID `JanOS-Admin` using that password.
3. Use base URL `http://172.0.0.1`.
4. Strip `/sdcard/lab/` from the remembered remote path. For example,
   `/sdcard/lab/pcaps/iot-lab_20260812_143000.pcap` becomes
   `pcaps/iot-lab_20260812_143000.pcap`.
5. URL-encode the relative path. Query `/api/list?path=pcaps` to confirm the
   remote size, then download `/api/download?path=<encoded-relative-path>`.
6. Write to `<local-name>.part`, update progress from received/expected bytes,
   close and verify the final size, then atomically rename to `<local-name>`.
7. Only a successfully renamed local file may be offered to ESPShark. Preserve
   or clearly label an interrupted `.part` file; never present it as evidence.
8. Send `stop` when the JanOS-Admin transfer session is no longer needed.

The HTTP API is available only while `JanOS-Admin` is running. It is a separate
post-capture mode, so the controller must expect its Wi-Fi connection to change
from the capture/upstream environment to `JanOS-Admin`. ADV implementations
without an HTTP client can stop after recording and leave the PCAP on the JanOS
SD card; the UART status contract itself does not carry file contents.

### 8.8. UI behavior and failure mapping

A practical Tab5/ADV screen should expose:

- capture SSID, Open/WPA2 selector and conditional password field;
- optional custom prefix plus a preview of the generated PCAP basename;
- Start, Refresh and Stop actions;
- upstream/NAPT/capture badges, channel, client count and a MAC/IP client list;
- packets, drops and human-formatted `file_bytes`, while retaining the exact
  integer internally;
- optional aggregate kbps limit plus separate recorder/limiter queue health;
- the remote filename for later transfer;
- a visible warning for an open SSID and for `client_isolation=off`.

Map `upstream=0` to “gateway active, Internet unavailable”, not to “capture
stopped”. Map `drops>0` to degraded evidence and `rate_queue_drops>0` to an
overloaded shaper. Removing client A must remove only its row; if client B
remains and `capture=active`, keep the session running.

Common start failures include missing upstream IPv4, invalid SSID/password,
invalid PCAP basename, an existing target file, unavailable SD storage, radio
busy state and recorder initialization failure. Current failure messages are
human-readable rather than a separate `[CGW_ERROR]` block. Therefore controllers
must display the captured message for diagnosis and always reconcile state with
a subsequent status request.

For protocol version 1, the exact substring `upstream did not recover after
APSTA switch` is the only start failure that should enter the automatic
`RECOVERING_UPSTREAM` policy above. Treat `No upstream IPv4 connection` as a
prompt to connect upstream, but do not loop it blindly when `wifi_connect`
itself fails. All other errors require operator action unless a future firmware
adds a structured retryable error field.

### 8.9. Compatibility rules

This document describes controller protocol version 1. To remain forward
compatible:

- ignore unknown `[CGW]` keys and unknown line types;
- never depend on the order of fields or client rows;
- prefer `packets` over the legacy `frames` alias;
- terminate a snapshot only on `[CGW] END`;
- use capability values such as `client_isolation`, rather than assuming a
  roadmap feature is present;
- prefer structured `[PCAP_FINAL]`; keep human log parsing limited to the legacy
  `PCAP saved:` finalization marker.

### 8.10. SD write baseline

`sd_status` proves only that the mount point exists. Benchmark the actual card
and current SDSPI clock to verify that it can support the fixed gateway profile:

```text
stop
sd_benchmark 32
sd_benchmark 128
```

The command writes 64 KiB chunks through a 64 KiB stdio buffer to the private
temporary file `/sdcard/lab/.janos_sd_benchmark.tmp`, calls `fflush` and `fsync`,
then removes the file. It accepts 1-256 MiB and defaults to 32 MiB. It refuses to
run while PCAP, Capture Gateway or wardrive is active.

Example final output:

```text
[SD_BENCH] result=ok bytes=134217728 elapsed_ms=42116 avg_kib_s=3112 avg_kbps=25496 p50_write_us=183 p95_write_us=41200 p99_write_us=118300 max_write_us=607400 flush_ms=34 sync_ms=7 conservative_50pct_kbps=12748 bus_khz=20000 errno=0
```

Interpret the fields as follows:

- `avg_kib_s` / `avg_kbps` include the final durable flush and describe sustained
  sequential throughput;
- `p99_write_us` and especially `max_write_us` reveal pauses that can fill a
  packet queue even when average throughput is high;
- `flush_ms` and `sync_ms` show finalization cost;
- `bus_khz` reveals whether mounting used the normal SDSPI clock or fell back to
  10/4 MHz after an initialization problem;
- `conservative_50pct_kbps` is exactly half the measured average, capped at the
  benchmark reporting maximum. It is diagnostic guidance, not a runtime input
  and not proof of lossless capture.

Use the longer 128 MiB result because some cards expose long garbage-collection
stalls only after tens of megabytes. Validate the fixed 4096 kbps profile using
real `drop_*`, `queue_high_water` and `rate_queue_drops` counters. A high average
with a very large `max_write_us` means buffering and the adaptive response still
matter; a card that cannot sustain the fixed profile should be replaced.

### 8.11. Product naming for controller integrations

The selected controller-facing name is **JanOS Gate-in-the-Middle (GITM)**. It
deliberately references MITM while describing the actual architecture more
accurately: JanOS becomes the client's real IP gateway instead of relying on ARP
poisoning. The firmware and wire-protocol names remain `capture_gateway` and
`[CGW]`, so the product name does not change the integration contract.

Names considered during selection:

| UI name | Acronym | Character |
|---|---|---|
| **JanOS Gate-in-the-Middle** | **GITM** | **selected**; a routed, controlled evolution of MITM |
| JanOS TraceGate | JTG | communicates both tracing and gateway operation |
| JanOS FlowGate | JFG | short and network-oriented, but sounds flow-level rather than packet-level |
| JanOS PacketScope | JPS | emphasizes inspection, but says less about routed gateway behavior |
| JanOS NetLens | JNL | friendly UI name focused on visibility |
| JanOS Capture Gateway | JCG | exact technical name and the least ambiguous option |

Selected Tab5 presentation:

```text
Title:        GITM
Subtitle:     Gate-in-the-Middle
Context:      JanOS Capture Gateway
Acronym:      GITM
Feature ID:   capture_gateway
Wire prefix:  [CGW]
Output:       PCAP
```

Keep `CGW` in parsers, logs and persisted controller state. `GITM` is the product
and display name; separating it from the stable protocol avoids a firmware and
controller compatibility break. The UI must describe packet capture accurately:
GITM does not imply TLS decryption or access to plaintext inside HTTPS, QUIC or
VPN tunnels.

### 8.12. Tab5 implementation handoff

An agent implementing this feature on Tab5 should deliver the following vertical
slice:

1. Add a **GITM** screen backed by the stable feature ID
   `capture_gateway`; do not rename the JanOS command or `[CGW]` protocol.
2. Reuse the existing upstream Wi-Fi connection flow. Collect downstream SSID,
   `open|wpa2`, optional WPA2 password and an optional safe filename prefix.
   Do not expose a rate field: JanOS always owns the adaptive 4096 kbps profile.
3. Generate `<prefix>_YYYYMMDD_HHMMSS` from the Tab5 clock, sanitize it to
   `[A-Za-z0-9._-]`, then send exactly one quoted start command described in
   section 8.2.
4. Stay in `STARTING` until one complete status block confirms both `active=1`
   and `capture=active`. Implement the one-time APSTA recovery flow from section
   8.6; never report success from a human log line alone.
5. While running, poll `capture_gateway status` without overlapping commands.
   Display upstream state, security, connected clients, file name/size, packets,
   recorder drops, queue pressure, effective rate and limiter drops. Use
   `[CGW_CLIENT] mac` as the client row key.
6. Make any non-zero recorder or limiter drop counter visibly degraded. Show
   adaptive throttling as normal pressure management, not as an error by itself.
7. Stop only with universal `stop`. Keep the UI in `STOPPING` until
   `[PCAP_FINAL]` is received, then offer PCAP transfer/opening in ESPShark.
8. Cover command quoting, fragmented UART reads, reconnect/retry, two-client
   join/leave behavior and the plain-HTTP JSON test from section 9.

The minimum acceptance result for the Tab5 slice is: one tap starts the AP and
capture, later clients appear without another start command, live counters
advance, universal stop returns a final summary, and the resulting PCAP opens in
ESPShark under the controller-generated name.

## 9. Phase 1 acceptance tests

- [ ] With all capture/wardrive operations stopped, run `sd_benchmark 32`, then
  `sd_benchmark 128`. Save the complete `[SD_BENCH] result=...` lines. The 32 MiB
  run is a smoke test; the longer run is more likely to expose SD garbage
  collection and long write stalls.
- [ ] Connect STA upstream and run the single `capture_gateway start ...`
  command while no downstream client is associated.
- [ ] Exercise the controller recovery path: after the first
  `upstream did not recover after APSTA switch` failure, require `active=0`,
  reconnect upstream and retry the identical start automatically. Confirm the UI
  never reports `RUNNING` before receiving `active=1,capture=active` and `[CGW]
  END`.
- [ ] Repeat once with an open SSID and once with WPA2; confirm status reports
  the matching `security=open|wpa2` value and clients can associate as expected.
- [ ] Start with `--pcap-name office_YYYYMMDD_HHMMSS`; confirm status and the
  saved file use that exact basename plus `.pcap`. Repeat the same name and
  confirm JanOS refuses to overwrite the first capture.
- [ ] Confirm status already says `capture=active`, then join the SSID with one
  test client; do not issue a second capture-start command.
- [ ] Run a two-client transfer of at least 128 MiB; the fixed ceiling is 4096 kbps.
  Confirm `rate_effective_kbps` falls below 4096 when recorder depth crosses a
  threshold, `throttle_events` increases, the limiter queue remains bounded and
  final `[PCAP_FINAL]` reports zero recorder drops. Any `rate_queue_drops` means
  the network shaper still overloaded and the run is degraded.
- [ ] Confirm DHCP address in `10.42.0.0/24`, gateway `10.42.0.1`, DNS `10.42.0.1`
  with `dns_proxy=on`, and working name resolution through the SoftAP proxy.
- [ ] Confirm ping, HTTP, HTTPS and a sustained TCP transfer reach the Internet.
- [ ] Verify both directions and original client IP in Wireshark without
  ARP-spoof traffic.
- [ ] Join client A and generate uniquely identifiable HTTP traffic. One minute
  later join B and generate different traffic. Disconnect A, generate more
  traffic from B, and confirm: status lists only B, `capture=active`, the frame
  counter keeps increasing, and the final PCAP contains B traffic from both
  before and after A disconnected.
- [ ] With A and B connected, test A-to-B ARP, ping and TCP in both directions.
  Until all paths are blocked and verified, report client isolation as `off`
  and do not claim complete visibility of peer-to-peer traffic.
- [ ] Compare generated packet count with PCAP records and recorder drop count.
- [ ] Disconnect/reconnect upstream and verify status changes plus recovery.
- [ ] Stop during idle and load; verify hooks, NAPT, DHCP and PCAP are finalized.
- [ ] Confirm radio/sniffer/portal modes cannot silently destroy an active gateway.
- [ ] Confirm an encrypted HTTPS test produces metadata/ciphertext, not a false
  claim of decrypted content.

### 9.1. Plain-HTTP JSON visibility test

Use a deterministic local endpoint so redirects to HTTPS and Internet service
changes cannot invalidate the test. On a computer reachable through the
upstream network, from this repository directory, run:

```text
python -m http.server 8080 --directory tests/capture_gateway
```

On client B, while connected to the capture SSID, run (replace the address with
the test computer's upstream LAN address):

```text
curl --http1.1 http://192.168.1.50:8080/sample.json
```

After `stop`, transfer/open the PCAP in ESPShark on Tab5, select the HTTP flow
and use **FOLLOW** (ASCII). The response headers and the raw JSON from
`sample.json` should be visible. The current integration is an offline PCAP
workflow; it does not yet stream the JSON live while capture is running. A
response larger than one TCP segment is still readable through Follow Stream,
subject to the viewer's explicit gap/truncation limits.

The feature may be marked `HARDWARE-VERIFIED` only after these tests pass on the
target ESP32-C5 with the intended SD card.

### 9.2. Hardware reference run: fixed adaptive 4096 kbps

The following ESP32-C5 run used the adaptive 4096 kbps profile that is now the
firmware default. One client streamed YouTube smoothly while capture remained
active. The last live snapshot before stop reported:

```text
packets=54444 drops=0 file_bytes=42378021
recorder queue_high_water=184/1024
rate_queue_high_water=232/1024 rate_queue_drops=0
rate_effective_kbps=4096 throttle_events=0 pause_events=0
```

Universal `stop` then produced:

```text
PCAP writer done: /sdcard/lab/pcaps/adaptive_4096_long.pcap (54550 frames, 0 drops)
PCAP saved: /sdcard/lab/pcaps/adaptive_4096_long.pcap (54550 frames, 0 drops)
[PCAP_FINAL] file=/sdcard/lab/pcaps/adaptive_4096_long.pcap frames=54550 drops=0 drop_alloc=0 drop_queue=0 drop_write=0 rate_queue_drops=0 throttle_events=0 pause_events=0
Capture Gateway stopped
```

This validates the healthy single-client path and shutdown ordering:

- all 54,550 accepted frames were serialized;
- allocation, recorder-queue, writer and limiter-queue drops were all zero;
- neither queue crossed the 50% adaptive threshold, so remaining at 4096 kbps
  with zero throttle and pause events was the correct behavior;
- the writer completed and the PCAP was saved before the gateway stopped and
  Wi-Fi reset began.

This run does not by itself validate adaptive threshold transitions or
multi-client isolation. Those remain separate acceptance tests.
