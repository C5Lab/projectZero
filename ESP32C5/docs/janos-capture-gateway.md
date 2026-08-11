# JanOS Capture Gateway

> **Product name:** JanOS Capture Gateway — instrumented APSTA/NAPT gateway for
> authorized traffic analysis.
>
> **Status:** implementation started, Phase 1 foundation.
>
> **Scope:** networks and client devices owned by the operator or tested with
> explicit authorization.

## 1. Purpose

JanOS Capture Gateway turns the ESP32-C5 into the actual IPv4 gateway for test
clients. A client joins a dedicated JanOS SoftAP, receives its address and
default route from JanOS, and reaches the Internet through the JanOS STA
connection and lwIP NAPT. JanOS records traffic on the downstream AP interface
before address translation, preserving the original client address in PCAP.

This replaces ARP-spoof MITM as the preferred capture architecture. ARP spoofing
remains a best-effort laboratory mode and cannot guarantee that another access
point will deliver every client's traffic to JanOS.

```text
authorized test client
        |
        | dedicated Wi-Fi SSID
        v
JanOS SoftAP: 10.42.0.1/24
        |
        | downstream capture (pre-NAT)
        v
IPv4 routing + firewall policy + NAPT
        |
        v
JanOS STA -> upstream AP/router -> Internet
```

## 2. Terminology and guarantees

The feature is a routed **capture gateway**, not an HTTP/SOCKS proxy and not a
transparent TLS proxy. The realistic guarantee is:

> Capture all routed IPv4 packets observed by the JanOS downstream netif for
> clients connected to the dedicated capture SSID, while reporting every known
> recorder drop.

It does not promise every RF frame, traffic from clients attached to another
AP, decrypted HTTPS/QUIC/VPN content, or mathematically zero packet loss. A
capture with a non-zero drop counter is explicitly degraded.

## 3. Operator flow

Phase 1 deliberately reuses the existing, tested STA credential path:

```text
wifi_connect <upstream_ssid> <password|--saved>
capture_gateway start <capture_ssid> <capture_password>
capture_gateway status
start_pcap gateway
stop
```

Requirements:

- the STA must already be associated and have a non-zero IPv4 address;
- capture SSID length is 1-32 bytes;
- capture password length is 8-63 bytes; open capture networks are not offered;
- the downstream network is fixed to `10.42.0.0/24` in Phase 1;
- gateway start fails if the upstream subnet contains `10.42.0.1`, preventing
  an ambiguous route caused by overlapping upstream/downstream addressing;
- the AP channel follows the associated upstream AP because ESP32-C5 uses one
  physical Wi-Fi radio;
- `stop` finalizes PCAP before disabling NAPT and resetting Wi-Fi.

`capture_gateway stop` is available when no gateway PCAP is active. During an
active capture, the universal `stop` command is required so hooks are restored
and the writer drains before the AP is removed.

## 4. Phase 1 implementation

### 4.1. Dedicated component

`components/capture_gateway` owns:

- validation and configuration of the dedicated WPA2 SoftAP;
- downstream address `10.42.0.1/24` and DHCP server lifecycle;
- propagation of the upstream DNS server through DHCP;
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

`start_pcap gateway` uses classic PCAP linktype 1 and hooks `WIFI_AP_DEF`:

- AP `input`: client-to-Internet packets before NAPT;
- AP `linkoutput`: reverse-NAPT Internet-to-client packets;
- no ARP poisoning;
- no second capture on the STA side, avoiding pre-/post-NAT duplicates.

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
- Current PCAP queue still allocates once per frame and has a finite depth.
- Traffic switched directly between SoftAP clients is not yet claimed as
  complete capture evidence.
- TLS, QUIC, SSH and VPN payloads remain encrypted.
- AP netif hooking uses the existing lwIP integration approach and must be
  revalidated after ESP-IDF upgrades.

## 7. Hardening roadmap

### Phase 2 — recorder integrity

- fixed PSRAM frame pool instead of `malloc` per packet;
- queue high-water mark, RX/captured/dropped counters and degraded flag;
- `.part` file, explicit sync, atomic final rename and session manifest;
- size/time rotation and SD free-space guard;
- controlled recovery after upstream loss and power interruption.

### Phase 3 — multi-client operations

- client inventory with MAC, DHCP address, hostname and counters;
- per-client capture selection and limits;
- verified client isolation policy;
- Tab5 controls for start/status/stop, live counters and PCAP transfer;
- optional configurable downstream subnet and DNS policy.

### Phase 4 — performance and alternate uplink

- TCP/UDP throughput and latency envelope with capture on/off;
- slow/full SD and queue-saturation tests;
- Ethernet or second independent Wi-Fi uplink for higher reliability;
- explicit IPv6 design using routing, RA/NDP and firewall policy.

## 8. Phase 1 acceptance tests

- [ ] Connect STA upstream, start gateway, and join its SSID with one test client.
- [ ] Confirm DHCP address in `10.42.0.0/24`, gateway `10.42.0.1`, and working DNS.
- [ ] Confirm ping, HTTP, HTTPS and a sustained TCP transfer reach the Internet.
- [ ] Run `start_pcap gateway`; verify both directions and original client IP in
  Wireshark without ARP-spoof traffic.
- [ ] Compare generated packet count with PCAP records and recorder drop count.
- [ ] Disconnect/reconnect upstream and verify status changes plus recovery.
- [ ] Stop during idle and load; verify hooks, NAPT, DHCP and PCAP are finalized.
- [ ] Confirm radio/sniffer/portal modes cannot silently destroy an active gateway.
- [ ] Confirm an encrypted HTTPS test produces metadata/ciphertext, not a false
  claim of decrypted content.

The feature may be marked `HARDWARE-VERIFIED` only after these tests pass on the
target ESP32-C5 with the intended SD card.
