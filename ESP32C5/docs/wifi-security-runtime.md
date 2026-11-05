# Passive Wi-Fi security runtime

Operator-facing Shield behavior is documented in
[JanOS Wi-Fi Shield](wifi-shield.md). The separation between host, firmware,
device, RF and storage evidence is recorded in
[Wi-Fi Shield validation](wifi-shield-validation.md).

This foundation supplies bounded receive storage, decoding, a single consumer
worker and a shared radio lifecycle. Combined Wi-Fi Shield, WPS Guard, SAE
Guard, Wi-Fi Trust Baseline and Detector V2 use one shared callback and worker
in their mutually exclusive profiles. The foundation itself implements no
detector policy, active response or public runtime command.
See [shared radio ownership](janos-radio-lease.md).

## Storage and callback boundary

The pool has eight slots (`WIFI_SECURITY_POOL_SLOTS`); each copies at most
1536 bytes (`WIFI_SECURITY_FRAME_COPY_MAX`). The queue contains slot indices,
with capacity 1..8; the production adapter uses eight. Storage, worker stack and
synchronization objects are fixed, with no heap requirement in the core.

The driver callback accepts management/data packets with `sig_len > 4`, removes
the four-byte FCS from the supplied MAC-frame length and submits borrowed bytes,
generation, RSSI, channel and RX timestamp. Submission performs a bounded copy
under callback-safe mutual exclusion, enqueues an index and optionally wakes the
worker outside the core lock on an empty-to-nonempty transition. It never drains
inline. FIFO follows successful enqueue order. Empty/null input is rejected.

No decoding, printing, allocation, channel changes, raw TX, or persistence
is permitted in the callback. It must not run consumers, wait/join, take the
lifecycle mutex, or perform filesystem/SD/NVS operations. Decoding and consumer
execution occur in the worker outside the core lock. The callback gate protects
core acceptance; it does not itself establish a driver callback fence.

`timestamp_us` stores the raw 32-bit RX timestamp supplied by the driver, widened into
the slot's 64-bit field. This is not a wrap-extended monotonic clock or a promise
of wall-clock/cross-session ordering. Platform timeout accounting separately uses
monotonic microseconds (`esp_timer_get_time` in the adapter).

## Start and states

Combined module `WIFI_SECURITY_MODULE_SHIELD` uses lease owner `SHIELD`
(`JANOS_RADIO_OWNER_SHIELD`). Compatibility modules use `SECURITY_MONITOR`
(`JANOS_RADIO_OWNER_SECURITY_MONITOR`). Their lease progression is
`IDLE/NONE -> PREPARING/<owner> -> RUNNING/<owner> -> CLEANUP/<owner> ->
IDLE/NONE`, with failed cleanup retaining the exact owner/generation in
`QUARANTINED`. Core `running` and `stopping` flags describe the core, not
verified driver or ownership state.

Start validates module arguments and its required feature uncertainty callback,
acquires the lease, then checks the mutable legacy host baseline. A free lease
does not imply idle hardware: legacy tasks can outlive their startup reservation.
The adapter reuses the analyzer host probe, including published legacy tasks and
uncertain driver activity; this probe does not reject the newly acquired security
owner. A busy baseline releases only the reservation, without changing channel,
filter, callback, worker, or feature context. If legacy startup wins acquisition,
security returns busy before performing that baseline probe or any radio access.

After an idle baseline, Start snapshots primary/secondary channel and the prior
promiscuous filter, prepares fixed resources, creates the worker, registers the
callback, installs exactly `MGMT|DATA`, enables promiscuous RX, marks the lease
running and only then commits opening the core generation. The driver must
already be initialized for these snapshots. Rollback uses the same Stop path.
Filter apply is considered potentially mutating even when it fails; its saved
filter must then be restored. Other failed acquisition hooks leave no acquired
resource. Cleanup errors take precedence over the startup error.

The adapter serializes lifecycle calls. Its phases are `IDLE`, `STARTING`,
`CANCELLED`, `OPEN_COMMITTED` and `STOPPING`. A contended Stop latches startup
cancellation independently of lease ownership. Cancellation is checked after
every startup side effect; atomic `generation_open` arbitration decides whether
cancellation or opening wins. A Stop after open commitment waits for serialized
cleanup and cannot retroactively cancel the commit. Lifecycle waits run outside
the phase/core critical sections; Stop charges mutex wait to its timeout.

## Exact Stop order and retry

For resources actually acquired, successful Stop follows:

```text
close callback admission -> unregister callback -> disable promiscuous RX
-> request core stop and lease cancellation -> signal worker stop
-> join worker -> restore saved promiscuous filter -> restore saved channel
-> finish core -> begin lease cleanup
-> finish verified cleanup and release owner/generation -> wipe module context
```

The worker drains accepted frames, including a final drain after stop, before
join succeeds. Callback closure does not discard queued frames. `finish` requires
no draining worker, no queued frames and no outstanding claimed slots; it wipes
slots/config and preserves final counters and the generation guard. Context wipe
runs once after join, filter/channel restoration and core finish. Idle Stop is a silent
no-op. Only `WIFI_SECURITY_SESSION_OK` permits general driver reset.

| Failure | Retention and retry |
| --- | --- |
| Worker join timeout | Worker flag, module context, saved channel and ownership remain; retry joins before restore/wipe. |
| Callback unregister or promiscuous disable fails | That resource flag remains; Stop still requests worker stop/join, but does not restore, finish or wipe until quiet is verified; retry repeats unresolved operations. |
| Saved-channel restore fails | Saved channel, module context and ownership remain; retry repeats restoration before finishing. |
| Filter snapshot fails | No filter is applied; rollback releases resources acquired earlier. |
| Filter apply fails or cancellation follows apply | Treat filter as changed; restore it after receive quiescence and join, before channel/context cleanup. |
| Filter restore fails | Saved filter, channel, module context and ownership remain quarantined; retry restores filter before channel and context cleanup. |
| Core finish fails | Outstanding activity/claims prevent wipe/release; resolve them before retry. |
| Lease cleanup/release fails | Session/ownership retry state and feature context remain live; retry releases the exact generation before the one-time wipe. |
| Lifecycle mutex timeout | Return false and report the actual ownership snapshot; it may say `none` if Start has not acquired the lease yet. |

Cleanup uncertainty attempts `begin_cleanup` and `finish_cleanup(false)` to
retain ownership in `QUARANTINED`. It does not erase unresolved resource flags or
pretend release succeeded if the lease transition itself fails. A later global
`stop` retries the same session/generation. No terminal success under uncertainty
is permitted. The foundation emits no wire prefix. Its required feature-supplied
uncertainty callback receives the result and a snapshot indicating whether
`SECURITY_MONITOR` owns the lease. The feature formats its approved versioned
prefix, such as `[WPS_GUARD/1]`, `[SAE_GUARD/1]` or `[WIFI_TRUST/1]`.
Pending pre-lease startup cancellation reports ownership false through that
pending feature callback, rather than claiming ownership was retained.

Global `stop` joins WPS, analyzer, then security cleanup before legacy teardown;
failure prevents the legacy reset. While this owner is active, admission permits
security status/stop, global `stop`, `help`, `ping` and `version`. Other radio
mutations remain busy. A bare `reboot` is allowed only for its quarantined,
nonzero generation with no command in flight and no analyzer-busy baseline.
These policies do not register feature commands or change legacy wire records.

## Generations and counters

The lease supplies a nonzero generation, never the feature. A core accepts only
strictly increasing generations; no wrap/reuse is allowed. Exhaustion requires a
new runtime only after every producer retaining old tokens has joined. Repeating
the identical active/open configuration is idempotent and does not reset state;
a stopping/closed session cannot reopen. Fresh starts reset counters and publish
their module/generation identity in the shared status snapshot, while finish preserves both.
All eight counters saturate at `UINT32_MAX`.

| Counter | Meaning |
| --- | --- |
| `received` | Nonempty submit attempts, including stale/closed attempts. Null/empty inputs do not count. |
| `queued` | Successfully accepted/enqueued frames. |
| `processed` | Successfully decoded frames whose consumer returned true; not every released slot. |
| `truncated` | Copies bounded below original length, including copies later rejected by a full queue. |
| `dropped_pool` | Pool exhaustion, including internal claim attempts; no free slot means no truncation copy. |
| `dropped_queue` | A copied slot could not enqueue; it is wiped/released. |
| `stale_generation` | Zero/mismatched tokens, including while closed. |
| `decode_rejected` | Decoder failures only; missing/false consumers do not increment it. |

A closed submission with a valid token has no dedicated drop counter. Counters
are not an exhaustive loss equation or evidence of complete RF reception.
The bounded decoder exposes bounded MAC-body slices and exact-SNAP-recognized
EAPOL views; consumers validate IE/EAPOL structures. Rejection is not a detector
verdict or attribution.

## Module integration and lifetime

Features pass `wifi_security_session_config_t` to
`wifi_security_runtime_platform_start`: a module (`WPS_GUARD`, `SAE_GUARD`,
`TRUST_MONITOR`, `SHIELD` or `DEAUTH_V2`), borrowed context, consumer, required
`validate`, `wipe` and `uncertainty` callbacks, and a separate
`telemetry_context`. Validation runs
before lease acquisition and must not mutate radio
state. Later active-family handlers are responsible for rejecting unsupported
active options before passive startup; admission is not argument validation or
authorization to transmit. This foundation offers no active-response engine.

`uncertainty(telemetry_context, result, owned)` must be concurrency-safe. The
adapter captures cleanup reports while serialized, then invokes the feature
after releasing all locks owned by the reporting caller. A contending Stop does
not own the lifecycle mutex; it can report while another caller is starting or
stopping. `telemetry_context` must survive module-context wipe and remain valid
until **all concurrent Start/Stop calls have returned**. The callback pointer and
telemetry context are copied under the phase gate before use outside it. This
foundation does not format feature messages or validate their wire schemas.

`consume(context, const wifi_security_frame_slot_t *, const
wifi_security_decoded_t *)` borrows slot/decoded views only until return. It may
query core status or request core stop, but must not retain views, mutate/init
the runtime or call serialized platform start/stop from the worker. A NULL
consumer is permitted; frames are still decoded/released. A false consumer
return leaves `processed` unchanged, and every dequeued slot is wiped on all
paths. No payload persistence is provided: no packet capture, credentials,
payload logging or SD/NVS writes. Consumers must preserve this boundary.

Feature context remains borrowed until successful cleanup; failed join/restore
requires retaining it. Hooks and their context must outlive all in-flight calls,
including late callback/notification returns. Static adapter state survives late
rejected callbacks. Successful unregister must prevent new callbacks; platform
integration must join existing callbacks before destroying contexts/storage.
Core close/finish alone is not that fence. The public layout permits fixed
caller storage, not concurrent field access or copying a live runtime. Pool
claim/release APIs are component internals, not feature interfaces.

### Combined Wi-Fi Shield module registration

The public `wifi_shield` command registers `WIFI_SECURITY_MODULE_SHIELD` and
holds `JANOS_RADIO_OWNER_SHIELD`. It combines bounded Deauth/Disassoc/CSA, WPS,
SAE, Trust and PMKID observation. Passive mode makes exactly zero TX calls.
WPS, SAE and Trust observations never authorize active response. The optional
Defence bridge is reachable only after an immutable selected BSSID and channel
snapshot confirms WPA2-PSK/CCMP and the operator explicitly supplies
`--defence decoy-4way`; in the granular form, the PMKID decoy remains
separately explicit and experimental. The explicit `--protect-all` preset is
the exception and enables it as part of the complete policy. `--multi-vector`
is accepted only with both granular active options. It
changes the per-BSSID satisfied policy from one successful response total to
at most one successful `decoy_pmkid` and one successful `decoy_4way` in either
order during the same campaign. Repeated completed actions remain suppressed;
failed transmissions remain incomplete and subject to the existing retry rate
limits. `--protect-all` is the explicit selected-target preset for the existing
active Deauth/PMKID multi-vector policy and the already combined passive
WPS/SAE/Trust monitors. It publishes `MODE=protect-all` together with
`ACTIVE=deauth,pmkid` and `PASSIVE=wps,sae,trust`. It does not authorize active
WPS, SAE or Trust traffic. The default cross-action latch and its wire records
are unchanged.

Shield does not classify `Auth -> Assoc` alone as actionable PMKID harvesting.
It retains the candidate for a fixed 30 ms grace interval in its PSRAM session
state. A matching standards-shaped EAPOL M2 completes an ordinary association,
cancels the candidate and emits observe-only Defence telemetry. If no such M2
arrives before worker expiry, the existing PMKID event and optional decoy path
run unchanged. This gate is Shield-specific; compatibility profiles retain
their existing behavior.

Large state, frame slots, compact rings, target snapshots, histories, queues
and task stacks use `MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT` with
`portBYTE_ALIGNMENT`. Allocation is transactional with no silent fallback to
internal SRAM. Internal SRAM retains only the small synchronization and
control objects that require it. Uncertain callback closure, worker/TX join,
filter/channel restore or lease release retains `SHIELD/QUARANTINED` and its
PSRAM bundle for Stop retry; it cannot publish terminal success.

For one effective channel, single-channel coverage is continuous subject to
driver and RX-drop uncertainty. Across multiple channels, multi-channel
coverage is sampled; only the resident channel is observed, so silence is not
proof of absence. WPS activity is not Pixie Dust, exploitation or vulnerable
router proof. A completed decoy TX is not prevention, client-retention or
real-handshake proof. Host success is not firmware, device, physical PSRAM/SD
or RF proof.

The eight public forms and exact built-in help are documented in the
[command manual](command-manual.md#wifi_shield). Internal profile entry points,
module enums and roadmap capabilities are not public CLI.

### Detector V2 compatibility-profile registration

`deauth_detector_v2` registers `WIFI_SECURITY_MODULE_DEAUTH_V2`, requests the
MGMT-only receive policy and uses `JANOS_RADIO_OWNER_SECURITY_MONITOR`. The
shared runtime owns the callback, worker and cleanup lifecycle; the existing
Detector task still owns exact `[DEAUTH_FORENSIC/1]`, `[DEAUTH_V2]`, `[CSA]`,
WATCH, Trace, Defence, LED and OLED publication/order. Its selected-channel
hopping, Trace lock/release and immutable Defence channel behavior are
unchanged. Legacy `deauth_detector` remains on its established direct path.

This migration adds no public status token or command form. Active V2 Defence
retains its existing explicit grammar and accepted response semantics; no
shared-runtime enum or internal `wifi_shield_start_deauth_profile` entry point
is a production CLI command.

### WPS Guard module registration

The production adapter registers WPS Guard with
`WIFI_SECURITY_MODULE_WPS_GUARD`. Its feature context supplies the metadata-only
consumer, validation, wipe and uncertainty callbacks required by the shared
lifecycle. The CLI resolves an owned immutable whole-target snapshot from one
completed scan before calling the Shield-owned WPS radio profile. Each target
record carries the BSSID and captured scan channel needed by the immutable
filter and channel plan. The snapshot is allocated only in byte-addressable
PSRAM, then zeroized and released by the feature wipe only after verified worker
join, filter/channel restoration and core finish. A pre-lease busy rejection
releases the snapshot locally. Failed cleanup keeps the radio owner quarantined
and retains the context/snapshot for retry. The adapter also snapshots the
shared runtime module/generation identity and status. It publishes `RX_DROPS` as the saturated sum of
`dropped_pool` and `dropped_queue`, distinct from WPS flow-table
`CAPACITY_DROPS`; the generation prevents a failed pre-open Start from inheriting
the preceding session's counters.

Shield owns only this profile's initial tune, deterministic scheduler, radio
fence and raw shared-runtime Start/Stop. WPS Guard continues to own its parser,
core, status, formatter and output. One effective selected channel remains
pinned; multiple unique selected channels are sampled in scan order with a
250 ms per-channel dwell. Every retune revalidates the WPS module and generation
after acquiring the radio fence; a failed retune does not advance the plan.
Stop closes the scheduler before fencing an in-flight retune and releases the
fence before shared-runtime cleanup. Evidence is limited to the currently
received/tuned channel: this sampled schedule does not guarantee complete
multi-channel coverage, and silence on a channel is not evidence of absence.

WPS Guard's consumer runs only in the shared worker. For each selected frame it
samples the injected monotonic clock once and uses that same value for flow
expiry and fragment observation; it never uses the raw driver RX timestamp for
the 5000 ms session clock. Expiry is strictly greater than 5000 ms: 5000001 us
expires a flow, not at 5000000 us. Unselected BSSIDs are counted as filtered
before WSC parsing. Recognizable WSC metadata reaches an eight-flow core with a
maximum 4096-byte declared length; unrelated traffic is counted without
creating a flow.

The shared bounded slot temporarily copies MAC-frame payload bytes. Those bytes
are borrowed and read only by the worker consumer, which validates the WSC
envelope; the fragment payload is hashed immediately into metadata. WPS Guard
does not decode WSC attributes. The copied slot is zeroized by the shared
runtime after consumption; payload bytes are never retained in WPS Guard
flow/session state or telemetry. WSC attributes, nonces, keys, PINs,
credentials and authentication tags likewise never enter that state or output.

Feature Start/Stop has an epoch and cancellation latch in addition to the
foundation lifecycle. This covers cancellation while the scan snapshot exists
but no foundation session has been opened. Global `stop` enters the feature
gate first, then the generic foundation gate for already-borrowed and future
modules. Record publication uses a separate mutex with a 250 ms acquisition
limit and a fixed publisher queue with a 250 ms admission limit, never the
callback or feature-state critical section. Lifecycle callers do not wait for
the UART driver; one dedicated task submits each complete record in one UART
transaction. Queue backpressure or a publisher error is reported as output
failure. To keep an asynchronous writer failure scoped to the originating
session, a new Start remains busy until prior-session publications resolve.
Publication ordering still orders `ARMED` against Stop and assigns
one terminal result to each cleanup attempt; a retained-context retry receives
a new attempt and a new result. In operator terms this is one terminal per
cleanup attempt, and a later retry receives a new terminal. The session retains
persistent output-failure evidence, which overrides the later cleanup label, so
the retry result remains `output_failed`. Failed output fail-closes consumption until
Stop. No terminal success is emitted while cleanup is uncertain.

This remains evidence-only passive monitoring. It sends no Fragment ACK, EAP
response, enrollment message, PIN verification, association request or raw TX,
and it does not attribute a sender. Identical retransmissions are counted as
telemetry, not anomalies. A `[WPS_GUARD/1]` alert does not prove WPSplinter and
does not prove that a device is exploitable. Disabled WPS advertisement does
not prove that legacy WPS code is unreachable.

### SAE Guard module registration

The production adapter registers SAE Guard with
`WIFI_SECURITY_MODULE_SAE_GUARD`. Its CLI owns a zeroized, immutable
whole-target snapshot in byte-addressable PSRAM and supplies a session-specific
opaque context token in addition to the feature epoch. Saved `validate`,
`consume` and `wipe` callbacks from an old generation are inert after restart.
The callback only copies into the shared runtime; the worker alone prefilters,
parses, correlates and publishes.

Wi-Fi Shield owns only this compatibility profile's bounded channel schedule,
initial tune, lifecycle gate, radio fence and raw shared-runtime Start/Stop.
SAE Guard still owns its parser, core, status, formatter and output; one
effective selected channel remains pinned for continuous coverage; multiple
unique selected channels are sampled in scan order with a 250 ms per-channel
dwell. Retune failures retry the same channel, and stale generations cannot
advance the schedule. Only the currently tuned channel reaches the same single
SAE consumer. Sampling is incomplete by design, so silence on a channel is not
evidence of absence.

Only selected, unprotected Authentication frames whose algorithm field is SAE
(3) reach the SAE parser. Unrelated subtypes, other algorithms and protected
bodies do not consume the detector clock. A selected SAE observation samples
the monotonic clock once; the same value drives parsing and the half-open
ten-second correlation window. The detector tracks 32 `(BSSID, station,
direction)` pairs and 32 independent malformed-BSSID rows. Thresholds are
three malformed frames per BSSID, eight unconfirmed Commits per pair and three
distinct group identifiers per uncompleted pair.

Known groups 19, 20 and 21 validate bounded Commit scalar/element bodies and
40, 56 and 72 byte Confirm totals. Status 126 (Hash-to-Element), status 127
(SAE-PK), status 76 anti-clogging and status 77 unsupported-group follow the
documented parser contract. Unknown groups remain observable and are not
malformed merely because the group is unknown. SAE scalar, element, token,
password identifier, password, PMK and raw payload bytes are never retained in
the feature state or output.

Each `[SAE_GUARD/1]` event is formatted into a fixed 512-byte line buffer and
enqueued outside the feature lock. Status and terminal records preserve
`CAPACITY_DROPS`, `PAIR_DROPS`, `MALFORMED_DROPS`, saturated `RX_DROPS` and
output failures. Events can carry combined reasons; severity is the maximum
severity and every unique interpretation is kept in deterministic order. A
static depth-eight publisher queue uses a 250 ms admission bound and a dedicated
task performs one complete UART write. A failed admission retains its pending
token until output failure is recorded and the completion boundary runs.

Start claims feature state atomically before scan snapshot/runtime startup.
Concurrent Stop callers share a cleanup attempt and receive one terminal for
that attempt. Pre-runtime cancellation, post-commit/pre-ARMED cancellation,
late publisher failure, post-wipe cleanup-only retry and stale callbacks are
covered by the host lifecycle harness. `sae_guard stop` and global `stop` retry
quarantined cleanup. The lifecycle terminal precedence is
`output_failed > restore_failed > queue_overflow > stopped`; successful cleanup
with shared-runtime loss cannot claim a complete observation set.

SAE Guard is passive and evidence-only. It sends no SAE Commit, SAE Confirm,
anti-clogging token, status response, deauthentication, disassociation or
channel-switch announcement. Malformed evidence may resemble a parser-risk
condition such as CVE-2026-72003, but it cannot identify a vulnerable driver,
cannot prove exploitation or code execution, and cannot prove attribution,
password compromise or that WPA3 is broken. Commit bursts mean possible
resource pressure, not a broken password exchange.

### Wi-Fi Trust Baseline module registration

The production adapter registers capture and monitor sessions as
`WIFI_SECURITY_MODULE_TRUST_MONITOR`. Bare capture and monitor remain current
channel only: the controller snapshots the active primary channel immediately
before Start and passes `NULL, 0`, so there is no scan, initial tune or retune.
An optional `--only` list is resolved before lease acquisition into private,
immutable complete selected target records in the Trust arena. Shield tunes to
the first selected channel and provides 250 ms sampled residence across the
distinct selected channels, retrying a failed retune without cursor advance.
Every status and terminal record preserves `SCOPE=current_channel`; for
`--only`, `CHANNEL` follows the actually resident channel. No new Trust wire
field or Shield presentation/output path is introduced.

Capture uses one PSRAM-only arena capped at 384 KiB for bounded builders,
targets, snapshots and an event batch. The arena is allocated before radio
lease acquisition, retained through cleanup quarantine, explicitly zeroized and
then released once. The feature finalizes valid, conflict-free profiles into an
owned pending snapshot before its runtime wipe callback. It performs no SD I/O
from callback, worker or wipe context and never writes baseline storage before
verified runtime cleanup and radio restore. Cancel/error preserves the prior
baseline; a cleanup-only retry retains the pending snapshot and arena.

Monitor validates and loads the baseline before acquiring the radio. Its worker
uses the same Beacon/Probe builder and deterministic diff core as capture.
Repeated identical advertisements update telemetry but do not republish the
same drift event. Unknown evidence never replaces confirmed values, malformed
input produces bounded evidence without baseline mutation, and the stored
baseline remains immutable throughout a monitor session.

The storage adapter serializes access, mounts SD on demand, creates
`/sdcard/lab/wifi-trust`, and maps the checked staged-publish/recovery interface.
It uses checked open, flush, file sync, close, rename/removal and volume sync
results; recovery uncertainty is carried into the terminal rather than hidden.
This host-tested transaction model does not prove FAT or real SD power-loss
recovery.

A timer callback samples monotonic time and uses the active owner's
monotonic due-time fence before latching an epoch and attempting a nonblocking
control-queue notification. Rearm replaces both ownership and any old pending
latch, so a delayed callback from the prior physical firing is inert before the
new deadline; at or after the new due time it can only deliver the surviving
epoch once. The dedicated control task polls the latch so a full queue cannot
silently discard a capture deadline. A separate bounded operation mutex
serializes physical timer arm and cancel. Cancel checks logical ownership before
calling `esp_timer_stop`, so stale cancellation cannot stop a rearmed timer.
Natural expiry, concurrent Stop, reentrant Stop and cleanup failure share one
end claim; exactly one caller owns runtime cleanup and exactly one terminal is
published for that attempt. A later quarantined retry is a new cleanup attempt.

`[WIFI_TRUST/1]` publication uses a static depth-eight queue with bounded
admission and a dedicated publisher that writes each complete record in one UART
transaction. Sink-time terminal formatting preserves the precedence
`output_failed > restore_failed/timeout > storage_uncertain > storage_failed >
queue_overflow > stopped/ok`. Pending publication keeps a new session busy until
the originating output resolves.

Wi-Fi Trust Baseline is passive and evidence-only. It does not attribute an
attacker and does not conclude `evil_twin`, compromise, safety or exploitability.
It sends no probe, authentication, association, deauthentication,
disassociation, channel-switch announcement or raw frame. It stores no packet
payload or credential. Its current host gates do not prove ESP-IDF compilation,
FreeRTOS/timer scheduling, the driver callback fence, RF reception, on-device
PSRAM behavior, channel restore, FAT durability or real SD power-loss recovery.

### Client Isolation Audit module registration

Client Isolation Audit is a synchronous console transaction and does not take a
shared promiscuous-radio lease. It snapshots the existing connected STA
identity twice before I/O and uses only the validated numeric same-subnet peer.
It does not scan, discover a peer, change the interface, transmit raw 802.11
frames or use Wi-Fi credentials. The legacy admission token is retained until
the handler returns; `status` remains read-only and the module adds no
feature-specific Stop path or change to global Stop output.

The fixed 52-byte big-endian `JISO/1` challenge/reply uses a 16-byte per-peer
token and HMAC-SHA256/16 over the complete 36-byte authenticated prefix. The
production adapter uses Mbed TLS; portable tests inject the cryptographic
operation. Every probe uses a fresh 16-byte nonce and accepts a reply only from
the exact peer IPv4/port with matching run, sequence and nonce. The runtime owns
one bounded UDP socket, at most ten probes, 32 receives per probe, 1000 ms per
probe and 15000 ms for setup plus the complete run. A conservative granted-time
axis bounds blocking calls even when the monotonic clock stalls or progresses
too slowly.

The conclusion order is exactly
`peer_reachable > local_error > cancelled > inconclusive_no_reply`. A single
authenticated matching reply is reachability proof; invalid and unrelated
datagrams remain telemetry. A no-reply run is always inconclusive and cannot
prove isolation. Before publication the command validates that per-probe and
aggregate counts, flags, run identity and conclusion are mutually consistent.
The token is scrubbed both at dispatcher rejection and on every handler exit;
history is freed and fixed internal copies are wiped. Versioned records contain
only topology, run identity, counters, timing and outcome, never token, nonce or
tag.

No firmware build, flash, owned-AP run, or device/network acceptance was
performed for this host gate. Device acceptance remains a separately approved
owned-lab matrix with isolation off/on, documented firewall and sleep state,
independent capture, repeated paired evidence and the rule that silence stays
inconclusive.

### Router Audit module registration

Router Audit is a synchronous command. Passive collection reads one immutable
connected-STA snapshot and cached gateway evidence and performs zero network
I/O. Standard collection is accepted only as `scan standard --owned`; it uses
the bounded gateway-only adapters and never takes a promiscuous callback,
changes a channel, downloads a catalog or adds a feature-specific Stop path.
The legacy console admission token is held until command return.

Catalog commands use one transferred PSRAM catalog allocation at a time. The
owned verify/install/recovery APIs clear caller handles before callbacks and
release them exactly once. An inactive slot is checked-sync'd and fully
verified before its journal is published; a serialized compare-and-advance
trusted NVS commit makes the catalog/signature pair-atomic from the command's
view. `PUBLISHED_UNCERTAIN` is retained when durable publication cannot be
proved. Installed lookup is evidence-only and runs only for a confirmed exact
identity.

The weak production trust-key provider is deliberately empty until a release
provisions an approved key ID and P-256 SPKI. It therefore returns
`UNKNOWN_KEY` instead of compiling a test key into firmware. Host tests execute
a real OpenSSL P-256/low-S path; the host Mbed TLS development package was
unavailable, so no ESP-IDF/Mbed TLS compile is claimed. There was no firmware
build, no real router, no real SD/NVS and no physical power-cut test.

## Host validation boundary

Host tests do not prove firmware compilation, FreeRTOS scheduling, driver
callback fence, RF reception, hardware cleanup, channel restore on device, or
SD durability. No RF/device validation is claimed. Portable C fixtures and
extracted adapter/console harnesses test bounded decoding/copying, generations,
counter semantics, cleanup ordering, failures/retry and modeled interleavings.
They do not replace ESP-IDF compilation or device acceptance. No persistence
backend or durability guarantee is added here.

A later controlled RF matrix requires separate approval and owned
WPA3-Personal APs. It must cover valid joins, retransmissions, bounded malformed
lab frames, Commit bursts, PMF modes and selected/unselected BSSIDs with an
independent capture. Acceptance must record zero JanOS TX. AP CPU or resource
impact requires AP-side evidence and cannot be inferred from JanOS reception.

Focused host gates:

```powershell
python -B -m unittest discover -s tests -p "test_wifi_security_*.py" -v
python -B -m unittest discover -s tests -p "test_wifi_trust_*.py" -v
python -B -m unittest discover -s tests -p "test_sae_guard_*.py" -v
python -B -m unittest discover -s tests -p "test_client_isolation_*.py" -v
python -B -m unittest discover -s tests -p "test_janos_console_admission.py" -v
python -B -m unittest discover -s tests -p "test_janos_wps_integration.py" -v
python -B -m unittest discover -s tests -p "test_legacy_console_registry.py" -v
python -B -m unittest discover -s tests -p "test_janos_console_startup.py" -v
```

Use WSL for full host C startup execution if the native command skips for lack
of a compiler. Stop at this host gate; ESP-IDF builds, flashing and RF/device
tests require separate approval.
