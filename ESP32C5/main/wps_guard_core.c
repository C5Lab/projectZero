#include "wps_guard_core.h"

#include <string.h>

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static bool unicast_address(const uint8_t address[6])
{
    return (address[0] & 1U) == 0 &&
           (address[0] | address[1] | address[2] |
            address[3] | address[4] | address[5]) != 0;
}

static void increment(uint32_t *counter)
{
    if (*counter != UINT32_MAX) ++*counter;
}

/* Copy only named metadata: even caller-owned struct padding is not retained. */
static void copy_fragment(wps_guard_fragment_t *out, const wps_guard_fragment_t *in)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->bssid, in->bssid, 6);
    memcpy(out->station, in->station, 6);
    out->direction = in->direction;
    out->eap_id = in->eap_id;
    out->opcode = in->opcode;
    out->flags = in->flags;
    out->declared_total = in->declared_total;
    out->payload_len = in->payload_len;
    out->payload_hash = in->payload_hash;
    out->timestamp_us = in->timestamp_us;
    out->channel = in->channel;
    out->rssi = in->rssi;
    out->length_present = in->length_present;
    out->more_fragments = in->more_fragments;
    out->input_truncated = in->input_truncated;
    out->envelope_reason = in->envelope_reason;
}

void wps_guard_core_init(wps_guard_core_t *core)
{
    if (core != NULL) memset(core, 0, sizeof(*core));
}

void wps_guard_reset(wps_guard_core_t *core)
{
    wps_guard_core_init(core);
}

void wps_guard_get_status(const wps_guard_core_t *core, wps_guard_status_t *status)
{
    if (status == NULL) return;
    memset(status, 0, sizeof(*status));
    if (core == NULL) return;
    *status = core->status;
    /* This is a bounded gauge rather than a cumulative counter. */
    status->active_sessions = 0;
    for (size_t i = 0; i < WPS_GUARD_MAX_SESSIONS; ++i) {
        if (core->sessions[i].active) ++status->active_sessions;
    }
}

bool wps_guard_decode_fragment(const wifi_security_decoded_t *frame,
                               bool input_truncated, uint64_t timestamp_us,
                               wps_guard_fragment_t *out)
{
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (frame == NULL || frame->protected_frame ||
        frame->kind != WIFI_SEC_FRAME_EAPOL || frame->eapol == NULL ||
        frame->to_ds == frame->from_ds ||
        !unicast_address(frame->bssid) || !unicast_address(frame->station) ||
        memcmp(frame->bssid, frame->station, 6) == 0) {
        return false;
    }
    const uint8_t *p = frame->eapol;
    const size_t length = frame->eapol_len;
    /* Through vendor type, independent of any untrusted length declarations. */
    if (length < 16 || p[1] != 0 || (p[4] != 1 && p[4] != 2) ||
        p[8] != 254 || p[9] != 0 || p[10] != 0x37 || p[11] != 0x2a ||
        p[12] != 0 || p[13] != 0 || p[14] != 0 || p[15] != 1) {
        return false;
    }

    memcpy(out->bssid, frame->bssid, 6);
    memcpy(out->station, frame->station, 6);
    out->direction = frame->from_ds ? WPS_GUARD_DIR_AP_TO_STA : WPS_GUARD_DIR_STA_TO_AP;
    out->eap_id = p[5];
    out->timestamp_us = timestamp_us;
    out->input_truncated = input_truncated;
    if (length > 16) out->opcode = p[16];
    if (length > 17) {
        out->flags = p[17];
        out->length_present = (p[17] & 2U) != 0;
        out->more_fragments = (p[17] & 1U) != 0;
    }
    if (input_truncated) {
        out->envelope_reason = WPS_GUARD_FRAME_TRUNCATED;
        return true;
    }
    out->envelope_reason = WPS_GUARD_INVALID_ENVELOPE;
    if (length < 18 || p[0] < 1 || p[0] > 3 ||
        read_be16(p + 2) != length - 4 || read_be16(p + 6) != length - 4 ||
        out->opcode < 1 || out->opcode > 6 || (out->flags & ~3U) != 0) {
        return true;
    }
    size_t offset = 18;
    if (out->length_present) {
        if (length < 20) return true;
        out->declared_total = read_be16(p + 18);
        offset = 20;
    }
    out->payload_len = (uint16_t)(length - offset);
    uint32_t hash = UINT32_C(2166136261);
    for (size_t i = offset; i < length; ++i) {
        hash ^= p[i];
        hash *= UINT32_C(16777619);
    }
    out->payload_hash = hash;
    out->envelope_reason = WPS_GUARD_NONE;
    return true;
}

bool wps_guard_payload_view(const wifi_security_decoded_t *frame,
                            const wps_guard_fragment_t *fragment,
                            const uint8_t **payload, size_t *length)
{
    if (payload != NULL) *payload = NULL;
    if (length != NULL) *length = 0;
    if (payload == NULL || length == NULL || fragment == NULL ||
        fragment->input_truncated || fragment->envelope_reason != WPS_GUARD_NONE)
        return false;
    wps_guard_fragment_t decoded;
    if (!wps_guard_decode_fragment(frame, false, fragment->timestamp_us, &decoded) ||
        decoded.envelope_reason != WPS_GUARD_NONE ||
        memcmp(decoded.bssid, fragment->bssid, 6) != 0 ||
        memcmp(decoded.station, fragment->station, 6) != 0 ||
        decoded.direction != fragment->direction || decoded.eap_id != fragment->eap_id ||
        decoded.opcode != fragment->opcode || decoded.flags != fragment->flags ||
        decoded.length_present != fragment->length_present ||
        decoded.more_fragments != fragment->more_fragments ||
        decoded.declared_total != fragment->declared_total ||
        decoded.payload_len != fragment->payload_len ||
        decoded.payload_hash != fragment->payload_hash)
        return false;
    const size_t offset = decoded.length_present ? 20U : 18U;
    *payload = frame->eapol + offset;
    *length = decoded.payload_len;
    return true;
}

static void record_reason(wps_guard_core_t *core, wps_guard_reason_t reason)
{
    increment(&core->status.reason_counts[reason]);
    if (reason == WPS_GUARD_RETRANSMISSION) increment(&core->status.retransmissions);
    else if (reason == WPS_GUARD_COMPLETE) increment(&core->status.completions);
    else if (reason == WPS_GUARD_SESSION_TIMEOUT) increment(&core->status.timeouts);
    else if (reason == WPS_GUARD_SESSION_CAPACITY) increment(&core->status.capacity_drops);
    else if ((reason >= WPS_GUARD_FIRST_MISSING_LENGTH &&
              reason <= WPS_GUARD_EMPTY_MORE_FRAGMENT) ||
             reason == WPS_GUARD_INVALID_ENVELOPE) increment(&core->status.anomalies);
}

static void set_event(wps_guard_event_t *event, const wps_guard_fragment_t *fragment,
                      wps_guard_reason_t reason, uint16_t declared,
                      uint32_t observed, uint32_t count, uint32_t retransmissions)
{
    if (event == NULL) return;
    memset(event, 0, sizeof(*event));
    copy_fragment(&event->fragment, fragment);
    event->reason = reason;
    event->declared_total = declared;
    event->observed_total = observed;
    event->fragment_count = count;
    event->retransmission_count = retransmissions;
}

size_t wps_guard_expire(wps_guard_core_t *core, uint64_t now_us,
                        wps_guard_event_t *events, size_t capacity)
{
    if (core == NULL) return 0;
    size_t written = 0;
    const uint64_t timeout_us = (uint64_t)WPS_GUARD_TIMEOUT_MS * 1000U;
    for (size_t i = 0; i < WPS_GUARD_MAX_SESSIONS; ++i) {
        wps_guard_session_t *session = &core->sessions[i];
        if (!session->active || now_us < session->last_seen_us ||
            now_us - session->last_seen_us <= timeout_us) continue;
        if (events != NULL && written < capacity) {
            set_event(&events[written++], &session->last_fragment,
                      WPS_GUARD_SESSION_TIMEOUT, session->declared_total,
                      session->observed_total, session->fragment_count,
                      session->retransmission_count);
        }
        record_reason(core, WPS_GUARD_SESSION_TIMEOUT);
        memset(session, 0, sizeof(*session));
    }
    return written;
}

static bool same_flow(const wps_guard_session_t *session, const wps_guard_fragment_t *f)
{
    return session->active && session->last_fragment.direction == f->direction &&
           memcmp(session->last_fragment.bssid, f->bssid, 6) == 0 &&
           memcmp(session->last_fragment.station, f->station, 6) == 0;
}

static bool identical_fragment(const wps_guard_fragment_t *a, const wps_guard_fragment_t *b)
{
    return a->eap_id == b->eap_id && a->opcode == b->opcode && a->flags == b->flags &&
           a->declared_total == b->declared_total && a->payload_len == b->payload_len &&
           a->payload_hash == b->payload_hash;
}

static wps_guard_reason_t envelope_reason(const wps_guard_fragment_t *f)
{
    if (f->input_truncated || f->envelope_reason == WPS_GUARD_FRAME_TRUNCATED)
        return WPS_GUARD_FRAME_TRUNCATED;
    if (f->envelope_reason != WPS_GUARD_NONE ||
        !unicast_address(f->bssid) || !unicast_address(f->station) ||
        memcmp(f->bssid, f->station, 6) == 0 ||
        (f->direction != WPS_GUARD_DIR_AP_TO_STA && f->direction != WPS_GUARD_DIR_STA_TO_AP) ||
        f->opcode < 1 || f->opcode > 6 || (f->flags & ~3U) != 0 ||
        f->length_present != ((f->flags & 2U) != 0) ||
        f->more_fragments != ((f->flags & 1U) != 0) ||
        (!f->length_present && f->declared_total != 0)) return WPS_GUARD_INVALID_ENVELOPE;
    return WPS_GUARD_NONE;
}

static void update_latest(wps_guard_session_t *session, const wps_guard_fragment_t *f)
{
    copy_fragment(&session->last_fragment, f);
    if (f->timestamp_us > session->last_seen_us) session->last_seen_us = f->timestamp_us;
}

wps_guard_reason_t wps_guard_observe(wps_guard_core_t *core,
                                     const wps_guard_fragment_t *f,
                                     wps_guard_event_t *event)
{
    if (event != NULL) memset(event, 0, sizeof(*event));
    if (core == NULL || f == NULL) {
        if (event != NULL) event->reason = WPS_GUARD_INVALID_ENVELOPE;
        return WPS_GUARD_INVALID_ENVELOPE;
    }
    (void)wps_guard_expire(core, f->timestamp_us, NULL, 0);
    increment(&core->status.fragments);
    wps_guard_session_t *session = NULL, *available = NULL;
    for (size_t i = 0; i < WPS_GUARD_MAX_SESSIONS; ++i) {
        if (same_flow(&core->sessions[i], f)) session = &core->sessions[i];
        else if (!core->sessions[i].active && available == NULL) available = &core->sessions[i];
    }
    uint16_t declared = session != NULL ? session->declared_total : f->declared_total;
    uint32_t observed = session != NULL ? session->observed_total : 0;
    uint32_t count = session != NULL ? session->fragment_count : 0;
    uint32_t retransmissions = session != NULL ? session->retransmission_count : 0;
    wps_guard_reason_t reason = envelope_reason(f);
    if (reason != WPS_GUARD_NONE) goto terminal;
    if (session != NULL && identical_fragment(&session->last_fragment, f)) {
        increment(&session->retransmission_count);
        retransmissions = session->retransmission_count;
        update_latest(session, f);
        reason = WPS_GUARD_RETRANSMISSION;
        goto report;
    }
    observed += f->payload_len; /* bounded by the declared limit plus one uint16_t */
    increment(&count);
    if (session != NULL) {
        const wps_guard_fragment_t *last = &session->last_fragment;
        if (last->eap_id == f->eap_id &&
            (last->payload_hash != f->payload_hash || last->payload_len != f->payload_len))
            reason = WPS_GUARD_EAP_ID_CONFLICT;
        else if (last->opcode != f->opcode) reason = WPS_GUARD_OPCODE_CHANGED;
        else if (f->length_present) reason = WPS_GUARD_REPEATED_LENGTH_FIELD;
        else if (last->eap_id == f->eap_id) reason = WPS_GUARD_INVALID_ENVELOPE;
    } else if (f->length_present && declared > WPS_GUARD_MAX_DECLARED) {
        reason = WPS_GUARD_DECLARED_OVER_LIMIT;
    }
    if (reason != WPS_GUARD_NONE) goto terminal;
    if (f->more_fragments && f->payload_len == 0) {
        reason = WPS_GUARD_EMPTY_MORE_FRAGMENT;
        goto terminal;
    }
    if (session == NULL && f->more_fragments) {
        if (!f->length_present) reason = WPS_GUARD_FIRST_MISSING_LENGTH;
        else if (declared <= f->payload_len) reason = WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST;
        else if (available == NULL) reason = WPS_GUARD_SESSION_CAPACITY;
        if (reason != WPS_GUARD_NONE) goto terminal;
        session = available;
        memset(session, 0, sizeof(*session));
        session->active = true;
        session->declared_total = declared;
    } else if ((session != NULL || f->length_present) && observed > declared) {
        reason = WPS_GUARD_OBSERVED_EXCEEDS_DECLARED;
        goto terminal;
    }
    if (!f->more_fragments) {
        reason = (session != NULL || f->length_present) && observed != declared ?
                 WPS_GUARD_FINAL_LENGTH_MISMATCH : WPS_GUARD_COMPLETE;
        goto terminal;
    }
    session->observed_total = observed;
    session->fragment_count = count;
    update_latest(session, f);
    goto report;

terminal:
    if (session != NULL) memset(session, 0, sizeof(*session));
report:
    set_event(event, f, reason, declared, observed, count, retransmissions);
    record_reason(core, reason);
    return reason;
}
