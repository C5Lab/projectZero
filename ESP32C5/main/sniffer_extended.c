#include "sniffer_extended.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SX_WPS_IE_BYTES 512
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void wps_init(sx_wps_t *w) {
    memset(w,0,sizeof(*w));
    w->state = w->config_methods = w->setup_locked = w->selected_registrar = -1;
}
void sx_init(sx_ap_t *ap) {
    memset(ap,0,sizeof(*ap)); ap->hidden = ap->privacy = -1; wps_init(&ap->wps);
}
static bool selectors(const uint8_t *p, size_t len, size_t *pos,
                      uint8_t out[SX_SELECTORS][4], uint8_t *stored, bool *truncated) {
    if (len-*pos < 2) return false;
    uint16_t count = le16(p+*pos); *pos += 2;
    if (!count || count > (len-*pos)/4) return false;
    *stored = count > SX_SELECTORS ? SX_SELECTORS : (uint8_t)count;
    memcpy(out,p+*pos,(size_t)*stored*4); *truncated |= count > SX_SELECTORS;
    *pos += (size_t)count*4; return true;
}
/* Only encoded selectors are reported; omitted default fields remain unknown. */
static void security(const uint8_t *p, size_t len, bool rsn, sx_security_t *s) {
    memset(s,0,sizeof(*s)); s->status = SX_INVALID;
    if (len < 2 || le16(p) != 1) return;
    size_t pos = 2;
    if (pos == len) goto valid;
    if (len-pos < 4) return;
    memcpy(s->group,p+pos,4); s->group_present = true; pos += 4;
    if (pos == len) goto valid;
    if (!selectors(p,len,&pos,s->pairwise,&s->pairwise_count,&s->truncated)) return;
    s->pairwise_known = true;
    if (pos == len) goto valid;
    if (!selectors(p,len,&pos,s->akm,&s->akm_count,&s->truncated)) return;
    s->akm_known = true;
    if (pos == len) goto valid;
    if (len-pos < 2) return;
    uint16_t caps = le16(p+pos); pos += 2;
    if (rsn) { s->pmf_capable = (caps & 0x80) != 0; s->pmf_required = (caps & 0x40) != 0; }
    if (pos == len) goto valid;
    if (!rsn || len-pos < 2) return;
    uint16_t count = le16(p+pos); pos += 2;
    if (count > (len-pos)/16) return;
    pos += (size_t)count*16;
    if (pos == len) goto valid;
    if (len-pos != 4) return;
    memcpy(s->management,p+pos,4); s->management_present = true;
valid:
    s->status = SX_VALID;
}
static bool text_attr(sx_text_t *t, const uint8_t *p, size_t len, bool *truncated) {
    if (t->present) return false;
    t->present = true; t->len = len > SX_TEXT_BYTES ? SX_TEXT_BYTES : (uint8_t)len;
    t->truncated = len > SX_TEXT_BYTES; *truncated |= t->truncated;
    memcpy(t->bytes,p,t->len); return true;
}
static void wps_parse(const uint8_t *p, size_t len, sx_wps_t *w) {
    w->status = SX_INVALID;
    size_t pos = 0;
    while (pos < len) {
        if (len-pos < 4) return;
        uint16_t id = be16(p+pos), n = be16(p+pos+2); pos += 4;
        if (n > len-pos) return;
        const uint8_t *v = p+pos;
        switch (id) {
            case 0x1044:
                if (n != 1 || (v[0] != 1 && v[0] != 2) || w->state != -1) return;
                w->state = v[0]; break;
            case 0x1008:
                if (n != 2 || w->config_methods != -1) return;
                w->config_methods = be16(v); break;
            case 0x1057:
                if (n != 1 || v[0] > 1 || w->setup_locked != -1) return;
                w->setup_locked = v[0]; break;
            case 0x1041:
                if (n != 1 || v[0] > 1 || w->selected_registrar != -1) return;
                w->selected_registrar = v[0]; break;
            case 0x1021: if (!text_attr(&w->manufacturer,v,n,&w->truncated)) return; break;
            case 0x1023: if (!text_attr(&w->model_name,v,n,&w->truncated)) return; break;
            case 0x1024: if (!text_attr(&w->model_number,v,n,&w->truncated)) return; break;
            case 0x1011: if (!text_attr(&w->device_name,v,n,&w->truncated)) return; break;
            default: break;
        }
        pos += n;
    }
    w->status = SX_VALID;
}
bool sx_parse(const uint8_t *f, size_t len, sx_observation_t *o) {
    if (!f || !o || len < 24 || (f[0]&0x0f) || (f[1]&0xc7) || (f[22]&0x0f)) return false;
    sx_source_t source; size_t fixed;
    switch (f[0]) {
        case 0x80: source = SX_BEACON; fixed = 12; break;
        case 0x50: source = SX_PROBE_RESP; fixed = 12; break;
        case 0x00: source = SX_ASSOC_REQ; fixed = 4; break;
        case 0x20: source = SX_REASSOC_REQ; fixed = 10; break;
        default: return false;
    }
    bool advertisement = source == SX_BEACON || source == SX_PROBE_RESP;
    const uint8_t *bssid = f+16;
    if ((bssid[0]&1) || !memcmp(bssid,"\0\0\0\0\0\0",6) ||
        memcmp(bssid,f+(advertisement ? 10 : 4),6)) return false;
    if (!advertisement && ((f[10]&1) || !memcmp(f+10,"\0\0\0\0\0\0",6) ||
                           !memcmp(f+10,bssid,6))) return false;
    memset(o,0,sizeof(*o)); wps_init(&o->wps);
    memcpy(o->bssid,bssid,6); o->source = source; o->hidden = o->privacy = -1;
    if (len < 24+fixed) return true;
    if (advertisement) o->privacy = (le16(f+34)&0x10) != 0;
    size_t pos = 24+fixed, wps_len = 0;
    uint8_t wps_bytes[SX_WPS_IE_BYTES];
    bool wps_seen = false, wps_overflow = false;
    while (pos < len) {
        if (len-pos < 2) return true;
        uint8_t id = f[pos], n = f[pos+1]; pos += 2;
        if (n > len-pos) return true;
        const uint8_t *p = f+pos;
        if (id == 0) {
            if (n > 32 || o->ssid_present) return true;
            o->ssid_present = true; o->ssid_len = n; memcpy(o->ssid,p,n);
            if (source == SX_BEACON) {
                bool zero = true;
                for (unsigned i=0; i<n; ++i) zero &= p[i] == 0;
                o->hidden = zero ? 1 : 0;
            }
        } else if (advertisement && id == 48) {
            if (o->rsn.status != SX_UNKNOWN) return true;
            security(p,n,true,&o->rsn);
        } else if (advertisement && id == 221 && n >= 4 &&
                   p[0] == 0 && p[1] == 0x50 && p[2] == 0xf2) {
            if (p[3] == 1) {
                if (o->wpa.status != SX_UNKNOWN) return true;
                security(p+4,n-4,false,&o->wpa);
            } else if (p[3] == 4) {
                wps_seen = true;
                if (n-4U > sizeof(wps_bytes)-wps_len) wps_overflow = true;
                else if (!wps_overflow) { memcpy(wps_bytes+wps_len,p+4,n-4U); wps_len += n-4U; }
            }
        }
        pos += n;
    }
    if (!o->ssid_present) return true;
    o->complete = true;
    if (advertisement) {
        if (o->rsn.status == SX_UNKNOWN) o->rsn.status = SX_ABSENT;
        if (o->wpa.status == SX_UNKNOWN) o->wpa.status = SX_ABSENT;
        if (wps_seen) {
            o->wps.present = true;
            if (wps_overflow) { o->wps.status = SX_INVALID; o->wps.truncated = true; }
            else wps_parse(wps_bytes,wps_len,&o->wps);
        } else o->wps.status = SX_ABSENT;
    }
    return true;
}
void sx_apply(sx_ap_t *ap, const sx_observation_t *o) {
    if (o->complete && o->ssid_present && o->ssid_len && o->hidden != 1) {
        memcpy(ap->resolved_ssid,o->ssid,o->ssid_len);
        ap->resolved_len = o->ssid_len; ap->ssid_source = o->source;
    }
    if (o->source != SX_BEACON && o->source != SX_PROBE_RESP) return;
    ap->profile_source = o->source; ap->frame_status = o->complete ? SX_VALID : SX_INVALID;
    if (!o->complete) {
        memset(&ap->rsn,0,sizeof(ap->rsn)); memset(&ap->wpa,0,sizeof(ap->wpa)); wps_init(&ap->wps);
        ap->rsn.status = ap->wpa.status = ap->wps.status = SX_INVALID; ap->privacy = -1; return;
    }
    if (o->source == SX_BEACON) ap->hidden = o->hidden;
    ap->privacy = o->privacy; ap->rsn = o->rsn; ap->wpa = o->wpa; ap->wps = o->wps;
    if (o->rsn.status == SX_INVALID || o->wpa.status == SX_INVALID || o->wps.status == SX_INVALID)
        ap->frame_status = SX_INVALID;
}

typedef struct { char *out; size_t cap, used; bool failed; } writer_t;
static void append(writer_t *w, const char *fmt, ...) {
    if (w->failed) return;
    va_list args; va_start(args,fmt);
    int n = vsnprintf(w->out+w->used,w->cap-w->used,fmt,args); va_end(args);
    if (n < 0 || (size_t)n >= w->cap-w->used) w->failed = true; else w->used += (size_t)n;
}
static void hex(writer_t *w, const uint8_t *p, size_t len) {
    for (size_t i=0; i<len; ++i) append(w,"%02X",p[i]);
}
static const char *status(sx_status_t s) {
    switch (s) { case SX_ABSENT: return "absent"; case SX_VALID: return "valid";
        case SX_INVALID: return "invalid"; default: return "unknown"; }
}
static const char *source(sx_source_t s) {
    switch (s) { case SX_BEACON: return "beacon"; case SX_PROBE_RESP: return "probe_resp";
        case SX_ASSOC_REQ: return "assoc_req"; case SX_REASSOC_REQ: return "reassoc_req";
        default: return "unknown"; }
}
static void number(writer_t *w, const char *key, int value) {
    append(w," | %s=",key); if (value < 0) append(w,"unknown"); else append(w,"%d",value);
}
static void selector_field(writer_t *w, const char *prefix, const char *key,
                           const uint8_t *p, bool present, sx_status_t state) {
    append(w," | %s_%s=",prefix,key);
    if (state != SX_VALID) append(w,state == SX_ABSENT ? "absent" : "unknown");
    else if (present) hex(w,p,4); else append(w,"unknown");
}
static void list_field(writer_t *w, const char *prefix, const char *key,
                       const uint8_t values[SX_SELECTORS][4], uint8_t count, bool known, sx_status_t state) {
    append(w," | %s_%s=",prefix,key);
    if (state != SX_VALID || !known) append(w,state == SX_ABSENT ? "absent" : "unknown");
    else for (unsigned i=0; i<count; ++i) { if (i) append(w,","); hex(w,values[i],4); }
}
static void format_security(writer_t *w, const char *prefix, const sx_security_t *s) {
    append(w," | %s_status=%s",prefix,status(s->status));
    selector_field(w,prefix,"group",s->group,s->group_present,s->status);
    list_field(w,prefix,"pairwise",s->pairwise,s->pairwise_count,s->pairwise_known,s->status);
    list_field(w,prefix,"akm",s->akm,s->akm_count,s->akm_known,s->status);
    if (!strcmp(prefix,"rsn")) {
        selector_field(w,prefix,"group_mgmt",s->management,s->management_present,s->status);
        number(w,"pmf_capable",s->status == SX_VALID ? s->pmf_capable : -1);
        number(w,"pmf_required",s->status == SX_VALID ? s->pmf_required : -1);
    }
    append(w," | %s_truncated=%d",prefix,s->truncated);
}
static void format_text(writer_t *w, const char *key, const sx_text_t *t, bool valid) {
    append(w," | %s_hex=",key);
    if (!valid || !t->present) append(w,"unknown"); else hex(w,t->bytes,t->len);
    append(w," | %s_truncated=%d",key,valid && t->truncated);
}
static size_t finish(writer_t *w) {
    if (w->failed) { if (w->cap) w->out[0] = 0; return 0; } return w->used;
}
size_t sx_format_ap(char *out, size_t cap, const sx_ap_t *ap, const uint8_t bssid[6],
                    int rssi, bool known, uint32_t last, bool seen, uint32_t now) {
    writer_t w = {out,cap,0,cap == 0};
    append(&w," | ext_ver=1 | bssid=%02X:%02X:%02X:%02X:%02X:%02X",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
    append(&w," | rssi="); if (known) append(&w,"%d",rssi); else append(&w,"unknown");
    append(&w," | age_ms="); if (seen) append(&w,"%lu",(unsigned long)(now-last)); else append(&w,"unknown");
    number(&w,"hidden",ap->hidden); append(&w," | resolved_ssid_hex=");
    if (ap->ssid_source == SX_NONE) append(&w,"unknown"); else hex(&w,ap->resolved_ssid,ap->resolved_len);
    append(&w," | ssid_source=%s | profile_source=%s | frame_status=%s",source(ap->ssid_source),source(ap->profile_source),status(ap->frame_status));
    number(&w,"privacy",ap->privacy); format_security(&w,"rsn",&ap->rsn); format_security(&w,"wpa",&ap->wpa);
    append(&w," | wps_status=%s",status(ap->wps.status));
    number(&w,"wps_present",ap->wps.present ? 1 : ap->wps.status == SX_ABSENT ? 0 : -1);
    bool valid = ap->wps.status == SX_VALID;
    number(&w,"wps_state",valid ? ap->wps.state : -1);
    number(&w,"wps_config_methods",valid ? ap->wps.config_methods : -1);
    number(&w,"wps_setup_locked",valid ? ap->wps.setup_locked : -1);
    number(&w,"wps_selected_registrar",valid ? ap->wps.selected_registrar : -1);
    format_text(&w,"wps_manufacturer",&ap->wps.manufacturer,valid);
    format_text(&w,"wps_model_name",&ap->wps.model_name,valid);
    format_text(&w,"wps_model_number",&ap->wps.model_number,valid);
    format_text(&w,"wps_device_name",&ap->wps.device_name,valid);
    append(&w," | wps_truncated=%d",ap->wps.truncated); return finish(&w);
}
size_t sx_format_client(char *out, size_t cap, int rssi, bool known, uint32_t last, uint32_t now) {
    writer_t w = {out,cap,0,cap == 0};
    append(&w," | ext_ver=1 | rssi=");
    if (known) append(&w,"%d",rssi); else append(&w,"unknown");
    append(&w," | age_ms=%lu",(unsigned long)(now-last)); return finish(&w);
}
