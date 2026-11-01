#include "pmkid_parser.h"

#include <string.h>

static unsigned le16(const uint8_t *p)
{
    return p[0] | ((unsigned)p[1] << 8);
}

static unsigned be16(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

static bool nonzero(const uint8_t *p, size_t n)
{
    uint8_t bits = 0;
    for (size_t i = 0; i < n; ++i) bits |= p[i];
    return bits != 0;
}

static size_t emit(const pmkid_identity_t *id, const uint8_t *p,
                   pmkid_visitor_t visitor, void *context)
{
    if (!nonzero(p, 16)) return 0;
    if (visitor) visitor(id, p, context);
    return 1;
}

static bool skip_suites(const uint8_t *p, size_t n, size_t *offset)
{
    if (n - *offset < 2) return false;
    size_t count = le16(p + *offset);
    *offset += 2;
    if (!count || count > (n - *offset) / 4) return false;
    *offset += count * 4;
    return true;
}

static size_t parse_rsn(const uint8_t *p, size_t n,
                        const pmkid_identity_t *id,
                        pmkid_visitor_t visitor, void *context)
{
    if (n < 6 || le16(p) != 1) return 0;
    size_t offset = 6; /* Version and group cipher. */
    if (!skip_suites(p, n, &offset) || !skip_suites(p, n, &offset)) return 0;
    if (n - offset < 4) return 0; /* Capabilities and PMKID count. */
    offset += 2;
    size_t count = le16(p + offset);
    offset += 2;
    if (count > (n - offset) / 16) return 0;
    /* Only the optional group-management cipher may follow the list. */
    size_t tail = n - offset - count * 16;
    if (tail != 0 && tail != 4) return 0;
    size_t found = 0;
    for (size_t i = 0; i < count; ++i) {
        found += emit(id, p + offset + i * 16, visitor, context);
    }
    return found;
}

size_t pmkid_parse_frame(const uint8_t *f, size_t n,
                        pmkid_visitor_t visitor, void *context)
{
    if (!f || n < 24 || (f[0] & 3) || (f[1] & 0x44)) return 0;
    /* Fragmented/protected frames need reassembly/decryption, which we do not do. */
    if (f[22] & 15) return 0;
    pmkid_identity_t id;
    uint8_t kind = f[0] & 0xfc;
    if ((f[0] & 0x0c) == 0x08) {
        unsigned ds = f[1] & 3;
        if (ds != 1 && ds != 2) return 0;
        memcpy(id.bssid, f + (ds == 1 ? 4 : 10), 6);
        memcpy(id.client, f + (ds == 1 ? 10 : 4), 6);
        if ((id.bssid[0] | id.client[0]) & 1) return 0;
        size_t offset = 24;
        if (f[0] & 0x80) {
            if (n - offset < 2 || (f[offset] & 0x80)) return 0; /* A-MSDU. */
            offset += 2;
            if (f[1] & 0x80) offset += 4; /* HT control. */
        }
        static const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
        if (offset > n || n - offset < sizeof(snap) + 4 ||
            memcmp(f + offset, snap, sizeof(snap))) return 0;
        offset += sizeof(snap);
        const uint8_t *e = f + offset;
        size_t body = be16(e + 2);
        if (e[1] != 3 || body < 95 || body > n - offset - 4) return 0;
        const uint8_t *key = e + 4;
        /* RSN descriptor, unencrypted pairwise key data only. */
        if (key[0] != 2 || !(be16(key + 1) & 0x0008) ||
            (be16(key + 1) & 0x1000)) return 0;
        size_t key_length = be16(key + 93);
        if (key_length != body - 95) return 0;
        const uint8_t *data = key + 95;
        /* Validate all TLVs before exposing any PMKID. */
        for (size_t i = 0; i < key_length;) {
            if (key_length - i < 2 || data[i + 1] > key_length - i - 2) return 0;
            i += 2 + data[i + 1];
        }
        size_t found = 0;
        for (size_t i = 0; i < key_length; i += 2 + data[i + 1]) {
            static const uint8_t oui_type[] = {0, 0x0f, 0xac, 4};
            if (data[i] == 221 && data[i + 1] == 20 &&
                !memcmp(data + i + 2, oui_type, sizeof(oui_type))) {
                found += emit(&id, data + i + 6, visitor, context);
            }
        }
        return found;
    }

    size_t fixed;
    switch (kind) {
        case 0x00: fixed = 4; break; /* Association request. */
        case 0x20: fixed = 10; break; /* Reassociation request. */
        case 0x10: case 0x30: fixed = 6; break; /* Responses. */
        default: return 0;
    }
    if (n < 24 + fixed || (f[1] & 3)) return 0;
    memcpy(id.bssid, f + 16, 6);
    bool response = kind == 0x10 || kind == 0x30;
    memcpy(id.client, f + (response ? 4 : 10), 6);
    if ((id.bssid[0] | id.client[0]) & 1 ||
        memcmp(id.bssid, f + (response ? 10 : 4), 6)) return 0;
    /* Validate IE boundaries before invoking visitors. A final four-byte FCS
     * cannot contain a PMKID IE and must not be interpreted as one. */
    size_t tags_end = 24 + fixed;
    while (tags_end < n) {
        size_t remaining = n - tags_end;
        if (remaining == 4) break;
        if (remaining < 2 || f[tags_end + 1] > remaining - 2) return 0;
        tags_end += 2 + f[tags_end + 1];
    }
    size_t found = 0;
    for (size_t i = 24 + fixed; i < tags_end;) {
        size_t length = f[i + 1];
        if (f[i] == 48) {
            found += parse_rsn(f + i + 2, length, &id, visitor, context);
        }
        i += 2 + length;
    }
    return found;
}

bool pmkid_is_capture_filename(const char *name)
{
    if (!name) return false;
    const char suffix[] = "_pmkid.pcap";
    size_t n = strlen(name);
    return n >= sizeof(suffix) - 1 &&
           !strcmp(name + n - (sizeof(suffix) - 1), suffix);
}
