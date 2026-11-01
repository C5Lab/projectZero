#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t test_ap[6] = {2, 1, 2, 3, 4, 5};
static const uint8_t test_sta[6] = {4, 6, 7, 8, 9, 10};

static size_t make_key(uint8_t *f, unsigned qos, unsigned ids)
{
    memset(f, 0, 512);
    f[0] = qos ? 0x88 : 0x08;
    f[1] = 2;
    memcpy(f + 4, test_sta, 6);
    memcpy(f + 10, test_ap, 6);
    memcpy(f + 16, test_ap, 6);
    size_t offset = qos ? 26 : 24;
    const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    memcpy(f + offset, snap, 8);
    uint8_t *e = f + offset + 8;
    e[0] = 2;
    e[1] = 3;
    size_t body = 95 + ids * 22;
    e[2] = body >> 8;
    e[3] = body;
    uint8_t *k = e + 4;
    k[0] = 2;
    k[2] = 0x8a; /* M1: pairwise, ACK, descriptor version 2. */
    k[93] = (ids * 22) >> 8;
    k[94] = ids * 22;
    for (unsigned i = 0; i < ids; ++i) {
        uint8_t *p = k + 95 + i * 22;
        const uint8_t kde[] = {221, 20, 0, 0x0f, 0xac, 4};
        memcpy(p, kde, 6);
        memset(p + 6, i + 1, 16);
    }
    return offset + 8 + 4 + body;
}

static size_t make_assoc(uint8_t *f, unsigned kind, unsigned ids)
{
    memset(f, 0, 512);
    f[0] = kind;
    bool response = kind == 0x10 || kind == 0x30;
    memcpy(f + 4, response ? test_sta : test_ap, 6);
    memcpy(f + 10, response ? test_ap : test_sta, 6);
    memcpy(f + 16, test_ap, 6);
    size_t fixed = kind == 0 ? 4 : kind == 0x20 ? 10 : 6;
    uint8_t *ie = f + 24 + fixed;
    ie[0] = 0; ie[1] = 3; memcpy(ie + 2, "lab", 3);
    ie += 5;
    ie[0] = 48;
    ie[1] = 22 + ids * 16;
    uint8_t *r = ie + 2;
    r[0] = 1;
    r[2] = 0; r[3] = 0x0f; r[4] = 0xac; r[5] = 4;
    r[6] = 1;
    memcpy(r + 8, r + 2, 4);
    r[12] = 1;
    memcpy(r + 14, r + 2, 4);
    r[17] = 2;
    r[20] = ids;
    for (unsigned i = 0; i < ids; ++i) memset(r + 22 + i * 16, i + 1, 16);
    return (size_t)(r + 22 + ids * 16 - f);
}

static size_t make_beacon(uint8_t *f)
{
    memset(f, 0, 512);
    f[0] = 0x80;
    memset(f + 4, 0xff, 6);
    memcpy(f + 10, test_ap, 6);
    memcpy(f + 16, test_ap, 6);
    f[36] = 0; f[37] = 3;
    memcpy(f + 38, "lab", 3);
    return 41;
}
