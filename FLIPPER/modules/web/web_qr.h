#ifndef LAB_C5_WEB_QR_H
#define LAB_C5_WEB_QR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C5_WEB_QR_SSID_CAPACITY 33u
#define C5_WEB_QR_PASSWORD_CAPACITY 64u
#define C5_WEB_QR_TEXT_CAPACITY 256u

/* Initialize this structure to zero before its first use. Its encoded QR
 * buffer is owned only while the QR screen is open; call clear on exit. */
typedef struct {
    uint8_t* code;
    char ssid[C5_WEB_QR_SSID_CAPACITY];
    char pass[C5_WEB_QR_PASSWORD_CAPACITY];
    char error[24];
    bool valid;
} C5WebQr;

/* Existing Wi-Fi QR payload, including escaping of \\, ;, comma and colon.
 * Returns false rather than truncating an SSID/password or payload. */
bool c5_web_qr_make_payload(
    const char* ssid,
    const char* pass,
    char* output,
    size_t capacity);

bool c5_web_qr_build(C5WebQr* qr, const char* ssid, const char* pass);
void c5_web_qr_clear(C5WebQr* qr);
int c5_web_qr_size(const C5WebQr* qr);
bool c5_web_qr_get_module(const C5WebQr* qr, int x, int y);

#endif
