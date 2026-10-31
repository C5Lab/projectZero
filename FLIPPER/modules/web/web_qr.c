#include "web_qr.h"

#include "../../qrcodegen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define C5_WEB_QR_MAX_VERSION 10
#define C5_WEB_QR_BUFFER_LENGTH qrcodegen_BUFFER_LEN_FOR_VERSION(C5_WEB_QR_MAX_VERSION)

static bool c5_web_qr_input_length(const char* value, size_t capacity, size_t* length) {
    if(!value || !length) return false;
    for(size_t i = 0; i < capacity; ++i) {
        if(value[i] == '\0') {
            *length = i;
            return true;
        }
    }
    return false;
}

static bool c5_web_qr_escape(
    const char* input,
    size_t input_length,
    char* output,
    size_t capacity) {
    size_t pos = 0;
    for(size_t i = 0; i < input_length; ++i) {
        char ch = input[i];
        if(ch == '\\' || ch == ';' || ch == ',' || ch == ':') {
            if(pos + 2 >= capacity) return false;
            output[pos++] = '\\';
        } else if(pos + 1 >= capacity) {
            return false;
        }
        output[pos++] = ch;
    }
    output[pos] = '\0';
    return true;
}

bool c5_web_qr_make_payload(
    const char* ssid,
    const char* pass,
    char* output,
    size_t capacity) {
    if(!output || capacity == 0) return false;
    output[0] = '\0';
    if(!ssid) return false;
    if(!pass) pass = "";

    size_t ssid_length = 0;
    size_t pass_length = 0;
    if(!c5_web_qr_input_length(ssid, C5_WEB_QR_SSID_CAPACITY, &ssid_length) ||
       !c5_web_qr_input_length(pass, C5_WEB_QR_PASSWORD_CAPACITY, &pass_length)) {
        return false;
    }

    char ssid_escaped[C5_WEB_QR_SSID_CAPACITY * 2];
    char pass_escaped[C5_WEB_QR_PASSWORD_CAPACITY * 2];
    if(!c5_web_qr_escape(
           ssid, ssid_length, ssid_escaped, sizeof(ssid_escaped)) ||
       !c5_web_qr_escape(
           pass, pass_length, pass_escaped, sizeof(pass_escaped))) {
        return false;
    }

    int required = pass_escaped[0] == '\0'
                       ? snprintf(output, capacity, "WIFI:T:nopass;S:%s;;", ssid_escaped)
                       : snprintf(
                             output,
                             capacity,
                             "WIFI:T:WPA;S:%s;P:%s;;",
                             ssid_escaped,
                             pass_escaped);
    if(required < 0 || (size_t)required >= capacity) {
        output[0] = '\0';
        return false;
    }
    return true;
}

void c5_web_qr_clear(C5WebQr* qr) {
    if(!qr) return;
    free(qr->code);
    qr->code = NULL;
    qr->ssid[0] = '\0';
    qr->pass[0] = '\0';
    qr->error[0] = '\0';
    qr->valid = false;
}

bool c5_web_qr_build(C5WebQr* qr, const char* ssid, const char* pass) {
    if(!qr) return false;
    c5_web_qr_clear(qr);

    char payload[C5_WEB_QR_TEXT_CAPACITY];
    if(!c5_web_qr_make_payload(ssid, pass, payload, sizeof(payload))) {
        strcpy(qr->error, "SSID/pass too long");
        return false;
    }

    uint8_t* code = malloc(C5_WEB_QR_BUFFER_LENGTH);
    uint8_t* work = malloc(C5_WEB_QR_BUFFER_LENGTH);
    if(!code || !work) {
        free(code);
        free(work);
        strcpy(qr->error, "QR OOM");
        return false;
    }

    bool encoded = qrcodegen_encodeText(
        payload,
        work,
        code,
        qrcodegen_Ecc_MEDIUM,
        1,
        C5_WEB_QR_MAX_VERSION,
        qrcodegen_Mask_AUTO,
        true);
    free(work);
    if(!encoded) {
        free(code);
        strcpy(qr->error, "QR too long");
        return false;
    }

    qr->code = code;
    qr->valid = true;
    memcpy(qr->ssid, ssid, strlen(ssid) + 1);
    if(pass) memcpy(qr->pass, pass, strlen(pass) + 1);
    return true;
}

int c5_web_qr_size(const C5WebQr* qr) {
    return qr && qr->valid && qr->code ? qrcodegen_getSize(qr->code) : 0;
}

bool c5_web_qr_get_module(const C5WebQr* qr, int x, int y) {
    int size = c5_web_qr_size(qr);
    if(x < 0 || y < 0 || x >= size || y >= size) return false;
    return qrcodegen_getModule(qr->code, x, y);
}
