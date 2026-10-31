#include "../modules/web/web_qr.h"
#include "../qrcodegen.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_wifi_payload(void) {
    char payload[C5_WEB_QR_TEXT_CAPACITY];
    assert(c5_web_qr_make_payload("Lab;C5,2:4\\", "pa;ss,wo:rd\\", payload, sizeof(payload)));
    assert(strcmp(payload, "WIFI:T:WPA;S:Lab\\;C5\\,2\\:4\\\\;P:pa\\;ss\\,wo\\:rd\\\\;;") == 0);
    assert(c5_web_qr_make_payload("Open Network", "", payload, sizeof(payload)));
    assert(strcmp(payload, "WIFI:T:nopass;S:Open Network;;") == 0);
    assert(!c5_web_qr_make_payload("Lab", "pw", payload, 8));
}

static void test_matrix_matches_existing_encoder(void) {
    const char* ssid = "LAB5; Test";
    const char* password = "a:b,c\\d";
    char payload[C5_WEB_QR_TEXT_CAPACITY];
    assert(c5_web_qr_make_payload(ssid, password, payload, sizeof(payload)));

    C5WebQr qr = {0};
    assert(c5_web_qr_build(&qr, ssid, password));
    assert(qr.valid);
    assert(strcmp(qr.ssid, ssid) == 0 && strcmp(qr.pass, password) == 0);
    assert(qr.error[0] == '\0');

    uint8_t temp[qrcodegen_BUFFER_LEN_FOR_VERSION(10)];
    uint8_t reference[qrcodegen_BUFFER_LEN_FOR_VERSION(10)];
    assert(qrcodegen_encodeText(
        payload, temp, reference, qrcodegen_Ecc_MEDIUM, 1, 10, qrcodegen_Mask_AUTO, true));
    int size = qrcodegen_getSize(reference);
    assert(c5_web_qr_size(&qr) == size);
    for(int y = 0; y < size; ++y) {
        for(int x = 0; x < size; ++x) {
            assert(c5_web_qr_get_module(&qr, x, y) == qrcodegen_getModule(reference, x, y));
        }
    }
    assert(!c5_web_qr_get_module(&qr, -1, 0));
    assert(!c5_web_qr_get_module(&qr, size, size));
    c5_web_qr_clear(&qr);
    assert(!qr.valid && !qr.code && c5_web_qr_size(&qr) == 0);
}

static void test_bounded_input_and_reuse(void) {
    C5WebQr qr = {0};
    assert(c5_web_qr_build(&qr, "Lab", NULL));
    assert(c5_web_qr_build(&qr, "Open", ""));
    assert(strcmp(qr.ssid, "Open") == 0);
    char too_long[C5_WEB_QR_SSID_CAPACITY + 2];
    memset(too_long, 'A', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    assert(!c5_web_qr_build(&qr, too_long, "pw"));
    assert(!qr.valid && !qr.code);
    assert(strcmp(qr.error, "SSID/pass too long") == 0);
    c5_web_qr_clear(&qr);
}

int main(void) {
    test_wifi_payload();
    test_matrix_matches_existing_encoder();
    test_bounded_input_and_reuse();
    puts("Web QR tests passed");
    return 0;
}
