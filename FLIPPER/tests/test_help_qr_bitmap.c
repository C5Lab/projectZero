#include "../gfx/help_qr_bitmap.h"
#include "../qrcodegen.h"

#include <stdio.h>

int main(void) {
    const char* url = "https://github.com/C5Lab/projectZero/wiki";
    uint8_t temp[qrcodegen_BUFFER_LEN_FOR_VERSION(10)];
    uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(10)];
    if(!qrcodegen_encodeText(
           url,
           temp,
           qr,
           qrcodegen_Ecc_MEDIUM,
           1,
           10,
           qrcodegen_Mask_AUTO,
           true)) {
        fputs("Reference QR encoding failed\n", stderr);
        return 1;
    }

    int size = qrcodegen_getSize(qr);
    if(size != LAB_C5_HELP_QR_SIZE) {
        fprintf(stderr, "QR size: expected %d, asset %d\n", size, LAB_C5_HELP_QR_SIZE);
        return 1;
    }
    if(sizeof(lab_c5_help_qr_bitmap) != (size_t)((size * size + 7) / 8)) {
        fputs("QR bitmap length mismatch\n", stderr);
        return 1;
    }
    for(int y = 0; y < size; y++) {
        for(int x = 0; x < size; x++) {
            bool expected = qrcodegen_getModule(qr, x, y);
            bool actual = lab_c5_help_qr_get_module(x, y);
            if(actual != expected) {
                fprintf(stderr, "QR module mismatch at (%d, %d)\n", x, y);
                return 1;
            }
        }
    }
    if(lab_c5_help_qr_get_module(-1, 0) || lab_c5_help_qr_get_module(size, 0) ||
       lab_c5_help_qr_get_module(0, -1) || lab_c5_help_qr_get_module(0, size)) {
        fputs("Out-of-range QR module should be light\n", stderr);
        return 1;
    }
    puts("Help QR bitmap matches qrcodegen");
    return 0;
}
