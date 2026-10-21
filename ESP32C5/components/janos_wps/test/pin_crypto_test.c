#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pin_crypto.h"

static void hex(const char *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        assert(sscanf(s + 2 * i, "%2x", &v) == 1);
        out[i] = (uint8_t)v;
    }
}

int main(void) {
    uint8_t shared[192], ne[16], nr[16], pke[192], pkr[192];
    for (size_t i = 0; i < sizeof(shared); i++) shared[i] = (uint8_t)i;
    for (size_t i = 0; i < 16; i++) { ne[i] = (uint8_t)i; nr[i] = (uint8_t)(i + 16); }
    memset(pke, 3, sizeof(pke)); memset(pkr, 11, sizeof(pkr));
    const uint8_t mac[6] = {2,0,0,0,0,1};
    pin_keys_t keys;
    assert(pin_derive_keys(shared, ne, mac, nr, &keys));
    uint8_t expected[80];
    hex("cec822affb4b78ca26d0f698ecc42d793bb5cd826ba1f0838adc19fee9623980"
        "c675240c5700236a32389636dc186967f141008f51e4e4c39259459dc6fc092c1"
        "a7a153d690bc26ef93329d09af51db1", expected, sizeof(expected));
    assert(memcmp(&keys, expected, sizeof(expected)) == 0);

    uint8_t psk1[16], psk2[16], want1[16], want2[16];
    assert(pin_derive_psks(keys.authkey, "12345670", 8, psk1, psk2));
    hex("9469cb094bdcb4b32c8e9be90ac02f39", want1, 16);
    hex("3f8d88c160caa2edae134a7f3a578727", want2, 16);
    assert(memcmp(psk1, want1, 16) == 0 && memcmp(psk2, want2, 16) == 0);
    assert(!pin_derive_psks(keys.authkey, "1234567x", 8, psk1, psk2));
    assert(!pin_derive_psks(keys.authkey, "123", 3, psk1, psk2));

    uint8_t rs1[16], rs2[16], got[32], want[32];
    for (size_t i = 0; i < 16; i++) { rs1[i] = (uint8_t)(i + 32); rs2[i] = (uint8_t)(i + 48); }
    assert(pin_commitment(keys.authkey, rs1, want1, pke, pkr, got));
    hex("f8918092cde7a9d68c2c8e813c3e37b048ee3d2824f7fe600a662d9d332a840e", want, 32);
    assert(memcmp(got, want, 32) == 0);
    assert(pin_commitment(keys.authkey, rs2, want2, pke, pkr, got));
    hex("43c0cc416c12892f51fe8b97811510af2bf125a501a74630527fde32206570f1", want, 32);
    assert(memcmp(got, want, 32) == 0);

    uint8_t plain[20] = {0x10,0x3f,0x00,0x10};
    memcpy(plain + 4, rs1, 16);
    uint8_t kwa[8], want_kwa[8];
    assert(pin_kwa(keys.authkey, plain, sizeof(plain), kwa));
    hex("3cb1d642f8576a07", want_kwa, 8);
    assert(memcmp(kwa, want_kwa, 8) == 0);

    uint8_t iv[16] = {0}, encrypted[80], decrypted[80]; size_t enc_len = 0, dec_len = 0;
    assert(pin_encrypt_settings(keys.keywrapkey, iv, plain, sizeof(plain), encrypted, sizeof(encrypted), &enc_len));
    assert(enc_len == 16 + 32);
    assert(pin_decrypt_settings(keys.keywrapkey, encrypted, enc_len, decrypted, sizeof(decrypted), &dec_len));
    assert(dec_len == sizeof(plain) && memcmp(decrypted, plain, sizeof(plain)) == 0);
    encrypted[enc_len - 1] ^= 1;
    assert(!pin_decrypt_settings(keys.keywrapkey, encrypted, enc_len, decrypted, sizeof(decrypted), &dec_len));

    uint8_t private_value[192], peer[192], public_value[192], dh_shared[192];
    uint8_t expected_public[192], expected_shared[192];
    for (size_t i = 0; i < sizeof(private_value); i++) private_value[i] = (uint8_t)i;
    hex("3803188372c4464b68b267a41431e7583ba86108b53901bb77b1f5992f2f99c3"
        "1dfb5712fa8fad1c58792337afaad7024992668ec080cb65259ccc38cd57de89c"
        "93060bed39604a0ef44e7c89fcaff0d7ae099e6ffaf86ec0ace493de7aa91d6d"
        "5bc51c93cd5bd04d7a3fbc26c0076ad9c7fb19f040070c078aa795476daee9e6"
        "ad902dfb9d0e627c8ede313bb4de814c5fe74e7134a2baaa790e4672ebd02da6e"
        "303db996d05698d689cce7bbfc7923f7195278b8c8dc0c433495cc56bb219c", peer, 192);
    hex("2a0c5426c0027f4c821ef5eef37738bc885edf46fe01c90bbd09655f9061ee3f"
        "d49a4575167947ff41838f711f1e740df6aaa693362fb2b8553a3f035d40de5c"
        "0da060760125a78109a25a36f37178211d3651998b32ee84f6f93614f618e46d"
        "9a3ca6c2087baf1c04ec2dd44cf02929db351d9a7c430b2fd90dbc79d95b3e49"
        "3c593e0f224e756239ba3f3d467e64de9190b5e9f6e133e729a4a0da200daeda"
        "ceda3ff6d0443dd6f96bb199855573837b3f4e9af3eeb1d5b5c0990dd72c8e3b", expected_public, 192);
    hex("cbc5256ae41ee7f24ca7851707babc37401765d999af969dc0552c31c6f6e958"
        "9e50ab77f037a6f6e49e599317f6b84118e11976aa859c8f3241c56916d1bbf9"
        "483d94a205dccda40b8a52dc29797d55663de282f5b53b4c5ce5272d1c203f8c"
        "af438f061be941bfd796c6df98124fb6a5598e7ae0998f6538fafadc451ef1048"
        "76ae2d5074649fe1e29b9b76e88683989820e5ada47d7f5c3d3a4506ab6982f6"
        "2015bbead9dadb08139c433b19fcf6f3244afb83e70db74ada2654fb96cdc8c", expected_shared, 192);
    assert(pin_group5_compute(private_value, peer, public_value, dh_shared));
    assert(memcmp(public_value, expected_public, 192) == 0);
    assert(memcmp(dh_shared, expected_shared, 192) == 0);
    memset(peer, 0, sizeof(peer)); peer[191] = 1;
    assert(!pin_group5_compute(private_value, peer, public_value, dh_shared));
    puts("PASS: full KDF, PIN halves, commitments, KWA and AES settings");
}
