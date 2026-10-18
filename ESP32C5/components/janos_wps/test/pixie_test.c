#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pixie.h"
#include "pixie_prng.h"

static void hex(const char *text, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned value = 0;
        assert(sscanf(text + i * 2, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
}

static pixie_bundle_t fixture(const char *hash1, const char *hash2) {
    pixie_bundle_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    memset(bundle.authkey, 0x11, sizeof(bundle.authkey));
    memset(bundle.pke, 0x22, sizeof(bundle.pke));
    memset(bundle.pkr, 0x33, sizeof(bundle.pkr));
    memset(bundle.e_nonce, 0x44, sizeof(bundle.e_nonce));
    hex(hash1, bundle.e_hash1, sizeof(bundle.e_hash1));
    hex(hash2, bundle.e_hash2, sizeof(bundle.e_hash2));
    return bundle;
}

static void test_prng_vectors(void) {
    uint8_t nonce[16], want_nonce[16], want_stream[48], stream[48], e_s1[16], e_s2[16];
    pixie_glibc_nonce(1, nonce);
    hex("6b8b4567327b23c6643c986966334873", want_nonce, sizeof(want_nonce));
    assert(memcmp(nonce, want_nonce, sizeof(want_nonce)) == 0);
    assert(pixie_glibc_first_word(1700000000u) == 280491303u);

    uint32_t seed = 0;
    pixie_glibc_nonce(1700000000u, nonce);
    assert(pixie_find_glibc_nonce_seed(nonce, 1700000003u, 1699999997u, &seed));
    assert(seed == 1700000000u);

    pixie_ralink_forward(0x12345678u, stream, sizeof(stream));
    hex("12d0569430fd13d35752ab38c5454bce1ea40bdbf44c85835dfcf5bb9a638d8"
        "3a37e0832d9f84a7ae4ad499bfcbe6a32", want_stream, sizeof(want_stream));
    assert(memcmp(stream, want_stream, sizeof(want_stream)) == 0);
    assert(pixie_ralink_recover(stream + 32, e_s1, e_s2));
    assert(memcmp(e_s1, stream, 16) == 0);
    assert(memcmp(e_s2, stream + 16, 16) == 0);
    stream[32] ^= 0xff;
    assert(!pixie_ralink_recover(stream + 32, e_s1, e_s2));
}

static void test_null_and_wrong_checksum(void) {
    pixie_options_t options = {.modes = PIXIE_MODE_NULL_SECRET, .yield_every = 128};
    pixie_result_t result;
    pixie_bundle_t bundle = fixture(
        "b31dec125290ad933c08433ee5448b6b7e9c80bc157457667bbcb6f3b383b8df",
        "0029888438664899e3470060c53562e93243ddddd4113bca027f5eb97cbfbffe");
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found && result.mode == PIXIE_MODE_NULL_SECRET);
    assert(strcmp(result.pin, "12345670") == 0);

    bundle = fixture(
        "b31dec125290ad933c08433ee5448b6b7e9c80bc157457667bbcb6f3b383b8df",
        "f976ce87e189ebc230974c1a3c46cc441fa052055a348b8edd87b84a19f6a459");
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found && strcmp(result.pin, "12345678") == 0);
}

static void test_static_and_no_match(void) {
    pixie_bundle_t bundle = fixture(
        "52a8b9f0c731552ad1ec9c8f4e4384b03f5e8c669f2815875948f5d415781ecc",
        "ea5cc8707296fe1c2399fdead17c1a5fc04a6a1b6629f5d9c539c754577f4495");
    pixie_secret_pair_t pairs[2];
    memset(&pairs, 0x56, sizeof(pairs));
    memset(pairs[1].e_s1, 0x12, sizeof(pairs[1].e_s1));
    memset(pairs[1].e_s2, 0x34, sizeof(pairs[1].e_s2));
    pixie_options_t options = {
        .modes = PIXIE_MODE_STATIC_SECRET,
        .static_secrets = pairs,
        .static_secret_count = 2,
    };
    pixie_result_t result;
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found && result.mode == PIXIE_MODE_STATIC_SECRET);
    assert(strcmp(result.pin, "01030365") == 0);

    options.modes = PIXIE_MODE_NULL_SECRET;
    assert(pixie_recover(&bundle, &options, &result));
    assert(!result.found && result.mode == PIXIE_MODE_NONE);
}

static void test_ralink_and_rtl(void) {
    pixie_result_t result;
    pixie_options_t options = {.modes = PIXIE_MODE_RALINK};
    pixie_bundle_t bundle = fixture(
        "214b4e1f4b72e421b112ff3a93b7fe7c3e0cc4ce5f0588a8df33f2b5f0320b7b",
        "b7477844d97c1c3632819916be1c854f21a1adac5558cc785064434d17988897");
    hex("a37e0832d9f84a7ae4ad499bfcbe6a32", bundle.e_nonce, 16);
    uint8_t recovered_s1[16], recovered_s2[16], expected_s1[16], expected_s2[16];
    assert(pixie_ralink_recover(bundle.e_nonce, recovered_s1, recovered_s2));
    hex("12d0569430fd13d35752ab38c5454bce", expected_s1, 16);
    hex("1ea40bdbf44c85835dfcf5bb9a638d83", expected_s2, 16);
    assert(memcmp(recovered_s1, expected_s1, 16) == 0);
    assert(memcmp(recovered_s2, expected_s2, 16) == 0);
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found && result.mode == PIXIE_MODE_RALINK);
    assert(strcmp(result.pin, "13572464") == 0);

    bundle = fixture(
        "f7565b92132d5b2ce6486cc7bf60b7aad965fd6bfc714d0c452d0be5b46175be",
        "ffadb4e39a41ad3baa53645a6f2024754fdc1e00781d682f104b3095fc76962d");
    hex("10b7f5272556150a03e5978e30f77714", bundle.e_nonce, 16);
    options = (pixie_options_t){
        .modes = PIXIE_MODE_RTL819X,
        .rtl_window_set = true,
        .rtl_window_start = 1700000002u,
        .rtl_window_end = 1699999998u,
    };
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found && result.mode == PIXIE_MODE_RTL819X);
    assert(strcmp(result.pin, "00010009") == 0);

    hex("e7d79b13da32e42b6bbe5c24f016aba906ad996317cb35a84bdbb0878a12ccd7",
        bundle.e_hash2, 32);
    assert(pixie_recover(&bundle, &options, &result));
    assert(!result.found && result.partial && result.mode == PIXIE_MODE_RTL819X);
    assert(strcmp(result.first_half, "0001") == 0);
}

static bool cancel_now(void *context) {
    (void)context;
    return true;
}

typedef struct { unsigned allocs, frees; bool fail; } cache_probe_t;
static void *probe_alloc(void *context, size_t size) {
    cache_probe_t *probe = context;
    ++probe->allocs;
    return probe->fail ? NULL : malloc(size);
}
static void probe_free(void *context, void *memory, size_t size) {
    cache_probe_t *probe = context;
    assert(size == 160000U);
    ++probe->frees;
    free(memory);
}

static void test_injected_cache_allocator(void) {
    pixie_bundle_t bundle = fixture(
        "b31dec125290ad933c08433ee5448b6b7e9c80bc157457667bbcb6f3b383b8df",
        "0029888438664899e3470060c53562e93243ddddd4113bca027f5eb97cbfbffe");
    cache_probe_t probe = {0};
    pixie_options_t options = {.modes = PIXIE_MODE_NULL_SECRET,
        .cache_alloc = probe_alloc, .cache_free = probe_free,
        .cache_context = &probe};
    pixie_result_t result;
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found && probe.allocs == 1U && probe.frees == 1U);
    probe.fail = true;
    assert(!pixie_recover(&bundle, &options, &result));
    assert(probe.allocs == 2U && probe.frees == 1U);
}

static void test_cancellation(void) {
    pixie_bundle_t bundle = fixture(
        "52a8b9f0c731552ad1ec9c8f4e4384b03f5e8c669f2815875948f5d415781ecc",
        "ea5cc8707296fe1c2399fdead17c1a5fc04a6a1b6629f5d9c539c754577f4495");
    pixie_options_t options = {
        .modes = PIXIE_MODE_NULL_SECRET,
        .yield_every = 1,
        .should_cancel = cancel_now,
    };
    pixie_result_t result;
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.cancelled && !result.found);
}

int main(void) {
    test_prng_vectors();
    test_null_and_wrong_checksum();
    test_static_and_no_match();
    test_ralink_and_rtl();
    test_cancellation();
    test_injected_cache_allocator();
    puts("PASS: Pixie PRNG and offline recovery fixtures");
    return 0;
}
