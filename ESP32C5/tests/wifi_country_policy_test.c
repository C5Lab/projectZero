#include "wifi_country_policy.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static void test_default_and_normalization(void)
{
    wifi_country_policy_record_t record = wifi_country_policy_default();
    CHECK(record.version == WIFI_COUNTRY_POLICY_VERSION);
    CHECK(strcmp(record.cc, "PA") == 0);
    CHECK(wifi_country_policy_is_pa(&record));
    CHECK(!wifi_country_policy_is_pa(NULL));

    char cc[WIFI_COUNTRY_CODE_SIZE] = {0};
    CHECK(wifi_country_policy_normalize("pl", cc) == WIFI_COUNTRY_POLICY_OK);
    CHECK(strcmp(cc, "PL") == 0);
    CHECK(wifi_country_policy_normalize("pa", cc) == WIFI_COUNTRY_POLICY_OK);
    CHECK(strcmp(cc, "PA") == 0);

    const char *bad[] = {"", "P", "POL", "P1", "ZZ", "ph ", " PL", NULL};
    for (size_t i = 0; bad[i] != NULL; ++i) {
        strcpy(cc, "OK");
        CHECK(wifi_country_policy_normalize(bad[i], cc) != WIFI_COUNTRY_POLICY_OK);
        CHECK(strcmp(cc, "OK") == 0);
    }
    CHECK(wifi_country_policy_normalize(NULL, cc) == WIFI_COUNTRY_POLICY_INVALID_ARGUMENT);
    CHECK(wifi_country_policy_normalize("PL", NULL) == WIFI_COUNTRY_POLICY_INVALID_ARGUMENT);
}

static void test_supported_profiles(void)
{
    /* Profiles outside the former short list, plus existing/default profiles. */
    const char *supported[] = {"RU", "PH", "AE", "AR", "ID", "IL", "SG", "TH",
        "TR", "UA", "ZA", "ZW", "EU", "AN", "YT", "PA", "PL", "US", "01"};
    CHECK(wifi_country_policy_count() == 176);
    CHECK(strcmp(wifi_country_policy_at(0), "PA") == 0);
    for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); ++i)
        CHECK(wifi_country_policy_is_supported(supported[i]));

    for (size_t i = 0; i < wifi_country_policy_count(); ++i) {
        const char *profile = wifi_country_policy_at(i);
        CHECK(profile != NULL && strlen(profile) == 2);
        CHECK(wifi_country_policy_is_supported(profile));
        for (size_t j = 0; j < i; ++j)
            CHECK(strcmp(profile, wifi_country_policy_at(j)) != 0);

        char lowercase[3] = {(char)tolower((unsigned char)profile[0]),
                             (char)tolower((unsigned char)profile[1]), '\0'};
        char normalized[WIFI_COUNTRY_CODE_SIZE];
        CHECK(wifi_country_policy_normalize(lowercase, normalized) == WIFI_COUNTRY_POLICY_OK);
        CHECK(strcmp(normalized, profile) == 0);

        wifi_country_policy_record_t record = {WIFI_COUNTRY_POLICY_VERSION, {0}};
        memcpy(record.cc, normalized, sizeof(record.cc));
        uint8_t bytes[WIFI_COUNTRY_POLICY_RECORD_SIZE];
        CHECK(wifi_country_policy_encode(&record, bytes, sizeof(bytes)) == WIFI_COUNTRY_POLICY_OK);
        wifi_country_policy_record_t decoded = {0};
        CHECK(wifi_country_policy_decode(bytes, sizeof(bytes), &decoded) == WIFI_COUNTRY_POLICY_OK);
        CHECK(decoded.version == record.version && strcmp(decoded.cc, profile) == 0);
    }
    CHECK(wifi_country_policy_at(wifi_country_policy_count()) == NULL);
    CHECK(!wifi_country_policy_is_supported("ZZ"));
    CHECK(!wifi_country_policy_is_supported(NULL));
}

static void test_persisted_record(void)
{
    wifi_country_policy_record_t record = {WIFI_COUNTRY_POLICY_VERSION, "PL"};
    uint8_t bytes[WIFI_COUNTRY_POLICY_RECORD_SIZE] = {0};
    const uint8_t expected[] = {1, 'P', 'L'};
    CHECK(wifi_country_policy_encode(&record, bytes, sizeof(bytes)) == WIFI_COUNTRY_POLICY_OK);
    CHECK(memcmp(bytes, expected, sizeof(expected)) == 0);

    wifi_country_policy_record_t decoded = {77, "OK"};
    CHECK(wifi_country_policy_decode(bytes, sizeof(bytes), &decoded) == WIFI_COUNTRY_POLICY_OK);
    CHECK(decoded.version == 1 && strcmp(decoded.cc, "PL") == 0);

    const uint8_t corrupt[][3] = {{2, 'P', 'L'}, {1, 'Z', 'Z'}, {1, 'p', 'l'}, {1, 'P', 0}};
    for (size_t i = 0; i < sizeof(corrupt) / sizeof(corrupt[0]); ++i) {
        decoded.version = 77;
        strcpy(decoded.cc, "OK");
        CHECK(wifi_country_policy_decode(corrupt[i], 3, &decoded) != WIFI_COUNTRY_POLICY_OK);
        CHECK(decoded.version == 77 && strcmp(decoded.cc, "OK") == 0);
    }
    for (size_t length = 0; length < 5; ++length) {
        if (length == 3) continue;
        CHECK(wifi_country_policy_decode(bytes, length, &decoded) == WIFI_COUNTRY_POLICY_WRONG_LENGTH);
    }
}

static void test_ru_profile_contract(void)
{
    size_t ru_count = 0;
    for (size_t i = 0; i < wifi_country_policy_count(); ++i)
        if (strcmp(wifi_country_policy_at(i), "RU") == 0) ++ru_count;
    CHECK(ru_count == 1);

    char normalized[WIFI_COUNTRY_CODE_SIZE] = {0};
    CHECK(wifi_country_policy_normalize("ru", normalized) == WIFI_COUNTRY_POLICY_OK);
    CHECK(strcmp(normalized, "RU") == 0);

    const wifi_country_policy_record_t record = {
        WIFI_COUNTRY_POLICY_VERSION, "RU"
    };
    uint8_t bytes[WIFI_COUNTRY_POLICY_RECORD_SIZE] = {0};
    const uint8_t expected[] = {1, 'R', 'U'};
    CHECK(wifi_country_policy_encode(&record, bytes, sizeof(bytes)) == WIFI_COUNTRY_POLICY_OK);
    CHECK(memcmp(bytes, expected, sizeof(expected)) == 0);

    wifi_country_policy_record_t decoded = {0};
    CHECK(wifi_country_policy_decode(bytes, sizeof(bytes), &decoded) == WIFI_COUNTRY_POLICY_OK);
    CHECK(decoded.version == WIFI_COUNTRY_POLICY_VERSION);
    CHECK(strcmp(decoded.cc, "RU") == 0);
}

int main(void)
{
    test_default_and_normalization();
    test_supported_profiles();
    test_persisted_record();
    test_ru_profile_contract();
    puts("PASS: WiFi country policy");
    return 0;
}
