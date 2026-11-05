#include "router_cve_verify.h"

#include <stdlib.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_MAJOR >= 4
#include "psa/crypto.h"
#endif
#endif

#define JCSG_VERSION 1U
#define JCVJ_VERSION 1U
#define JCVJ_CRC_OFFSET 120U
#define ROUTER_CVE_FUTURE_SKEW_SECONDS 86400ULL

router_cve_verify_result_t router_cve_validate_catalog_time(
    uint64_t created_epoch, uint64_t expires_epoch,
    const router_cve_time_policy_t *time_policy)
{
    if (time_policy == NULL || created_epoch >= expires_epoch)
        return ROUTER_CVE_VERIFY_BAD_FORMAT;
    if (!time_policy->reliable)
        return time_policy->allow_unknown ? ROUTER_CVE_VERIFY_OK :
                                            ROUTER_CVE_VERIFY_TIME_UNKNOWN;
    if (created_epoch > time_policy->now_epoch &&
        created_epoch - time_policy->now_epoch >
            ROUTER_CVE_FUTURE_SKEW_SECONDS)
        return ROUTER_CVE_VERIFY_NOT_YET_VALID;
    if (time_policy->now_epoch >= expires_epoch)
        return ROUTER_CVE_VERIFY_STALE;
    return ROUTER_CVE_VERIFY_OK;
}

typedef struct {
    uint32_t state[8U];
    uint64_t bit_count;
    uint8_t block[64U];
    size_t used;
} verify_sha256_t;

static uint16_t le16(const uint8_t *value)
{
    return (uint16_t)value[0] | (uint16_t)((uint16_t)value[1] << 8U);
}

static uint32_t le32(const uint8_t *value)
{
    return (uint32_t)value[0] | ((uint32_t)value[1] << 8U) |
           ((uint32_t)value[2] << 16U) | ((uint32_t)value[3] << 24U);
}

static uint64_t le64(const uint8_t *value)
{
    return (uint64_t)le32(value) | ((uint64_t)le32(value + 4U) << 32U);
}

static void put_le16(uint8_t *value, uint16_t input)
{
    value[0] = (uint8_t)input;
    value[1] = (uint8_t)(input >> 8U);
}

static void put_le32(uint8_t *value, uint32_t input)
{
    value[0] = (uint8_t)input;
    value[1] = (uint8_t)(input >> 8U);
    value[2] = (uint8_t)(input >> 16U);
    value[3] = (uint8_t)(input >> 24U);
}

static void put_le64(uint8_t *value, uint64_t input)
{
    put_le32(value, (uint32_t)input);
    put_le32(value + 4U, (uint32_t)(input >> 32U));
}

static bool all_zero(const uint8_t *value, size_t size)
{
    uint8_t accumulated = 0U;
    size_t i;
    for (i = 0U; i < size; ++i) accumulated |= value[i];
    return accumulated == 0U;
}

static bool bytes_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t different = 0U;
    size_t i;
    for (i = 0U; i < size; ++i) different |= (uint8_t)(left[i] ^ right[i]);
    return different == 0U;
}

static uint32_t rotr32(uint32_t value, unsigned count)
{
    return (value >> count) | (value << (32U - count));
}

static const uint32_t sha_k[64U] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void sha_transform(verify_sha256_t *sha, const uint8_t block[64U])
{
    uint32_t w[64U], a, b, c, d, e, f, g, h;
    unsigned i;
    for (i = 0U; i < 16U; ++i) {
        size_t p = (size_t)i * 4U;
        w[i] = ((uint32_t)block[p] << 24U) | ((uint32_t)block[p + 1U] << 16U) |
               ((uint32_t)block[p + 2U] << 8U) | block[p + 3U];
    }
    for (; i < 64U; ++i) {
        uint32_t s0 = rotr32(w[i - 15U], 7U) ^ rotr32(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
        uint32_t s1 = rotr32(w[i - 2U], 17U) ^ rotr32(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }
    a=sha->state[0]; b=sha->state[1]; c=sha->state[2]; d=sha->state[3];
    e=sha->state[4]; f=sha->state[5]; g=sha->state[6]; h=sha->state[7];
    for (i = 0U; i < 64U; ++i) {
        uint32_t s1=rotr32(e,6U)^rotr32(e,11U)^rotr32(e,25U);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+s1+ch+sha_k[i]+w[i];
        uint32_t s0=rotr32(a,2U)^rotr32(a,13U)^rotr32(a,22U);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=s0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    sha->state[0]+=a; sha->state[1]+=b; sha->state[2]+=c; sha->state[3]+=d;
    sha->state[4]+=e; sha->state[5]+=f; sha->state[6]+=g; sha->state[7]+=h;
}

static void sha_init(verify_sha256_t *sha)
{
    static const uint32_t initial[8U] = {0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    memset(sha, 0, sizeof(*sha));
    memcpy(sha->state, initial, sizeof(initial));
}

static void sha_update(verify_sha256_t *sha, const void *data, size_t size)
{
    const uint8_t *bytes = data;
    sha->bit_count += (uint64_t)size * 8ULL;
    while (size > 0U) {
        size_t take = 64U - sha->used;
        if (take > size) take = size;
        memcpy(sha->block + sha->used, bytes, take);
        sha->used += take; bytes += take; size -= take;
        if (sha->used == 64U) { sha_transform(sha, sha->block); sha->used = 0U; }
    }
}

static void sha_final(verify_sha256_t *sha, uint8_t output[32U])
{
    uint64_t bits = sha->bit_count;
    unsigned i;
    sha->block[sha->used++] = 0x80U;
    if (sha->used > 56U) {
        memset(sha->block + sha->used, 0, 64U - sha->used);
        sha_transform(sha, sha->block); sha->used = 0U;
    }
    memset(sha->block + sha->used, 0, 56U - sha->used);
    for (i = 0U; i < 8U; ++i) sha->block[63U - i] = (uint8_t)(bits >> (i * 8U));
    sha_transform(sha, sha->block);
    for (i = 0U; i < 8U; ++i) {
        output[i*4U]=(uint8_t)(sha->state[i]>>24U); output[i*4U+1U]=(uint8_t)(sha->state[i]>>16U);
        output[i*4U+2U]=(uint8_t)(sha->state[i]>>8U); output[i*4U+3U]=(uint8_t)sha->state[i];
    }
    memset(sha, 0, sizeof(*sha));
}

static void hash_bytes(const void *data, size_t size, uint8_t output[32U])
{
    verify_sha256_t sha;
    sha_init(&sha); sha_update(&sha, data, size); sha_final(&sha, output);
}

static uint32_t crc32_bytes(const uint8_t *bytes, size_t size)
{
    uint32_t crc = 0xFFFFFFFFU;
    size_t i;
    while (size-- > 0U) {
        crc ^= *bytes++;
        for (i = 0U; i < 8U; ++i)
            crc = (crc >> 1U) ^ (0xEDB88320U & (uint32_t)-(int32_t)(crc & 1U));
    }
    return ~crc;
}

static int compare_be32(const uint8_t left[32U], const uint8_t right[32U])
{
    size_t i;
    for (i = 0U; i < 32U; ++i) {
        if (left[i] < right[i]) return -1;
        if (left[i] > right[i]) return 1;
    }
    return 0;
}

static bool parse_der_integer(const uint8_t *der, size_t size, size_t *position,
                              uint8_t value[32U])
{
    size_t length, encoded_length, start;
    if (*position + 2U > size || der[*position] != 0x02U) return false;
    length = der[*position + 1U];
    encoded_length = length;
    *position += 2U;
    if (length == 0U || length > 33U || *position > size - length) return false;
    start = *position;
    if (der[start] == 0U) {
        if (length == 1U || (der[start + 1U] & 0x80U) == 0U) return false;
        ++start; --length;
    } else if ((der[start] & 0x80U) != 0U) {
        return false;
    }
    if (length > 32U) return false;
    memset(value, 0, 32U);
    memcpy(value + 32U - length, der + start, length);
    *position += encoded_length;
    return !all_zero(value, 32U);
}

static bool strict_low_s_der(const uint8_t *der, size_t size)
{
    static const uint8_t order[32U] = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
    static const uint8_t half_order[32U] = {
        0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8};
    uint8_t r[32U], s[32U];
    size_t position = 2U;
    if (der == NULL || size < 8U || size > ROUTER_CVE_SIG_MAX_DER_BYTES ||
        der[0] != 0x30U || der[1] >= 0x80U || (size_t)der[1] + 2U != size) return false;
    if (!parse_der_integer(der, size, &position, r) ||
        !parse_der_integer(der, size, &position, s) || position != size) return false;
    return compare_be32(r, order) < 0 && compare_be32(s, order) < 0 &&
           compare_be32(s, half_order) <= 0;
}

static const router_cve_trusted_key_t *find_key(const router_cve_crypto_t *crypto,
                                                const uint8_t key_id[16U])
{
    size_t i;
    if (crypto == NULL || crypto->keys == NULL || crypto->key_count == 0U ||
        crypto->key_count > ROUTER_CVE_MAX_TRUSTED_KEYS) return NULL;
    for (i = 0U; i < crypto->key_count; ++i) {
        size_t j;
        if (all_zero(crypto->keys[i].key_id, 16U) ||
            crypto->keys[i].subject_public_key_info == NULL ||
            crypto->keys[i].subject_public_key_info_size == 0U ||
            crypto->keys[i].subject_public_key_info_size > ROUTER_CVE_MAX_PUBLIC_KEY_BYTES) return NULL;
        for (j = 0U; j < i; ++j)
            if (bytes_equal(crypto->keys[i].key_id, crypto->keys[j].key_id, 16U)) return NULL;
    }
    for (i = 0U; i < crypto->key_count; ++i) {
        if (bytes_equal(crypto->keys[i].key_id, key_id, 16U)) return &crypto->keys[i];
    }
    return NULL;
}

typedef struct {
    uint8_t *data;
    size_t size;
    size_t release_size;
    router_cve_owned_release_fn release;
    void *context;
} owned_value_t;

typedef struct {
    router_cve_owned_release_fn release;
    void *context;
    size_t release_size;
} owned_release_adapter_t;

static owned_value_t take_owned(router_cve_owned_bytes_t *source)
{
    owned_value_t value={0};
    if(source!=NULL) {
        value.data=source->data;
        value.size=source->size;
        value.release_size=source->size;
        value.release=source->release;
        value.context=source->context;
        memset(source,0,sizeof(*source));
    }
    return value;
}

static void release_owned(owned_value_t *owned,bool wipe)
{
    if(owned==NULL) return;
    if(owned->data!=NULL) {
        if(wipe&&owned->release_size>0U) memset(owned->data,0,owned->release_size);
        if(owned->release!=NULL)
            owned->release(owned->context,owned->data,owned->release_size);
        else free(owned->data);
    }
    memset(owned,0,sizeof(*owned));
}

static void release_owned_from_db(void *context,void *data,size_t size)
{
    owned_release_adapter_t *adapter=context;
    (void)size;
    if(adapter->release!=NULL)
        adapter->release(adapter->context,data,adapter->release_size);
    else free(data);
}

static router_cve_verify_result_t precheck_owned_bytes(
    const owned_value_t *catalog,const owned_value_t *signature,
    const router_cve_crypto_t *crypto,uint8_t catalog_hash[32U],
    uint8_t signature_hash[32U])
{
    const router_cve_trusted_key_t *key;
    uint16_t der_size;
    if(catalog==NULL||signature==NULL||catalog->data==NULL||signature->data==NULL||
       catalog->size<192U||catalog->size>ROUTER_CVE_DB_MAX_BYTES||
       signature->size<ROUTER_CVE_SIG_HEADER_BYTES||
       signature->size>ROUTER_CVE_SIG_MAX_BYTES||crypto==NULL)
        return ROUTER_CVE_VERIFY_BAD_FORMAT;
    if(memcmp(signature->data,"JCSG",4U)!=0||
       le16(signature->data+4U)!=JCSG_VERSION||
       le16(signature->data+6U)!=ROUTER_CVE_SIG_HEADER_BYTES||
       le32(signature->data+8U)!=0U||le32(signature->data+12U)!=signature->size||
       !all_zero(signature->data+66U,14U)) return ROUTER_CVE_VERIFY_BAD_FORMAT;
    der_size=le16(signature->data+64U);
    if(der_size==0U||der_size>ROUTER_CVE_SIG_MAX_DER_BYTES||
       signature->size!=ROUTER_CVE_SIG_HEADER_BYTES+der_size||
       !strict_low_s_der(signature->data+ROUTER_CVE_SIG_HEADER_BYTES,der_size))
        return ROUTER_CVE_VERIFY_BAD_FORMAT;
    hash_bytes(catalog->data,catalog->size,catalog_hash);
    hash_bytes(signature->data,signature->size,signature_hash);
    if(!bytes_equal(catalog_hash,signature->data+32U,32U))
        return ROUTER_CVE_VERIFY_BAD_HASH;
    key=find_key(crypto,signature->data+16U);
    if(key==NULL) return ROUTER_CVE_VERIFY_UNKNOWN_KEY;
    if(crypto->verify==NULL) return ROUTER_CVE_VERIFY_BAD_FORMAT;
    if(!crypto->verify(crypto->context,key->subject_public_key_info,
                       key->subject_public_key_info_size,catalog_hash,
                       signature->data+ROUTER_CVE_SIG_HEADER_BYTES,der_size))
        return ROUTER_CVE_VERIFY_BAD_SIGNATURE;
    return ROUTER_CVE_VERIFY_OK;
}

static router_cve_verify_result_t verify_owned_bytes(
    owned_value_t catalog,owned_value_t signature,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,router_cve_verified_t *verified)
{
    owned_release_adapter_t catalog_release={
        catalog.release,catalog.context,catalog.release_size};
    router_cve_db_result_t db_result = ROUTER_CVE_DB_IO;
    router_cve_db_t *db=NULL;
    router_cve_db_metadata_t metadata;
    router_cve_verified_t value;
    uint8_t catalog_hash[32U], signature_hash[32U];
    router_cve_verify_result_t result=ROUTER_CVE_VERIFY_BAD_FORMAT;
    if(time_policy==NULL||verified==NULL) goto done;
    result=precheck_owned_bytes(&catalog,&signature,crypto,catalog_hash,signature_hash);
    if(result!=ROUTER_CVE_VERIFY_OK) goto done;
    db=router_cve_db_open_owned_snapshot_with_release(
        catalog.data,(uint32_t)catalog.size,release_owned_from_db,
        &catalog_release,&db_result);
    memset(&catalog,0,sizeof(catalog));
    if (db == NULL) {
        if (db_result == ROUTER_CVE_DB_CAPACITY) result=ROUTER_CVE_VERIFY_CAPACITY;
        else if (db_result == ROUTER_CVE_DB_IO) result=ROUTER_CVE_VERIFY_IO;
        else if (db_result == ROUTER_CVE_DB_HASH || db_result == ROUTER_CVE_DB_CRC) result=ROUTER_CVE_VERIFY_BAD_HASH;
        else result=ROUTER_CVE_VERIFY_BAD_FORMAT;
        goto done;
    }
    db_result = router_cve_db_metadata(db, &metadata);
    router_cve_db_close(db);
    db=NULL;
    if (db_result != ROUTER_CVE_DB_OK) goto done;
    if (!bytes_equal(metadata.key_id, signature.data + 16U, 16U)) {
        result=ROUTER_CVE_VERIFY_UNKNOWN_KEY; goto done;
    }
    result = router_cve_validate_catalog_time(
        metadata.created_epoch, metadata.expires_epoch, time_policy);
    if (result != ROUTER_CVE_VERIFY_OK) goto done;
    memset(&value, 0, sizeof(value));
    value.catalog = metadata;
    memcpy(value.catalog_sha256, catalog_hash, 32U);
    memcpy(value.signature_sha256, signature_hash, 32U);
    value.catalog_time_unknown = !time_policy->reliable;
    *verified = value;
    result=ROUTER_CVE_VERIFY_OK;
done:
    if(db!=NULL) router_cve_db_close(db);
    release_owned(&catalog,false);
    release_owned(&signature,true);
    return result;
}

router_cve_verify_result_t router_cve_verify_owned(
    router_cve_owned_bytes_t *catalog,router_cve_owned_bytes_t *signature,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,router_cve_verified_t *verified)
{
    owned_value_t owned_catalog=take_owned(catalog);
    owned_value_t owned_signature=take_owned(signature);
    return verify_owned_bytes(owned_catalog,owned_signature,crypto,time_policy,verified);
}

router_cve_verify_result_t router_cve_verify_bytes(
    const uint8_t *catalog, size_t catalog_size, const uint8_t *signature,
    size_t signature_size, const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy, router_cve_verified_t *verified)
{
    uint8_t *catalog_snapshot;
    uint8_t *signature_snapshot;
    if (catalog == NULL || signature == NULL || catalog_size < 192U ||
        catalog_size > ROUTER_CVE_DB_MAX_BYTES ||
        signature_size < ROUTER_CVE_SIG_HEADER_BYTES ||
        signature_size > ROUTER_CVE_SIG_MAX_BYTES)
        return ROUTER_CVE_VERIFY_BAD_FORMAT;
    catalog_snapshot = malloc(catalog_size);
    signature_snapshot = malloc(signature_size);
    if (catalog_snapshot == NULL || signature_snapshot == NULL) {
        free(catalog_snapshot);
        free(signature_snapshot);
        return ROUTER_CVE_VERIFY_CAPACITY;
    }
    memcpy(catalog_snapshot, catalog, catalog_size);
    memcpy(signature_snapshot, signature, signature_size);
    {
        owned_value_t owned_catalog={catalog_snapshot,catalog_size,catalog_size,NULL,NULL};
        owned_value_t owned_signature={signature_snapshot,signature_size,signature_size,NULL,NULL};
        return verify_owned_bytes(owned_catalog,owned_signature,crypto,time_policy,verified);
    }
}

typedef struct {
    uint64_t generation;
    uint64_t serial;
    uint8_t slot;
    bool time_unknown;
    uint32_t catalog_size;
    uint32_t signature_size;
    uint8_t catalog_sha256[32U];
    uint8_t signature_sha256[32U];
    uint8_t key_id[16U];
} decoded_journal_t;

static void encode_journal(const decoded_journal_t *journal,
                           uint8_t output[ROUTER_CVE_INSTALL_JOURNAL_BYTES])
{
    memset(output, 0, ROUTER_CVE_INSTALL_JOURNAL_BYTES);
    memcpy(output, "JCVJ", 4U); put_le16(output + 4U, JCVJ_VERSION);
    put_le16(output + 6U, ROUTER_CVE_INSTALL_JOURNAL_BYTES);
    put_le64(output + 8U, journal->generation); put_le64(output + 16U, journal->serial);
    output[24U] = journal->slot; output[25U] = journal->time_unknown ? 1U : 0U;
    put_le32(output + 32U, journal->catalog_size); put_le32(output + 36U, journal->signature_size);
    memcpy(output + 40U, journal->catalog_sha256, 32U);
    memcpy(output + 72U, journal->signature_sha256, 32U);
    memcpy(output + 104U, journal->key_id, 16U);
    put_le32(output + JCVJ_CRC_OFFSET, crc32_bytes(output, JCVJ_CRC_OFFSET));
}

static bool decode_journal(const uint8_t input[ROUTER_CVE_INSTALL_JOURNAL_BYTES],
                           decoded_journal_t *journal)
{
    if (memcmp(input, "JCVJ", 4U) != 0 || le16(input + 4U) != JCVJ_VERSION ||
        le16(input + 6U) != ROUTER_CVE_INSTALL_JOURNAL_BYTES ||
        input[24U] > 1U || input[25U] > 1U || !all_zero(input + 26U, 6U) ||
        !all_zero(input + 124U, 4U) ||
        le32(input + JCVJ_CRC_OFFSET) != crc32_bytes(input, JCVJ_CRC_OFFSET)) return false;
    memset(journal, 0, sizeof(*journal));
    journal->generation=le64(input+8U); journal->serial=le64(input+16U);
    journal->slot=input[24U]; journal->time_unknown=input[25U] != 0U;
    journal->catalog_size=le32(input+32U); journal->signature_size=le32(input+36U);
    memcpy(journal->catalog_sha256,input+40U,32U); memcpy(journal->signature_sha256,input+72U,32U);
    memcpy(journal->key_id,input+104U,16U);
    return journal->generation != 0U && journal->serial != 0U &&
           journal->catalog_size >= 192U && journal->catalog_size <= ROUTER_CVE_DB_MAX_BYTES &&
           journal->signature_size >= ROUTER_CVE_SIG_HEADER_BYTES &&
           journal->signature_size <= ROUTER_CVE_SIG_MAX_BYTES;
}

static router_cve_install_object_t catalog_object(uint8_t slot)
{
    return slot == 0U ? ROUTER_CVE_OBJECT_SLOT0_CATALOG : ROUTER_CVE_OBJECT_SLOT1_CATALOG;
}

static router_cve_install_object_t signature_object(uint8_t slot)
{
    return slot == 0U ? ROUTER_CVE_OBJECT_SLOT0_SIGNATURE : ROUTER_CVE_OBJECT_SLOT1_SIGNATURE;
}

static router_cve_verify_result_t verify_journal_candidate(
    const decoded_journal_t *journal, const router_cve_install_ops_t *ops,
    const router_cve_crypto_t *crypto, const router_cve_time_policy_t *time_policy,
    const router_cve_install_scratch_t *scratch, router_cve_install_status_t *status)
{
    router_cve_storage_result_t read_result;
    router_cve_verified_t verified;
    size_t size = 0U;
    router_cve_verify_result_t result;
    if (journal->catalog_size > scratch->catalog_capacity ||
        journal->signature_size > scratch->signature_capacity) return ROUTER_CVE_VERIFY_CAPACITY;
    read_result=ops->read(ops->context,catalog_object(journal->slot),scratch->catalog,
                          scratch->catalog_capacity,&size);
    if (read_result != ROUTER_CVE_STORAGE_OK || size != journal->catalog_size)
        return read_result == ROUTER_CVE_STORAGE_ERROR ? ROUTER_CVE_VERIFY_IO : ROUTER_CVE_VERIFY_RECOVERY;
    {
        uint8_t digest[32U];
        hash_bytes(scratch->catalog,size,digest);
        if(!bytes_equal(digest,journal->catalog_sha256,32U)) return ROUTER_CVE_VERIFY_RECOVERY;
    }
    read_result=ops->read(ops->context,signature_object(journal->slot),scratch->signature,
                          scratch->signature_capacity,&size);
    if (read_result != ROUTER_CVE_STORAGE_OK || size != journal->signature_size)
        return read_result == ROUTER_CVE_STORAGE_ERROR ? ROUTER_CVE_VERIFY_IO : ROUTER_CVE_VERIFY_RECOVERY;
    {
        uint8_t digest[32U];
        hash_bytes(scratch->signature,size,digest);
        if(!bytes_equal(digest,journal->signature_sha256,32U)) return ROUTER_CVE_VERIFY_RECOVERY;
    }
    result=router_cve_verify_bytes(scratch->catalog,journal->catalog_size,scratch->signature,
                                   journal->signature_size,crypto,time_policy,&verified);
    if(result!=ROUTER_CVE_VERIFY_OK) return result;
    if(verified.catalog.serial!=journal->serial ||
       !bytes_equal(verified.catalog.key_id,journal->key_id,16U)) return ROUTER_CVE_VERIFY_RECOVERY;
    memset(status,0,sizeof(*status)); status->available=true; status->slot=journal->slot;
    status->generation=journal->generation; status->serial=journal->serial;
    memcpy(status->catalog_sha256,journal->catalog_sha256,32U);
    memcpy(status->signature_sha256,journal->signature_sha256,32U);
    memcpy(status->key_id,journal->key_id,16U);
    status->created_epoch=verified.catalog.created_epoch;
    status->expires_epoch=verified.catalog.expires_epoch;
    status->installed_time_unknown=journal->time_unknown;
    status->catalog_time_unknown=journal->time_unknown || verified.catalog_time_unknown;
    return ROUTER_CVE_VERIFY_OK;
}

static bool journal_matches_commit(const decoded_journal_t *journal,
                                   const router_cve_commit_record_t *commit)
{
    return journal->slot==commit->slot && journal->generation==commit->generation &&
           journal->serial==commit->serial && journal->time_unknown==commit->catalog_time_unknown &&
           bytes_equal(journal->catalog_sha256,commit->catalog_sha256,32U) &&
           bytes_equal(journal->signature_sha256,commit->signature_sha256,32U) &&
           bytes_equal(journal->key_id,commit->key_id,16U);
}

static router_cve_verify_result_t recover_locked(
    const router_cve_install_ops_t *ops, const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    const router_cve_install_scratch_t *scratch, router_cve_install_status_t *status)
{
    router_cve_commit_record_t commit;
    bool present=false;
    uint8_t bytes[ROUTER_CVE_INSTALL_JOURNAL_BYTES];
    decoded_journal_t journal;
    size_t size=0U;
    router_cve_storage_result_t read_result;
    if(!ops->get_commit(ops->context,&commit,&present)) return ROUTER_CVE_VERIFY_IO;
    if(!present) return ROUTER_CVE_VERIFY_NOT_FOUND;
    if(commit.slot>1U || commit.generation==0U || commit.serial==0U ||
       all_zero(commit.catalog_sha256,32U) || all_zero(commit.signature_sha256,32U) ||
       all_zero(commit.key_id,16U)) return ROUTER_CVE_VERIFY_RECOVERY;
    read_result=ops->read(ops->context,
        commit.slot==0U?ROUTER_CVE_OBJECT_JOURNAL0:ROUTER_CVE_OBJECT_JOURNAL1,
        bytes,sizeof(bytes),&size);
    if(read_result==ROUTER_CVE_STORAGE_ERROR) return ROUTER_CVE_VERIFY_IO;
    if(read_result!=ROUTER_CVE_STORAGE_OK || size!=sizeof(bytes) ||
       !decode_journal(bytes,&journal) || !journal_matches_commit(&journal,&commit))
        return ROUTER_CVE_VERIFY_RECOVERY;
    return verify_journal_candidate(&journal,ops,crypto,time_policy,scratch,status);
}

router_cve_verify_result_t router_cve_install_recover(
    const router_cve_install_ops_t *ops, const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    const router_cve_install_scratch_t *scratch, router_cve_install_status_t *status)
{
    router_cve_verify_result_t result;
    if(ops==NULL || ops->enter==NULL || ops->leave==NULL || ops->read==NULL ||
       ops->get_commit==NULL || crypto==NULL || time_policy==NULL || scratch==NULL ||
       scratch->catalog==NULL || scratch->signature==NULL || status==NULL)
        return ROUTER_CVE_VERIFY_BAD_FORMAT;
    if(!ops->enter(ops->context)) return ROUTER_CVE_VERIFY_BUSY;
    result=recover_locked(ops,crypto,time_policy,scratch,status);
    ops->leave(ops->context);
    return result;
}

router_cve_verify_result_t router_cve_install_recover_owned(
    router_cve_owned_bytes_t *catalog_handle,
    router_cve_owned_bytes_t *signature_handle,
    const router_cve_install_ops_t *ops,const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    router_cve_install_status_t *status)
{
    owned_value_t catalog=take_owned(catalog_handle);
    owned_value_t signature=take_owned(signature_handle);
    router_cve_commit_record_t commit;
    router_cve_storage_result_t read_result;
    router_cve_verified_t verified;
    router_cve_install_status_t recovered;
    router_cve_verify_result_t result=ROUTER_CVE_VERIFY_BAD_FORMAT;
    decoded_journal_t journal;
    uint8_t journal_bytes[ROUTER_CVE_INSTALL_JOURNAL_BYTES];
    size_t size=0U;
    bool present=false,locked=false;
    if(ops==NULL||ops->enter==NULL||ops->leave==NULL||ops->read==NULL||
       ops->get_commit==NULL||crypto==NULL||time_policy==NULL||status==NULL||
       catalog.data==NULL||signature.data==NULL) goto done;
    if(!ops->enter(ops->context)) { result=ROUTER_CVE_VERIFY_BUSY; goto done; }
    locked=true;
    if(!ops->get_commit(ops->context,&commit,&present)) {
        result=ROUTER_CVE_VERIFY_IO;
        goto done;
    }
    if(!present) {
        result=ROUTER_CVE_VERIFY_NOT_FOUND;
        goto done;
    }
    if(commit.slot>1U||commit.generation==0U||commit.serial==0U||
       all_zero(commit.catalog_sha256,32U)||
       all_zero(commit.signature_sha256,32U)||all_zero(commit.key_id,16U)) {
        result=ROUTER_CVE_VERIFY_RECOVERY;
        goto done;
    }
    read_result=ops->read(ops->context,
        commit.slot==0U?ROUTER_CVE_OBJECT_JOURNAL0:ROUTER_CVE_OBJECT_JOURNAL1,
        journal_bytes,sizeof(journal_bytes),&size);
    if(read_result==ROUTER_CVE_STORAGE_ERROR) {
        result=ROUTER_CVE_VERIFY_IO;
        goto done;
    }
    if(read_result!=ROUTER_CVE_STORAGE_OK||size!=sizeof(journal_bytes)||
       !decode_journal(journal_bytes,&journal)||
       !journal_matches_commit(&journal,&commit)) {
        result=ROUTER_CVE_VERIFY_RECOVERY;
        goto done;
    }
    if(journal.catalog_size>catalog.size||journal.signature_size>signature.size) {
        result=ROUTER_CVE_VERIFY_CAPACITY;
        goto done;
    }
    read_result=ops->read(ops->context,catalog_object(journal.slot),catalog.data,
                          catalog.size,&size);
    if(read_result!=ROUTER_CVE_STORAGE_OK||size!=journal.catalog_size) {
        result=read_result==ROUTER_CVE_STORAGE_ERROR?
               ROUTER_CVE_VERIFY_IO:ROUTER_CVE_VERIFY_RECOVERY;
        goto done;
    }
    {
        uint8_t digest[32U];
        hash_bytes(catalog.data,size,digest);
        if(!bytes_equal(digest,journal.catalog_sha256,32U)) {
            result=ROUTER_CVE_VERIFY_RECOVERY;
            goto done;
        }
    }
    read_result=ops->read(ops->context,signature_object(journal.slot),signature.data,
                          signature.size,&size);
    if(read_result!=ROUTER_CVE_STORAGE_OK||size!=journal.signature_size) {
        result=read_result==ROUTER_CVE_STORAGE_ERROR?
               ROUTER_CVE_VERIFY_IO:ROUTER_CVE_VERIFY_RECOVERY;
        goto done;
    }
    {
        uint8_t digest[32U];
        hash_bytes(signature.data,size,digest);
        if(!bytes_equal(digest,journal.signature_sha256,32U)) {
            result=ROUTER_CVE_VERIFY_RECOVERY;
            goto done;
        }
    }
    catalog.size=journal.catalog_size;
    signature.size=journal.signature_size;
    {
        owned_value_t checked_catalog=catalog;
        owned_value_t checked_signature=signature;
        memset(&catalog,0,sizeof(catalog));
        memset(&signature,0,sizeof(signature));
        result=verify_owned_bytes(checked_catalog,checked_signature,crypto,
                                  time_policy,&verified);
    }
    if(result!=ROUTER_CVE_VERIFY_OK) goto done;
    if(verified.catalog.serial!=journal.serial||
       !bytes_equal(verified.catalog.key_id,journal.key_id,16U)) {
        result=ROUTER_CVE_VERIFY_RECOVERY;
        goto done;
    }
    memset(&recovered,0,sizeof(recovered));
    recovered.available=true;
    recovered.slot=journal.slot;
    recovered.generation=journal.generation;
    recovered.serial=journal.serial;
    memcpy(recovered.catalog_sha256,journal.catalog_sha256,32U);
    memcpy(recovered.signature_sha256,journal.signature_sha256,32U);
    memcpy(recovered.key_id,journal.key_id,16U);
    recovered.created_epoch=verified.catalog.created_epoch;
    recovered.expires_epoch=verified.catalog.expires_epoch;
    recovered.installed_time_unknown=journal.time_unknown;
    recovered.catalog_time_unknown=journal.time_unknown||
                                   verified.catalog_time_unknown;
    *status=recovered;
    result=ROUTER_CVE_VERIFY_OK;
done:
    if(locked) ops->leave(ops->context);
    release_owned(&catalog,false);
    release_owned(&signature,true);
    return result;
}

router_cve_verify_result_t router_cve_install_catalog(
    const uint8_t *catalog, size_t catalog_size, const uint8_t *signature,
    size_t signature_size, const router_cve_install_ops_t *ops,
    const router_cve_crypto_t *crypto, const router_cve_time_policy_t *time_policy,
    const router_cve_install_scratch_t *scratch, router_cve_install_status_t *status)
{
    router_cve_verified_t verified, readback;
    router_cve_install_status_t active, published;
    router_cve_commit_record_t current, desired;
    router_cve_verify_result_t result;
    decoded_journal_t journal;
    uint8_t journal_bytes[ROUTER_CVE_INSTALL_JOURNAL_BYTES];
    uint64_t generation=1U;
    uint8_t slot=0U;
    size_t size=0U;
    bool current_present=false;
    if(ops==NULL||ops->enter==NULL||ops->leave==NULL||ops->read==NULL||ops->write==NULL||
       ops->write_atomic==NULL||ops->sync==NULL||ops->get_commit==NULL||
       ops->advance_commit==NULL||scratch==NULL||status==NULL)
        return ROUTER_CVE_VERIFY_BAD_FORMAT;
    result=router_cve_verify_bytes(catalog,catalog_size,signature,signature_size,crypto,time_policy,&verified);
    if(result!=ROUTER_CVE_VERIFY_OK) return result;
    if(!ops->enter(ops->context)) return ROUTER_CVE_VERIFY_BUSY;
    if(!ops->get_commit(ops->context,&current,&current_present)){result=ROUTER_CVE_VERIFY_IO;goto done;}
    if(current_present) {
        router_cve_time_policy_t structural_time={false,0U,true};
        result=recover_locked(ops,crypto,&structural_time,scratch,&active);
        if(result!=ROUTER_CVE_VERIFY_OK) goto done;
        if(verified.catalog.serial<=current.serial || current.generation==UINT64_MAX) {
            result=ROUTER_CVE_VERIFY_ROLLBACK; goto done;
        }
        slot=(uint8_t)(current.slot^1U); generation=current.generation+1U;
    }
    if(catalog_size>scratch->catalog_capacity||signature_size>scratch->signature_capacity) {
        result=ROUTER_CVE_VERIFY_CAPACITY; goto done;
    }
    if(!ops->write(ops->context,catalog_object(slot),catalog,catalog_size)||!ops->sync(ops->context)||
       !ops->write(ops->context,signature_object(slot),signature,signature_size)||!ops->sync(ops->context))
        {result=ROUTER_CVE_VERIFY_PUBLISH;goto done;}
    if(ops->read(ops->context,catalog_object(slot),scratch->catalog,scratch->catalog_capacity,&size)!=ROUTER_CVE_STORAGE_OK||size!=catalog_size)
        {result=ROUTER_CVE_VERIFY_PUBLISH;goto done;}
    if(ops->read(ops->context,signature_object(slot),scratch->signature,scratch->signature_capacity,&size)!=ROUTER_CVE_STORAGE_OK||size!=signature_size)
        {result=ROUTER_CVE_VERIFY_PUBLISH;goto done;}
    result=router_cve_verify_bytes(scratch->catalog,catalog_size,scratch->signature,signature_size,crypto,time_policy,&readback);
    if(result!=ROUTER_CVE_VERIFY_OK||!bytes_equal(readback.catalog_sha256,verified.catalog_sha256,32U)||
       !bytes_equal(readback.signature_sha256,verified.signature_sha256,32U))
        {result=ROUTER_CVE_VERIFY_PUBLISH;goto done;}
    memset(&journal,0,sizeof(journal)); journal.generation=generation; journal.serial=verified.catalog.serial;
    journal.slot=slot; journal.time_unknown=verified.catalog_time_unknown;
    journal.catalog_size=(uint32_t)catalog_size; journal.signature_size=(uint32_t)signature_size;
    memcpy(journal.catalog_sha256,verified.catalog_sha256,32U); memcpy(journal.signature_sha256,verified.signature_sha256,32U);
    memcpy(journal.key_id,verified.catalog.key_id,16U); encode_journal(&journal,journal_bytes);
    if(!ops->write_atomic(ops->context,slot==0U?ROUTER_CVE_OBJECT_JOURNAL0:ROUTER_CVE_OBJECT_JOURNAL1,
                          journal_bytes,sizeof(journal_bytes)))
        {result=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN;goto done;}
    if(!ops->sync(ops->context)){result=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN;goto done;}
    memset(&published,0,sizeof(published)); published.available=true; published.slot=slot;
    published.generation=generation; published.serial=journal.serial;
    memcpy(published.catalog_sha256,journal.catalog_sha256,32U); memcpy(published.signature_sha256,journal.signature_sha256,32U);
    memcpy(published.key_id,journal.key_id,16U);
    published.created_epoch=verified.catalog.created_epoch;
    published.expires_epoch=verified.catalog.expires_epoch;
    published.installed_time_unknown=journal.time_unknown;
    published.catalog_time_unknown=journal.time_unknown;
    memset(&desired,0,sizeof(desired)); desired.slot=slot; desired.generation=generation;
    desired.serial=journal.serial; memcpy(desired.catalog_sha256,journal.catalog_sha256,32U);
    memcpy(desired.signature_sha256,journal.signature_sha256,32U);
    memcpy(desired.key_id,journal.key_id,16U); desired.catalog_time_unknown=journal.time_unknown;
    if(!ops->advance_commit(ops->context,current_present?&current:NULL,current_present,&desired)) {
        result=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN; goto done;
    }
    *status=published;
    result=ROUTER_CVE_VERIFY_OK;
done:
    ops->leave(ops->context);
    return result;
}

router_cve_verify_result_t router_cve_install_catalog_owned(
    router_cve_owned_bytes_t *catalog_handle,
    router_cve_owned_bytes_t *signature_handle,
    const router_cve_install_ops_t *ops,const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    router_cve_install_status_t *status)
{
    owned_value_t catalog=take_owned(catalog_handle);
    owned_value_t signature=take_owned(signature_handle);
    router_cve_verified_t verified;
    router_cve_install_status_t published;
    router_cve_commit_record_t current,desired;
    router_cve_verify_result_t result=ROUTER_CVE_VERIFY_BAD_FORMAT;
    decoded_journal_t journal;
    uint8_t journal_bytes[ROUTER_CVE_INSTALL_JOURNAL_BYTES];
    uint8_t catalog_hash[32U],signature_hash[32U];
    uint64_t generation=1U;
    uint8_t slot=0U;
    size_t catalog_size=0U,signature_size=0U,read_size=0U;
    bool current_present=false,locked=false;
    if(ops==NULL||ops->enter==NULL||ops->leave==NULL||ops->read==NULL||
       ops->write==NULL||ops->write_atomic==NULL||ops->sync==NULL||
       ops->get_commit==NULL||ops->advance_commit==NULL||status==NULL||
       time_policy==NULL) goto done;
    result=precheck_owned_bytes(&catalog,&signature,crypto,catalog_hash,signature_hash);
    if(result!=ROUTER_CVE_VERIFY_OK) goto done;
    catalog_size=catalog.size;
    signature_size=signature.size;
    if(!ops->enter(ops->context)) { result=ROUTER_CVE_VERIFY_BUSY; goto done; }
    locked=true;
    if(!ops->get_commit(ops->context,&current,&current_present)) {
        result=ROUTER_CVE_VERIFY_IO;
        goto done;
    }
    if(current_present) {
        if(current.slot>1U||current.generation==0U||current.serial==0U||
           all_zero(current.catalog_sha256,32U)||
           all_zero(current.signature_sha256,32U)||all_zero(current.key_id,16U)) {
            result=ROUTER_CVE_VERIFY_RECOVERY;
            goto done;
        }
        if(current.generation==UINT64_MAX) {
            result=ROUTER_CVE_VERIFY_ROLLBACK;
            goto done;
        }
        slot=(uint8_t)(current.slot^1U);
        generation=current.generation+1U;
    }
    if(!ops->write(ops->context,catalog_object(slot),catalog.data,catalog.size)||
       !ops->sync(ops->context)||
       !ops->write(ops->context,signature_object(slot),signature.data,signature.size)||
       !ops->sync(ops->context)) {
        result=ROUTER_CVE_VERIFY_PUBLISH;
        goto done;
    }
    if(ops->read(ops->context,catalog_object(slot),catalog.data,catalog.size,
                 &read_size)!=ROUTER_CVE_STORAGE_OK||read_size!=catalog.size) {
        result=ROUTER_CVE_VERIFY_PUBLISH;
        goto done;
    }
    if(ops->read(ops->context,signature_object(slot),signature.data,signature.size,
                 &read_size)!=ROUTER_CVE_STORAGE_OK||read_size!=signature.size) {
        result=ROUTER_CVE_VERIFY_PUBLISH;
        goto done;
    }
    {
        owned_value_t checked_catalog=catalog;
        owned_value_t checked_signature=signature;
        memset(&catalog,0,sizeof(catalog));
        memset(&signature,0,sizeof(signature));
        result=verify_owned_bytes(checked_catalog,checked_signature,crypto,time_policy,&verified);
    }
    if(result!=ROUTER_CVE_VERIFY_OK||
       !bytes_equal(verified.catalog_sha256,catalog_hash,32U)||
       !bytes_equal(verified.signature_sha256,signature_hash,32U)) {
        result=ROUTER_CVE_VERIFY_PUBLISH;
        goto done;
    }
    if(current_present&&verified.catalog.serial<=current.serial) {
        result=ROUTER_CVE_VERIFY_ROLLBACK;
        goto done;
    }
    memset(&journal,0,sizeof(journal));
    journal.generation=generation;
    journal.serial=verified.catalog.serial;
    journal.slot=slot;
    journal.time_unknown=verified.catalog_time_unknown;
    journal.catalog_size=(uint32_t)catalog_size;
    journal.signature_size=(uint32_t)signature_size;
    memcpy(journal.catalog_sha256,verified.catalog_sha256,32U);
    memcpy(journal.signature_sha256,verified.signature_sha256,32U);
    memcpy(journal.key_id,verified.catalog.key_id,16U);
    encode_journal(&journal,journal_bytes);
    if(!ops->write_atomic(ops->context,
                          slot==0U?ROUTER_CVE_OBJECT_JOURNAL0:
                                   ROUTER_CVE_OBJECT_JOURNAL1,
                          journal_bytes,sizeof(journal_bytes))) {
        result=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN;
        goto done;
    }
    if(!ops->sync(ops->context)) {
        result=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN;
        goto done;
    }
    memset(&published,0,sizeof(published));
    published.available=true;
    published.slot=slot;
    published.generation=generation;
    published.serial=journal.serial;
    memcpy(published.catalog_sha256,journal.catalog_sha256,32U);
    memcpy(published.signature_sha256,journal.signature_sha256,32U);
    memcpy(published.key_id,journal.key_id,16U);
    published.created_epoch=verified.catalog.created_epoch;
    published.expires_epoch=verified.catalog.expires_epoch;
    published.installed_time_unknown=journal.time_unknown;
    published.catalog_time_unknown=journal.time_unknown;
    memset(&desired,0,sizeof(desired));
    desired.slot=slot;
    desired.generation=generation;
    desired.serial=journal.serial;
    memcpy(desired.catalog_sha256,journal.catalog_sha256,32U);
    memcpy(desired.signature_sha256,journal.signature_sha256,32U);
    memcpy(desired.key_id,journal.key_id,16U);
    desired.catalog_time_unknown=journal.time_unknown;
    if(!ops->advance_commit(ops->context,current_present?&current:NULL,
                            current_present,&desired)) {
        result=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN;
        goto done;
    }
    *status=published;
    result=ROUTER_CVE_VERIFY_OK;
done:
    if(locked) ops->leave(ops->context);
    release_owned(&catalog,false);
    release_owned(&signature,true);
    return result;
}

bool router_cve_mbedtls_p256_verify(
    void *context, const uint8_t *subject_public_key_info,
    size_t subject_public_key_info_size, const uint8_t digest[32U],
    const uint8_t *strict_der, size_t strict_der_size)
{
    (void)context;
    if(subject_public_key_info==NULL || subject_public_key_info_size==0U ||
       digest==NULL || strict_der==NULL || strict_der_size==0U) return false;
#if defined(ESP_PLATFORM)
    mbedtls_pk_context key;
#if MBEDTLS_VERSION_MAJOR >= 4
    psa_key_attributes_t attributes=PSA_KEY_ATTRIBUTES_INIT;
#else
    mbedtls_ecp_keypair *ec;
#endif
    int result;
    mbedtls_pk_init(&key);
    result=mbedtls_pk_parse_public_key(&key,subject_public_key_info,subject_public_key_info_size);
#if MBEDTLS_VERSION_MAJOR >= 4
    if(result==0) result=mbedtls_pk_get_psa_attributes(
        &key,PSA_KEY_USAGE_VERIFY_HASH,&attributes);
    if(result==0 &&
       (!mbedtls_pk_can_do_psa(&key,PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                               PSA_KEY_USAGE_VERIFY_HASH) ||
        psa_get_key_type(&attributes)!=
            PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) ||
        psa_get_key_bits(&attributes)!=256U)) result=-1;
    psa_reset_key_attributes(&attributes);
#else
    ec=result==0 ? mbedtls_pk_ec(key) : NULL;
    if(result==0 && (!mbedtls_pk_can_do(&key,MBEDTLS_PK_ECDSA) || mbedtls_pk_get_bitlen(&key)!=256U ||
                     ec==NULL || ec->MBEDTLS_PRIVATE(grp).id!=MBEDTLS_ECP_DP_SECP256R1)) result=-1;
#endif
    if(result==0) result=mbedtls_pk_verify(&key,MBEDTLS_MD_SHA256,digest,32U,strict_der,strict_der_size);
    mbedtls_pk_free(&key);
    return result==0;
#else
    (void)subject_public_key_info; (void)subject_public_key_info_size;
    (void)digest; (void)strict_der; (void)strict_der_size;
    return false;
#endif
}
