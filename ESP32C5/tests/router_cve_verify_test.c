#include "router_cve_verify.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Production translation units are compiled with malloc/calloc/free renamed
 * to these wrappers. This test translation unit deliberately restores the
 * C allocator so fixture ownership is distinct from auxiliary allocations. */
#ifdef malloc
#undef malloc
#endif
#ifdef calloc
#undef calloc
#endif
#ifdef free
#undef free
#endif
extern void *malloc(size_t size);
extern void *calloc(size_t count, size_t size);
extern void free(void *memory);

static size_t auxiliary_largest_request;
static unsigned auxiliary_allocation_calls;
static unsigned auxiliary_fail_at;

void *router_cve_test_malloc(size_t size)
{
    ++auxiliary_allocation_calls;
    if(size>auxiliary_largest_request) auxiliary_largest_request=size;
    if(auxiliary_fail_at!=0U&&auxiliary_allocation_calls==auxiliary_fail_at) return NULL;
    return malloc(size);
}

void *router_cve_test_calloc(size_t count,size_t size)
{
    size_t total;
    ++auxiliary_allocation_calls;
    if(size!=0U&&count>SIZE_MAX/size) return NULL;
    total=count*size;
    if(total>auxiliary_largest_request) auxiliary_largest_request=total;
    if(auxiliary_fail_at!=0U&&auxiliary_allocation_calls==auxiliary_fail_at) return NULL;
    return calloc(count,size);
}

void router_cve_test_free(void *memory)
{
    free(memory);
}

typedef struct {
    uint8_t data[ROUTER_CVE_OBJECT_COUNT][2048U];
    size_t size[ROUTER_CVE_OBJECT_COUNT];
    bool present[ROUTER_CVE_OBJECT_COUNT];
    router_cve_commit_record_t commit;
    bool commit_present;
    bool locked;
    bool race_advance_enabled;
    unsigned mutation_calls;
    unsigned fail_at;
    bool read_fail_enabled;
    router_cve_install_object_t read_fail_object;
    bool tamper_catalog_read;
    const void *catalog_write_pointer;
    void *catalog_read_pointer;
} fake_store_t;

typedef struct {
    uint8_t *expected;
    size_t expected_size;
    unsigned calls;
    bool expect_zeroed;
} release_probe_t;

static uint8_t expected_digest[3U][32U];
static size_t expected_digest_count;
static uint8_t *mutation_target;
static const router_cve_owned_bytes_t *callback_catalog_handle;
static const router_cve_owned_bytes_t *callback_signature_handle;

static void release_probe(void *context,void *memory,size_t size)
{
    release_probe_t *probe=context;
    size_t i;
    assert(probe!=NULL&&memory==probe->expected&&size==probe->expected_size);
    if(probe->expect_zeroed)
        for(i=0U;i<size;++i) assert(((const uint8_t *)memory)[i]==0U);
    ++probe->calls;
    free(memory);
}

static router_cve_owned_bytes_t owned_copy(const uint8_t *data,size_t size,
                                            release_probe_t *probe,bool zeroed)
{
    router_cve_owned_bytes_t owned;
    uint8_t *copy=malloc(size);
    assert(copy!=NULL);
    memcpy(copy,data,size);
    memset(probe,0,sizeof(*probe));
    probe->expected=copy;
    probe->expected_size=size;
    probe->expect_zeroed=zeroed;
    owned.data=copy;
    owned.size=size;
    owned.release=release_probe;
    owned.context=probe;
    return owned;
}

static router_cve_owned_bytes_t owned_buffer(size_t capacity,
                                              release_probe_t *probe,bool zeroed)
{
    router_cve_owned_bytes_t owned;
    uint8_t *buffer=malloc(capacity);
    assert(buffer!=NULL);
    memset(buffer,0xA5,capacity);
    memset(probe,0,sizeof(*probe));
    probe->expected=buffer;
    probe->expected_size=capacity;
    probe->expect_zeroed=zeroed;
    owned.data=buffer;
    owned.size=capacity;
    owned.release=release_probe;
    owned.context=probe;
    return owned;
}

static void assert_consumed(const router_cve_owned_bytes_t *owned)
{
    assert(owned!=NULL&&owned->data==NULL&&owned->size==0U&&
           owned->release==NULL&&owned->context==NULL);
}

static uint8_t *load_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *data;
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
    data = malloc((size_t)length);
    assert(data != NULL && fread(data, 1U, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    *size = (size_t)length;
    return data;
}

static bool fake_verify(void *context, const uint8_t *spki, size_t spki_size,
                        const uint8_t digest[32U], const uint8_t *der,
                        size_t der_size)
{
    static const uint8_t expected_der[] = {0x30U,0x06U,0x02U,0x01U,0x01U,0x02U,0x01U,0x01U};
    (void)context;
    bool known=false;
    size_t i;
    if(callback_catalog_handle!=NULL) assert_consumed(callback_catalog_handle);
    if(callback_signature_handle!=NULL) assert_consumed(callback_signature_handle);
    if(mutation_target!=NULL) {
        mutation_target[200U]^=1U;
        mutation_target=NULL;
    }
    for(i=0U;i<expected_digest_count;++i) known=known || memcmp(digest,expected_digest[i],32U)==0;
    return spki_size == 1U && spki[0] == 0x42U && known &&
           der_size == sizeof(expected_der) && memcmp(der, expected_der, sizeof(expected_der)) == 0;
}

static router_cve_storage_result_t store_read(void *context,
    router_cve_install_object_t object, void *buffer, size_t capacity, size_t *size)
{
    fake_store_t *store = context;
    assert(object < ROUTER_CVE_OBJECT_COUNT && size != NULL);
    if (store->read_fail_enabled && object == store->read_fail_object)
        return ROUTER_CVE_STORAGE_ERROR;
    if (!store->present[object]) return ROUTER_CVE_STORAGE_MISSING;
    if (store->size[object] > capacity) return ROUTER_CVE_STORAGE_ERROR;
    if(object==ROUTER_CVE_OBJECT_SLOT0_CATALOG||
       object==ROUTER_CVE_OBJECT_SLOT1_CATALOG) store->catalog_read_pointer=buffer;
    memcpy(buffer, store->data[object], store->size[object]);
    if(store->tamper_catalog_read&&
       (object==ROUTER_CVE_OBJECT_SLOT0_CATALOG||
        object==ROUTER_CVE_OBJECT_SLOT1_CATALOG)) ((uint8_t *)buffer)[200U]^=1U;
    *size = store->size[object];
    return ROUTER_CVE_STORAGE_OK;
}

static bool mutation_allowed(fake_store_t *store)
{
    ++store->mutation_calls;
    return store->fail_at == 0U || store->mutation_calls != store->fail_at;
}

static bool store_write_common(fake_store_t *store, router_cve_install_object_t object,
                               const void *data, size_t size)
{
    if (!mutation_allowed(store) || object >= ROUTER_CVE_OBJECT_COUNT ||
        size > sizeof(store->data[object])) return false;
    if(object==ROUTER_CVE_OBJECT_SLOT0_CATALOG||
       object==ROUTER_CVE_OBJECT_SLOT1_CATALOG) store->catalog_write_pointer=data;
    memcpy(store->data[object], data, size);
    store->size[object] = size;
    store->present[object] = true;
    return true;
}

static bool store_write(void *context, router_cve_install_object_t object,
                        const void *data, size_t size)
{
    return store_write_common(context, object, data, size);
}

static bool store_write_atomic(void *context, router_cve_install_object_t object,
                               const void *data, size_t size)
{
    return store_write_common(context, object, data, size);
}

static bool store_sync(void *context)
{
    return mutation_allowed(context);
}

static bool store_enter(void *context)
{
    fake_store_t *store=context;
    if(store->locked) return false;
    store->locked=true;
    return true;
}

static void store_leave(void *context)
{
    fake_store_t *store=context;
    assert(store->locked);
    store->locked=false;
}

static bool commit_equal(const router_cve_commit_record_t *left,
                         const router_cve_commit_record_t *right)
{
    return left->slot==right->slot && left->generation==right->generation &&
           left->serial==right->serial &&
           memcmp(left->catalog_sha256,right->catalog_sha256,32U)==0 &&
           memcmp(left->signature_sha256,right->signature_sha256,32U)==0 &&
           memcmp(left->key_id,right->key_id,16U)==0 &&
           left->catalog_time_unknown==right->catalog_time_unknown;
}

static bool store_get_commit(void *context,router_cve_commit_record_t *commit,
                             bool *present)
{
    fake_store_t *store=context;
    assert(store->locked && commit!=NULL && present!=NULL);
    *present=store->commit_present;
    if(*present) *commit=store->commit;
    return true;
}

static bool store_advance_commit(void *context,
    const router_cve_commit_record_t *expected,bool expected_present,
    const router_cve_commit_record_t *desired)
{
    fake_store_t *store=context;
    assert(store->locked && desired!=NULL);
    if(!mutation_allowed(store)) return false;
    if(store->race_advance_enabled) {
        store->commit_present=true;
        store->commit=*desired;
        store->commit.serial=desired->serial+1U;
        store->commit.generation=desired->generation+1U;
        return false;
    }
    if(expected_present!=store->commit_present) return false;
    if(expected_present && (expected==NULL || !commit_equal(expected,&store->commit))) return false;
    if((store->commit_present && (desired->serial<=store->commit.serial ||
                                  desired->generation<=store->commit.generation)) ||
       (!store->commit_present && desired->serial==0U)) return false;
    store->commit=*desired;
    store->commit_present=true;
    return true;
}

static router_cve_install_ops_t store_ops(fake_store_t *store)
{
    router_cve_install_ops_t ops = {
        .enter=store_enter, .leave=store_leave,
        .read=store_read, .write=store_write, .write_atomic=store_write_atomic,
        .sync=store_sync, .get_commit=store_get_commit,
        .advance_commit=store_advance_commit, .context=store};
    return ops;
}

static router_cve_verify_result_t recover_owned_once(
    fake_store_t *store,const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time,size_t catalog_capacity,
    size_t signature_capacity,router_cve_install_status_t *status)
{
    router_cve_install_ops_t ops=store_ops(store);
    release_probe_t catalog_release,signature_release;
    router_cve_owned_bytes_t catalog=
        owned_buffer(catalog_capacity,&catalog_release,false);
    router_cve_owned_bytes_t signature=
        owned_buffer(signature_capacity,&signature_release,true);
    router_cve_verify_result_t result=router_cve_install_recover_owned(
        &catalog,&signature,&ops,crypto,time,status);
    assert_consumed(&catalog);
    assert_consumed(&signature);
    assert(catalog_release.calls==1U&&signature_release.calls==1U);
    return result;
}

static void expect_unchanged(const router_cve_install_status_t *value,
                             const router_cve_install_status_t *before)
{
    assert(memcmp(value, before, sizeof(*value)) == 0);
}

static void put_le16_test(uint8_t *value, uint16_t input)
{
    value[0]=(uint8_t)input; value[1]=(uint8_t)(input>>8U);
}

static void put_le32_test(uint8_t *value, uint32_t input)
{
    value[0]=(uint8_t)input; value[1]=(uint8_t)(input>>8U);
    value[2]=(uint8_t)(input>>16U); value[3]=(uint8_t)(input>>24U);
}

static uint32_t crc32_test(const uint8_t *bytes,size_t size)
{
    uint32_t crc=0xffffffffU;
    size_t bit;
    while(size-- > 0U) {
        crc^=*bytes++;
        for(bit=0U;bit<8U;++bit)
            crc=(crc>>1U)^(0xedb88320U&(uint32_t)-(int32_t)(crc&1U));
    }
    return ~crc;
}

int main(int argc, char **argv)
{
    size_t catalog7_size, sig7_size, catalog8_size, sig8_size, max_size, max_sig_size;
    uint8_t *catalog7, *sig7, *catalog8, *sig8, *max_catalog, *max_sig;
    static const uint8_t spki[] = {0x42U};
    router_cve_trusted_key_t key;
    router_cve_crypto_t crypto;
    router_cve_time_policy_t time;
    router_cve_verified_t verified, verified_before;
    router_cve_verify_result_t result;
    uint8_t scratch_catalog[2048U], scratch_signature[ROUTER_CVE_SIG_MAX_BYTES];
    router_cve_install_scratch_t scratch = {
        scratch_catalog, sizeof(scratch_catalog), scratch_signature, sizeof(scratch_signature)};
    fake_store_t store;
    router_cve_install_ops_t ops;
    router_cve_install_status_t status, before, recovered;
    router_cve_commit_record_t commit7,commit8;
    unsigned fail;

    assert(argc == 7);
    catalog7=load_file(argv[1],&catalog7_size); sig7=load_file(argv[2],&sig7_size);
    catalog8=load_file(argv[3],&catalog8_size); sig8=load_file(argv[4],&sig8_size);
    max_catalog=load_file(argv[5],&max_size); max_sig=load_file(argv[6],&max_sig_size);
    assert(max_size==ROUTER_CVE_DB_MAX_BYTES);
    memcpy(expected_digest[0],sig7+32U,32U);
    memcpy(expected_digest[1],sig8+32U,32U);
    memcpy(expected_digest[2],max_sig+32U,32U);
    expected_digest_count=3U;
    memset(&key,0,sizeof(key)); memcpy(key.key_id,catalog7+112U,16U);
    key.subject_public_key_info=spki; key.subject_public_key_info_size=sizeof(spki);
    crypto.keys=&key; crypto.key_count=1U; crypto.verify=fake_verify; crypto.context=NULL;
    time.reliable=true; time.now_epoch=4070908800ULL+100U; time.allow_unknown=false;

    {
        router_cve_time_policy_t boundary = {
            .reliable = true,
            .now_epoch = 4070908800ULL - 86400ULL,
            .allow_unknown = false,
        };
        assert(router_cve_validate_catalog_time(
                   4070908800ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_OK);
        boundary.now_epoch = 4070908800ULL - 86401ULL;
        assert(router_cve_validate_catalog_time(
                   4070908800ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_NOT_YET_VALID);
        boundary.now_epoch = 4083782399ULL;
        assert(router_cve_validate_catalog_time(
                   4070908800ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_OK);
        boundary.now_epoch = 4083782400ULL;
        assert(router_cve_validate_catalog_time(
                   4070908800ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_STALE);
        boundary.reliable = false;
        assert(router_cve_validate_catalog_time(
                   4070908800ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_TIME_UNKNOWN);
        boundary.allow_unknown = true;
        assert(router_cve_validate_catalog_time(
                   4070908800ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_OK);
        assert(router_cve_validate_catalog_time(
                   4083782400ULL, 4083782400ULL, &boundary) ==
               ROUTER_CVE_VERIFY_BAD_FORMAT);
    }

    {
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        router_cve_owned_bytes_t owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        callback_catalog_handle=&owned_catalog;
        callback_signature_handle=&owned_signature;
        assert(router_cve_verify_owned(&owned_catalog,&owned_signature,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_OK);
        callback_catalog_handle=NULL;
        callback_signature_handle=NULL;
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
    }
    {
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        router_cve_owned_bytes_t owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        auxiliary_allocation_calls=0U;
        auxiliary_largest_request=0U;
        auxiliary_fail_at=1U;
        assert(router_cve_verify_owned(&owned_catalog,&owned_signature,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_CAPACITY);
        auxiliary_fail_at=0U;
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
    }
    {
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog=owned_copy(max_catalog,max_size,&catalog_release,false);
        router_cve_owned_bytes_t owned_signature=owned_copy(max_sig,max_sig_size,&signature_release,true);
        auxiliary_allocation_calls=0U;
        auxiliary_largest_request=0U;
        assert(router_cve_verify_owned(&owned_catalog,&owned_signature,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_FORMAT);
        assert(auxiliary_largest_request<max_size);
        assert(auxiliary_allocation_calls==1U);
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
    }
    {
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        router_cve_owned_bytes_t owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        router_cve_crypto_t no_keys={0};
        fake_store_t no_key_store;
        router_cve_install_ops_t no_key_ops;
        assert(router_cve_verify_owned(&owned_catalog,&owned_signature,&no_keys,&time,&verified)==
               ROUTER_CVE_VERIFY_UNKNOWN_KEY);
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        memset(&no_key_store,0,sizeof(no_key_store));
        no_key_ops=store_ops(&no_key_store);
        owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &no_key_ops,&no_keys,&time,&status)==
               ROUTER_CVE_VERIFY_UNKNOWN_KEY);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        assert(no_key_store.mutation_calls==0U&&!no_key_store.commit_present);
    }

    memset(&verified,0xA5,sizeof(verified)); verified_before=verified;
    result=router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&crypto,&time,&verified);
    assert(result==ROUTER_CVE_VERIFY_OK && verified.catalog.serial==7U &&
           !verified.catalog_time_unknown);
    {
        uint8_t changed[2048U];
        assert(catalog7_size<sizeof(changed)); memcpy(changed,catalog7,catalog7_size);
        mutation_target=changed;
        assert(router_cve_verify_bytes(changed,catalog7_size,sig7,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_OK);
        assert(changed[200U]!=(catalog7[200U]));
    }
    {
        uint8_t changed[2048U];
        assert(catalog7_size<sizeof(changed)); memcpy(changed,catalog7,catalog7_size); changed[200U]^=1U;
        verified=verified_before;
        assert(router_cve_verify_bytes(changed,catalog7_size,sig7,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_HASH);
        assert(memcmp(&verified,&verified_before,sizeof(verified))==0);
    }
    {
        uint8_t changed[ROUTER_CVE_SIG_MAX_BYTES];
        memcpy(changed,sig7,sig7_size); changed[16U]^=1U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,changed,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_UNKNOWN_KEY);
        memcpy(changed,sig7,sig7_size); changed[84U]=2U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,changed,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_SIGNATURE);
        memcpy(changed,sig7,sig7_size); changed[82U]=0U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,changed,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_FORMAT);
        memcpy(changed,sig7,sig7_size); changed[81U]=7U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,changed,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_FORMAT);
        memcpy(changed,sig7,sig7_size); changed[sig7_size-1U]=0x80U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,changed,sig7_size,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_FORMAT);
        memcpy(changed,sig7,80U);
        changed[80U]=0x30U; changed[81U]=0x26U;
        changed[82U]=0x02U; changed[83U]=0x01U; changed[84U]=0x01U;
        changed[85U]=0x02U; changed[86U]=0x21U; changed[87U]=0x00U;
        memset(changed+88U,0xffU,32U);
        put_le16_test(changed+64U,40U); put_le32_test(changed+12U,120U);
        assert(router_cve_verify_bytes(catalog7,catalog7_size,changed,120U,&crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_BAD_FORMAT);
    }
    time.now_epoch=4083782400ULL;
    assert(router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&crypto,&time,&verified)==
           ROUTER_CVE_VERIFY_STALE);
    time.now_epoch=4070908800ULL-86401ULL;
    assert(router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&crypto,&time,&verified)==
           ROUTER_CVE_VERIFY_NOT_YET_VALID);
    time.reliable=false; time.allow_unknown=false;
    assert(router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&crypto,&time,&verified)==
           ROUTER_CVE_VERIFY_TIME_UNKNOWN);
    time.allow_unknown=true;
    assert(router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&crypto,&time,&verified)==
           ROUTER_CVE_VERIFY_OK && verified.catalog_time_unknown);
    time.reliable=true; time.allow_unknown=false; time.now_epoch=4070908900ULL;

    {
        router_cve_trusted_key_t duplicate[2U]={key,key};
        router_cve_crypto_t bad_crypto=crypto;
        bad_crypto.keys=duplicate; bad_crypto.key_count=2U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&bad_crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_UNKNOWN_KEY);
        bad_crypto.keys=&key; bad_crypto.key_count=ROUTER_CVE_MAX_TRUSTED_KEYS+1U;
        assert(router_cve_verify_bytes(catalog7,catalog7_size,sig7,sig7_size,&bad_crypto,&time,&verified)==
               ROUTER_CVE_VERIFY_UNKNOWN_KEY);
    }

    {
        fake_store_t owned_store;
        router_cve_install_ops_t owned_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        const void *expected_catalog_pointer;
        memset(&owned_store,0,sizeof(owned_store));
        owned_ops=store_ops(&owned_store);
        owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        expected_catalog_pointer=owned_catalog.data;
        callback_catalog_handle=&owned_catalog;
        callback_signature_handle=&owned_signature;
        assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &owned_ops,&crypto,&time,&status)==
               ROUTER_CVE_VERIFY_OK);
        callback_catalog_handle=NULL;
        callback_signature_handle=NULL;
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        assert(owned_store.catalog_write_pointer==expected_catalog_pointer);
        assert(owned_store.catalog_read_pointer==expected_catalog_pointer);
        assert(owned_store.commit_present&&owned_store.commit.serial==7U&&status.serial==7U);
        assert(status.created_epoch==4070908800ULL &&
               status.expires_epoch==4083782400ULL &&
               !status.installed_time_unknown);
        {
            release_probe_t recovery_catalog_release,recovery_signature_release;
            router_cve_owned_bytes_t recovery_catalog=
                owned_buffer(ROUTER_CVE_DB_MAX_BYTES,&recovery_catalog_release,false);
            router_cve_owned_bytes_t recovery_signature=
                owned_buffer(ROUTER_CVE_SIG_MAX_BYTES,&recovery_signature_release,true);
            const void *recovery_catalog_pointer=recovery_catalog.data;
            callback_catalog_handle=&recovery_catalog;
            callback_signature_handle=&recovery_signature;
            auxiliary_allocation_calls=0U;
            auxiliary_largest_request=0U;
            assert(router_cve_install_recover_owned(&recovery_catalog,&recovery_signature,
                                                    &owned_ops,&crypto,&time,&recovered)==
                   ROUTER_CVE_VERIFY_OK);
            callback_catalog_handle=NULL;
            callback_signature_handle=NULL;
            assert_consumed(&recovery_catalog);
            assert_consumed(&recovery_signature);
            assert(recovery_catalog_release.calls==1U&&recovery_signature_release.calls==1U);
            assert(owned_store.catalog_read_pointer==recovery_catalog_pointer);
            assert(auxiliary_largest_request<ROUTER_CVE_DB_MAX_BYTES);
            assert(auxiliary_allocation_calls==3U);
            assert(recovered.serial==7U&&recovered.slot==0U);
            assert(recovered.created_epoch==4070908800ULL &&
                   recovered.expires_epoch==4083782400ULL &&
                   !recovered.installed_time_unknown);
        }
        {
            fake_store_t recovery_trial;
            router_cve_time_policy_t policy=time;
            memset(&recovered,0x37,sizeof(recovered));
            before=recovered;

            recovery_trial=owned_store;
            recovery_trial.locked=true;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_BUSY);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            recovery_trial.read_fail_enabled=true;
            recovery_trial.read_fail_object=ROUTER_CVE_OBJECT_JOURNAL0;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_IO);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            recovery_trial.read_fail_enabled=true;
            recovery_trial.read_fail_object=ROUTER_CVE_OBJECT_SLOT0_CATALOG;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_IO);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            recovery_trial.read_fail_enabled=true;
            recovery_trial.read_fail_object=ROUTER_CVE_OBJECT_SLOT0_SIGNATURE;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_IO);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,192U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_CAPACITY);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            recovery_trial.data[ROUTER_CVE_OBJECT_SLOT0_CATALOG][200U]^=1U;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_RECOVERY);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            policy.now_epoch=4083782400ULL;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_STALE);
            expect_unchanged(&recovered,&before);

            recovery_trial=owned_store;
            policy.reliable=false;
            policy.allow_unknown=false;
            assert(recover_owned_once(&recovery_trial,&crypto,&policy,2048U,
                                      ROUTER_CVE_SIG_MAX_BYTES,&recovered)==
                   ROUTER_CVE_VERIFY_TIME_UNKNOWN);
            expect_unchanged(&recovered,&before);
        }
    }
    {
        fake_store_t busy_store;
        router_cve_install_ops_t busy_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        memset(&busy_store,0,sizeof(busy_store));
        busy_store.locked=true;
        busy_ops=store_ops(&busy_store);
        owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &busy_ops,&crypto,&time,&status)==
               ROUTER_CVE_VERIFY_BUSY);
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
    }
    {
        fake_store_t empty_store;
        router_cve_install_ops_t empty_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        memset(&empty_store,0,sizeof(empty_store));
        empty_ops=store_ops(&empty_store);
        owned_catalog=owned_buffer(2048U,&catalog_release,false);
        owned_signature=owned_buffer(ROUTER_CVE_SIG_MAX_BYTES,&signature_release,true);
        assert(router_cve_install_recover_owned(&owned_catalog,&owned_signature,
                                                &empty_ops,&crypto,&time,&recovered)==
               ROUTER_CVE_VERIFY_NOT_FOUND);
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
    }
    {
        fake_store_t max_store;
        router_cve_install_ops_t max_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        memset(&max_store,0,sizeof(max_store));
        max_ops=store_ops(&max_store);
        owned_catalog=owned_copy(max_catalog,max_size,&catalog_release,false);
        owned_signature=owned_copy(max_sig,max_sig_size,&signature_release,true);
        auxiliary_allocation_calls=0U;
        auxiliary_largest_request=0U;
        assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &max_ops,&crypto,&time,&status)==
               ROUTER_CVE_VERIFY_PUBLISH);
        assert(auxiliary_largest_request<max_size);
        assert(auxiliary_allocation_calls==0U);
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        assert(!max_store.commit_present);
    }
    {
        fake_store_t allocation_store;
        router_cve_install_ops_t allocation_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        memset(&allocation_store,0,sizeof(allocation_store));
        allocation_ops=store_ops(&allocation_store);
        owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        auxiliary_allocation_calls=0U;
        auxiliary_fail_at=1U;
        assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &allocation_ops,&crypto,&time,&status)==
               ROUTER_CVE_VERIFY_PUBLISH);
        auxiliary_fail_at=0U;
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        assert(!allocation_store.commit_present);
    }
    {
        fake_store_t tamper_store;
        router_cve_install_ops_t tamper_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        memset(&tamper_store,0,sizeof(tamper_store));
        tamper_store.tamper_catalog_read=true;
        tamper_ops=store_ops(&tamper_store);
        owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &tamper_ops,&crypto,&time,&status)==
               ROUTER_CVE_VERIFY_PUBLISH);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        assert(!tamper_store.commit_present);
    }
    {
        router_cve_install_object_t read_failure;
        for(read_failure=ROUTER_CVE_OBJECT_SLOT0_CATALOG;
            read_failure<=ROUTER_CVE_OBJECT_SLOT0_SIGNATURE;++read_failure) {
            fake_store_t read_store;
            router_cve_install_ops_t read_ops;
            release_probe_t catalog_release,signature_release;
            router_cve_owned_bytes_t owned_catalog;
            router_cve_owned_bytes_t owned_signature;
            memset(&read_store,0,sizeof(read_store));
            read_store.read_fail_enabled=true;
            read_store.read_fail_object=read_failure;
            read_ops=store_ops(&read_store);
            owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
            owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
            assert(router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                    &read_ops,&crypto,&time,&status)==
                   ROUTER_CVE_VERIFY_PUBLISH);
            assert(catalog_release.calls==1U&&signature_release.calls==1U);
            assert(!read_store.commit_present);
        }
    }
    for(fail=1U;fail<=7U;++fail) {
        fake_store_t owned_trial;
        router_cve_install_ops_t owned_trial_ops;
        release_probe_t catalog_release,signature_release;
        router_cve_owned_bytes_t owned_catalog;
        router_cve_owned_bytes_t owned_signature;
        memset(&owned_trial,0,sizeof(owned_trial));
        owned_trial.fail_at=fail;
        owned_trial_ops=store_ops(&owned_trial);
        owned_catalog=owned_copy(catalog7,catalog7_size,&catalog_release,false);
        owned_signature=owned_copy(sig7,sig7_size,&signature_release,true);
        memset(&status,0x29,sizeof(status));
        before=status;
        result=router_cve_install_catalog_owned(&owned_catalog,&owned_signature,
                                                &owned_trial_ops,&crypto,&time,&status);
        assert(result==(fail<=4U?ROUTER_CVE_VERIFY_PUBLISH:
                                ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN));
        assert_consumed(&owned_catalog);
        assert_consumed(&owned_signature);
        assert(catalog_release.calls==1U&&signature_release.calls==1U);
        expect_unchanged(&status,&before);
        if(result==ROUTER_CVE_VERIFY_PUBLISH) assert(!owned_trial.commit_present);
    }

    memset(&store,0,sizeof(store)); ops=store_ops(&store);
    memset(&status,0xA5,sizeof(status)); before=status;
    assert(router_cve_install_catalog(catalog7,catalog7_size,sig7,sig7_size,&ops,&crypto,&time,&scratch,&status)==
           ROUTER_CVE_VERIFY_OK);
    assert(status.available && status.serial==7U && status.generation==1U && status.slot==0U &&
           store.commit_present && store.commit.serial==7U);
    assert(status.created_epoch==4070908800ULL &&
           status.expires_epoch==4083782400ULL &&
           !status.installed_time_unknown);
    commit7=store.commit;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&recovered)==ROUTER_CVE_VERIFY_OK);
    assert(recovered.serial==7U && recovered.slot==0U);
    assert(recovered.created_epoch==4070908800ULL &&
           recovered.expires_epoch==4083782400ULL &&
           !recovered.installed_time_unknown);
    assert(router_cve_install_catalog(catalog7,catalog7_size,sig7,sig7_size,&ops,&crypto,&time,&scratch,&before)==
           ROUTER_CVE_VERIFY_ROLLBACK);

    assert(router_cve_install_catalog(catalog8,catalog8_size,sig8,sig8_size,&ops,&crypto,&time,&scratch,&status)==
           ROUTER_CVE_VERIFY_OK);
    assert(status.serial==8U && status.generation==2U && status.slot==1U && store.commit.serial==8U);
    commit8=store.commit;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&recovered)==ROUTER_CVE_VERIFY_OK &&
           recovered.serial==8U);
    store.read_fail_enabled=true; store.read_fail_object=ROUTER_CVE_OBJECT_JOURNAL1;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&before)==ROUTER_CVE_VERIFY_IO);
    store.read_fail_object=ROUTER_CVE_OBJECT_SLOT1_CATALOG;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&before)==ROUTER_CVE_VERIFY_IO);
    store.read_fail_enabled=false;
    store.data[ROUTER_CVE_OBJECT_SLOT1_CATALOG][200U]^=1U;
    memset(&status,0x3C,sizeof(status)); before=status;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&status)==ROUTER_CVE_VERIFY_RECOVERY);
    expect_unchanged(&status,&before);
    store.data[ROUTER_CVE_OBJECT_SLOT1_CATALOG][200U]^=1U;
    {
        store.commit=commit7;
        assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&recovered)==
               ROUTER_CVE_VERIFY_OK && recovered.serial==7U);
        store.commit=commit8;
        store.present[ROUTER_CVE_OBJECT_JOURNAL1]=false;
        assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&recovered)==
               ROUTER_CVE_VERIFY_RECOVERY);
        store.present[ROUTER_CVE_OBJECT_JOURNAL1]=true;
    }
    time.now_epoch=4083782400ULL;
    memset(&status,0x44,sizeof(status)); before=status;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&status)==ROUTER_CVE_VERIFY_STALE);
    expect_unchanged(&status,&before);
    time.now_epoch=4083782400ULL-1ULL;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&recovered)==ROUTER_CVE_VERIFY_OK);
    time.now_epoch=4070908800ULL-86401ULL;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&status)==ROUTER_CVE_VERIFY_NOT_YET_VALID);
    time.now_epoch=4070908800ULL-86400ULL;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&recovered)==ROUTER_CVE_VERIFY_OK);
    time.reliable=false; time.allow_unknown=false;
    assert(router_cve_install_recover(&ops,&crypto,&time,&scratch,&status)==ROUTER_CVE_VERIFY_TIME_UNKNOWN);
    time.reliable=true; time.allow_unknown=false; time.now_epoch=4070908900ULL;

    for(fail=1U;fail<=7U;++fail) {
        fake_store_t trial;
        router_cve_install_ops_t trial_ops;
        memset(&trial,0,sizeof(trial)); trial.fail_at=fail; trial_ops=store_ops(&trial);
        memset(&status,0x5A,sizeof(status)); before=status;
        result=router_cve_install_catalog(catalog7,catalog7_size,sig7,sig7_size,
                                          &trial_ops,&crypto,&time,&scratch,&status);
        assert(result==ROUTER_CVE_VERIFY_PUBLISH || result==ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN);
        if(result!=ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN) expect_unchanged(&status,&before);
        trial.fail_at=0U;
        result=router_cve_install_recover(&trial_ops,&crypto,&time,&scratch,&recovered);
        assert(result==ROUTER_CVE_VERIFY_NOT_FOUND ||
               (result==ROUTER_CVE_VERIFY_OK && recovered.serial==7U));
    }

    {
        fake_store_t unknown_store;
        router_cve_install_ops_t unknown_ops;
        memset(&unknown_store,0,sizeof(unknown_store)); unknown_ops=store_ops(&unknown_store);
        time.reliable=false; time.allow_unknown=true;
        assert(router_cve_install_catalog(catalog7,catalog7_size,sig7,sig7_size,&unknown_ops,&crypto,&time,&scratch,&status)==
               ROUTER_CVE_VERIFY_OK && status.catalog_time_unknown);
        assert(status.installed_time_unknown);
        assert(unknown_store.commit_present && unknown_store.commit.catalog_time_unknown);
        time.reliable=true; time.allow_unknown=false;
        assert(router_cve_install_recover(&unknown_ops,&crypto,&time,&scratch,&recovered)==
               ROUTER_CVE_VERIFY_OK && recovered.catalog_time_unknown);
        assert(recovered.installed_time_unknown);
        unknown_store.data[ROUTER_CVE_OBJECT_JOURNAL0][25U]=0U;
        put_le32_test(unknown_store.data[ROUTER_CVE_OBJECT_JOURNAL0]+120U,
                      crc32_test(unknown_store.data[ROUTER_CVE_OBJECT_JOURNAL0],120U));
        assert(router_cve_install_recover(&unknown_ops,&crypto,&time,&scratch,&recovered)==
               ROUTER_CVE_VERIFY_RECOVERY);
        unknown_store.data[ROUTER_CVE_OBJECT_JOURNAL0][25U]=1U;
        put_le32_test(unknown_store.data[ROUTER_CVE_OBJECT_JOURNAL0]+120U,
                      crc32_test(unknown_store.data[ROUTER_CVE_OBJECT_JOURNAL0],120U));
        unknown_store.commit.catalog_time_unknown=false;
        assert(router_cve_install_recover(&unknown_ops,&crypto,&time,&scratch,&recovered)==
               ROUTER_CVE_VERIFY_RECOVERY);
    }

    {
        fake_store_t base;
        router_cve_install_ops_t base_ops;
        memset(&base,0,sizeof(base)); base_ops=store_ops(&base);
        time.reliable=true; time.now_epoch=4070908900ULL;
        assert(router_cve_install_catalog(catalog7,catalog7_size,sig7,sig7_size,&base_ops,&crypto,&time,&scratch,&status)==
               ROUTER_CVE_VERIFY_OK);
        base.locked=true;
        assert(router_cve_install_catalog(catalog8,catalog8_size,sig8,sig8_size,&base_ops,&crypto,&time,&scratch,&status)==
               ROUTER_CVE_VERIFY_BUSY);
        base.locked=false;
        {
            fake_store_t race=base;
            router_cve_install_ops_t race_ops=store_ops(&race);
            race.race_advance_enabled=true;
            memset(&status,0x6CU,sizeof(status)); before=status;
            assert(router_cve_install_catalog(catalog8,catalog8_size,sig8,sig8_size,&race_ops,&crypto,&time,&scratch,&status)==
                   ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN);
            assert(race.commit.serial==9U && race.commit.generation==3U);
            expect_unchanged(&status,&before);
        }
        for(fail=1U;fail<=7U;++fail) {
            fake_store_t trial=base;
            router_cve_install_ops_t trial_ops;
            trial.mutation_calls=0U; trial.fail_at=fail; trial_ops=store_ops(&trial);
            memset(&status,0x5A,sizeof(status)); before=status;
            result=router_cve_install_catalog(catalog8,catalog8_size,sig8,sig8_size,
                                              &trial_ops,&crypto,&time,&scratch,&status);
            assert(result==ROUTER_CVE_VERIFY_PUBLISH ||
                   result==ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN);
            if(result==ROUTER_CVE_VERIFY_PUBLISH) expect_unchanged(&status,&before);
            trial.fail_at=0U;
            assert(router_cve_install_recover(&trial_ops,&crypto,&time,&scratch,&recovered)==
                   ROUTER_CVE_VERIFY_OK);
            assert(recovered.serial==7U || recovered.serial==8U);
        }
    }

    free(catalog7); free(sig7); free(catalog8); free(sig8);
    free(max_catalog); free(max_sig);
    puts("PASS: strict JCSG/1 verification and pair-atomic anti-rollback install");
    return 0;
}
