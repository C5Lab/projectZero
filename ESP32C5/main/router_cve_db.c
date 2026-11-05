#include "router_cve_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define JCVE_HEADER_SIZE 192U
#define JCVE_MAX_VALIDITY (180ULL * 86400ULL)
#define JCVE_NO_STRING UINT32_MAX
#define JCVE_SOURCE_SIZE 24U
#define JCVE_MODEL_SIZE 16U
#define JCVE_ALIAS_SIZE 8U
#define JCVE_ADVISORY_SIZE 32U
#define JCVE_FIRMWARE_SIZE 12U
#define JCVE_MAX_SOURCES ROUTER_CVE_DB_MAX_SOURCES
#define JCVE_MAX_MODELS ROUTER_CVE_DB_MAX_MODELS
#define JCVE_MAX_ALIASES ROUTER_CVE_DB_MAX_ALIASES
#define JCVE_MAX_ADVISORIES ROUTER_CVE_DB_MAX_ADVISORIES
#define JCVE_MAX_RULES ROUTER_CVE_DB_MAX_FIRMWARE_RULES
#define JCVE_STRING_MAX 255U
#define JCVE_MAX_RULES_PER_MODEL 256U
#define JCVE_MAX_ADVISORIES_PER_MODEL 128U

enum {
    JCVE_SOURCE_SECTION = 0,
    JCVE_MODEL_SECTION,
    JCVE_ALIAS_SECTION,
    JCVE_ADVISORY_SECTION,
    JCVE_FIRMWARE_SECTION,
    JCVE_STRING_SECTION,
    JCVE_SECTION_COUNT
};

typedef struct {
    uint32_t offset;
    uint32_t count;
} jcve_section_t;

typedef struct {
    uint32_t state[8U];
    uint64_t bit_count;
    uint8_t block[64U];
    size_t used;
} jcve_sha256_t;

typedef struct {
    uint32_t relative;
    uint8_t length;
    bool referenced;
} jcve_string_entry_t;

typedef struct {
    uint64_t hash;
    uint32_t relative;
    uint8_t length;
} jcve_value_key_t;

struct router_cve_db {
    router_cve_db_io_t io;
    void *handle;
    uint8_t *cache;
    router_cve_db_release_fn cache_release;
    void *cache_release_context;
    router_cve_db_alloc_t allocator;
    uint32_t file_size;
    uint64_t created_epoch;
    uint64_t expires_epoch;
    uint64_t serial;
    uint8_t key_id[16U];
    uint8_t payload_sha256[32U];
    uint8_t provenance_sha256[32U];
    jcve_section_t sections[JCVE_SECTION_COUNT];
    jcve_string_entry_t *strings;
    uint32_t string_count;
    uint32_t validation_work;
    uint32_t snapshot_read_ops;
    bool validating;
    bool work_exhausted;
    uint32_t string_hash_bytes;
    uint32_t string_sort_comparisons;
    uint32_t string_compare_bytes;
};

static bool work_take(router_cve_db_t *db,uint32_t units)
{
    if(!db->validating) return true;
    if(units>ROUTER_CVE_DB_MAX_VALIDATION_WORK-db->validation_work) {
        db->work_exhausted=true;
        return false;
    }
    db->validation_work+=units;
    return true;
}

static void *default_allocate(void *context,size_t size)
{
    (void)context;
    return malloc(size);
}

static void default_release(void *context,void *memory,size_t size)
{
    (void)context;
    (void)size;
    free(memory);
}

static void release_cache(router_cve_db_t *db)
{
    if(db->cache!=NULL&&db->cache_release!=NULL) {
        db->cache_release(db->cache_release_context,db->cache,db->file_size);
        db->cache=NULL;
    }
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

static void sha_transform(jcve_sha256_t *sha, const uint8_t block[64U])
{
    uint32_t w[64U];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned i;
    for (i = 0U; i < 16U; ++i) {
        size_t p = (size_t)i * 4U;
        w[i] = ((uint32_t)block[p] << 24U) |
               ((uint32_t)block[p + 1U] << 16U) |
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
        uint32_t s1 = rotr32(e,6U)^rotr32(e,11U)^rotr32(e,25U);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + sha_k[i] + w[i];
        uint32_t s0 = rotr32(a,2U)^rotr32(a,13U)^rotr32(a,22U);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    sha->state[0]+=a; sha->state[1]+=b; sha->state[2]+=c; sha->state[3]+=d;
    sha->state[4]+=e; sha->state[5]+=f; sha->state[6]+=g; sha->state[7]+=h;
}

static void sha_init(jcve_sha256_t *sha)
{
    static const uint32_t initial[8U] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    memset(sha, 0, sizeof(*sha));
    memcpy(sha->state, initial, sizeof(initial));
}

static void sha_update(jcve_sha256_t *sha, const void *data, size_t size)
{
    const uint8_t *bytes = data;
    sha->bit_count += (uint64_t)size * 8ULL;
    while (size > 0U) {
        size_t take = 64U - sha->used;
        if (take > size) take = size;
        memcpy(sha->block + sha->used, bytes, take);
        sha->used += take;
        bytes += take;
        size -= take;
        if (sha->used == 64U) {
            sha_transform(sha, sha->block);
            sha->used = 0U;
        }
    }
}

static void sha_final(jcve_sha256_t *sha, uint8_t output[32U])
{
    uint64_t bits = sha->bit_count;
    unsigned i;
    sha->block[sha->used++] = 0x80U;
    if (sha->used > 56U) {
        memset(sha->block + sha->used, 0, 64U - sha->used);
        sha_transform(sha, sha->block);
        sha->used = 0U;
    }
    memset(sha->block + sha->used, 0, 56U - sha->used);
    for (i = 0U; i < 8U; ++i)
        sha->block[63U - i] = (uint8_t)(bits >> (i * 8U));
    sha_transform(sha, sha->block);
    for (i = 0U; i < 8U; ++i) {
        output[i*4U]=(uint8_t)(sha->state[i]>>24U);
        output[i*4U+1U]=(uint8_t)(sha->state[i]>>16U);
        output[i*4U+2U]=(uint8_t)(sha->state[i]>>8U);
        output[i*4U+3U]=(uint8_t)sha->state[i];
    }
    memset(sha, 0, sizeof(*sha));
}

static uint32_t crc_update(uint32_t crc, const uint8_t *bytes, size_t size)
{
    size_t i;
    crc = ~crc;
    while (size-- > 0U) {
        crc ^= *bytes++;
        for (i = 0U; i < 8U; ++i)
            crc = (crc >> 1U) ^ (0xEDB88320U & (uint32_t)-(int32_t)(crc & 1U));
    }
    return ~crc;
}

static router_cve_io_result_t stdio_open(void *context, const char *path, void **handle)
{
    FILE *file;
    (void)context;
    file = fopen(path, "rb");
    if (file == NULL)
        return errno == ENOENT ? ROUTER_CVE_IO_MISSING : ROUTER_CVE_IO_ERROR;
    *handle = file;
    return ROUTER_CVE_IO_OK;
}

static bool stdio_size(void *context, void *handle, uint32_t *size)
{
    FILE *file = handle;
    long length;
    (void)context;
    if (fseek(file, 0L, SEEK_END) != 0) return false;
    length = ftell(file);
    if (length < 0L || (uint64_t)length > UINT32_MAX) return false;
    if (fseek(file, 0L, SEEK_SET) != 0) return false;
    *size = (uint32_t)length;
    return true;
}

static bool stdio_read(void *context, void *handle, uint32_t offset,
                       void *buffer, size_t size)
{
    FILE *file = handle;
    (void)context;
    if (offset > (uint32_t)LONG_MAX || fseek(file, (long)offset, SEEK_SET) != 0)
        return false;
    return fread(buffer, 1U, size, file) == size;
}

static bool stdio_close(void *context, void *handle)
{
    (void)context;
    return fclose(handle) == 0;
}

static bool db_read(const router_cve_db_t *db, uint32_t offset,
                    void *buffer, size_t size)
{
    if (size > db->file_size || offset > db->file_size - size) return false;
    if (db->cache != NULL) {
        memcpy(buffer, db->cache + offset, size);
        return true;
    }
    return db->io.read_at(db->io.context, db->handle, offset, buffer, size);
}

static bool all_zero(const uint8_t *bytes, size_t size)
{
    size_t i;
    for (i = 0U; i < size; ++i) if (bytes[i] != 0U) return false;
    return true;
}

static bool valid_utf8(const uint8_t *s, size_t n)
{
    size_t i = 0U;
    while (i < n) {
        uint32_t cp;
        size_t need;
        uint8_t first = s[i++];
        if (first < 0x80U) {
            if (first == 0U) return false;
            continue;
        }
        if (first >= 0xC2U && first <= 0xDFU) { cp=first&0x1FU; need=1U; }
        else if (first >= 0xE0U && first <= 0xEFU) { cp=first&0x0FU; need=2U; }
        else if (first >= 0xF0U && first <= 0xF4U) { cp=first&0x07U; need=3U; }
        else return false;
        if (need > n - i) return false;
        while (need-- > 0U) {
            if ((s[i] & 0xC0U) != 0x80U) return false;
            cp = (cp << 6U) | (s[i++] & 0x3FU);
        }
        if (cp > 0x10FFFFU || (cp >= 0xD800U && cp <= 0xDFFFU) ||
            (first == 0xE0U && cp < 0x800U) ||
            (first == 0xF0U && cp < 0x10000U)) return false;
    }
    return true;
}

static bool string_at(router_cve_db_t *db, uint32_t relative,
                      char output[JCVE_STRING_MAX + 1U], uint8_t *length)
{
    const jcve_section_t *section = &db->sections[JCVE_STRING_SECTION];
    uint32_t low=0U,high=db->string_count;
    while(low<high) {
        uint32_t middle=low+(high-low)/2U;
        jcve_string_entry_t *entry=&db->strings[middle];
        if(!work_take(db,1U)) return false;
        if(relative<entry->relative) high=middle;
        else if(relative>entry->relative) low=middle+1U;
        else {
            if(!db_read(db,section->offset+relative+1U,output,entry->length))
                return false;
            output[entry->length]='\0';
            if(length!=NULL) *length=entry->length;
            if(db->validating) entry->referenced=true;
            return true;
        }
    }
    return false;
}

static bool record_u32(router_cve_db_t *db, unsigned section,
                       uint32_t index, unsigned field, uint32_t *value)
{
    static const uint32_t sizes[5U] = {
        JCVE_SOURCE_SIZE, JCVE_MODEL_SIZE, JCVE_ALIAS_SIZE,
        JCVE_ADVISORY_SIZE, JCVE_FIRMWARE_SIZE};
    uint8_t bytes[4U];
    uint32_t offset;
    if (section >= 5U || index >= db->sections[section].count||!work_take(db,1U))
        return false;
    offset = db->sections[section].offset + index * sizes[section] + field * 4U;
    if (!db_read(db, offset, bytes, sizeof(bytes))) return false;
    *value = le32(bytes);
    return true;
}

static bool canonical_identity(const char *value)
{
    const uint8_t *p = (const uint8_t *)value;
    size_t total = strlen(value);
    bool previous_space = false;
    bool any = false;
    if(!valid_utf8(p,total)) return false;
    while (*p != 0U) {
        if (*p < 0x80U) {
            if ((*p >= (uint8_t)'A' && *p <= (uint8_t)'Z') ||
                (!(*p >= (uint8_t)'a' && *p <= (uint8_t)'z') &&
                 !(*p >= (uint8_t)'0' && *p <= (uint8_t)'9') &&
                 *p != (uint8_t)' ')) return false;
            if (*p == (uint8_t)' ') {
                if (!any || previous_space || p[1] == 0U) return false;
                previous_space = true;
            } else {
                any = true;
                previous_space = false;
            }
            ++p;
        } else {
            size_t width = *p < 0xE0U ? 2U : (*p < 0xF0U ? 3U : 4U);
            any = true;
            previous_space = false;
            p += width;
        }
    }
    return any;
}

static bool canonical_id(const char *value)
{
    size_t i, n = strlen(value);
    if (n == 0U || n > 64U) return false;
    for (i = 0U; i < n; ++i) {
        char c = value[i];
        bool alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!alnum && c != '.' && c != '_' && c != '-') return false;
        if (i == 0U && !alnum) return false;
    }
    return true;
}

static bool lower_hex64(const char *value)
{
    size_t i;
    if (strlen(value) != 64U) return false;
    for (i=0U;i<64U;++i)
        if (!((value[i]>='0'&&value[i]<='9')||(value[i]>='a'&&value[i]<='f')))
            return false;
    return true;
}

static bool canonical_https(const char *value)
{
    const char *host;
    const char *path;
    const char *colon;
    size_t i, host_len, authority_len;
    unsigned long port=0UL;
    if (strncmp(value, "https://", 8U) != 0) return false;
    for (i=0U; value[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c <= 0x20U || c == 0x7FU || c >= 0x80U) return false;
        if (c == '#' || c == '?' || c == '%') return false;
    }
    host = value + 8U;
    path = strchr(host, '/');
    authority_len = path == NULL ? strlen(host) : (size_t)(path - host);
    colon=memchr(host,':',authority_len);
    host_len=colon==NULL?authority_len:(size_t)(colon-host);
    if (host_len == 0U || host[0] == '.' || host[host_len-1U] == '.' ||
        (colon!=NULL&&memchr(colon+1,':',authority_len-host_len-1U)!=NULL)) return false;
    for (i=0U;i<host_len;++i) {
        char c=host[i];
        if (!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='-'))
            return false;
        if(c=='.'&&i+1U<host_len&&host[i+1U]=='.') return false;
        if(c=='-'&&(i==0U||i+1U==host_len||host[i-1U]=='.'||host[i+1U]=='.'))
            return false;
    }
    if(colon!=NULL) {
        size_t port_len=authority_len-host_len-1U;
        if(port_len==0U||(port_len>1U&&colon[1]=='0')) return false;
        for(i=1U;i<=port_len;++i) {
            if(colon[i]<'0'||colon[i]>'9') return false;
            port=port*10UL+(unsigned long)(colon[i]-'0');
            if(port>65535UL) return false;
        }
        if(port==0UL||port==443UL) return false;
    }
    if(path!=NULL) {
        const char *p=path;
        while(*p!='\0') {
            char c=*p++;
            if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
                 (c>='0'&&c<='9')||c=='.'||c=='_'||c=='~'||
                 c==':'||c=='@'||c=='/'||c=='-')) return false;
        }
    }
    return true;
}

static bool calendar_date(const char *value)
{
    unsigned year, month, day, max_day;
    bool leap;
    size_t i;
    if (strlen(value) != 10U || value[4] != '-' || value[7] != '-') return false;
    for(i=0U;i<10U;++i) {
        if(i==4U||i==7U) continue;
        if(value[i]<'0'||value[i]>'9') return false;
    }
    if (sscanf(value, "%4u-%2u-%2u", &year, &month, &day) != 3) return false;
    if (year == 0U || month < 1U || month > 12U || day < 1U) return false;
    leap = year%4U==0U && (year%100U!=0U || year%400U==0U);
    max_day = month==2U ? (leap?29U:28U) :
              ((month==4U||month==6U||month==9U||month==11U)?30U:31U);
    return day <= max_day;
}

static bool retrieved_time(const char *value)
{
    char date[11U];
    unsigned hour,minute,second;
    size_t i;
    if(strlen(value)!=20U||value[4]!='-'||value[7]!='-'||value[10]!='T'||
       value[13]!=':'||value[16]!=':'||value[19]!='Z') return false;
    for(i=0U;i<19U;++i) {
        if(i==4U||i==7U||i==10U||i==13U||i==16U) continue;
        if(value[i]<'0'||value[i]>'9') return false;
    }
    memcpy(date,value,10U); date[10]='\0';
    if(!calendar_date(date)||sscanf(value+11U,"%2u:%2u:%2uZ",&hour,&minute,&second)!=3)
        return false;
    return hour<24U&&minute<60U&&second<60U;
}

static bool cve_text(const char *value)
{
    size_t i, n = strlen(value);
    if (n < 13U || strncmp(value,"CVE-",4U)!=0 || value[8]!='-') return false;
    for(i=4U;i<8U;++i) if(value[i]<'0'||value[i]>'9') return false;
    for(i=9U;i<n;++i) if(value[i]<'0'||value[i]>'9') return false;
    return n-9U >= 4U;
}

static bool severity_text(const char *value)
{
    static const char *const values[] = {
        "critical","high","low","medium","none","unknown"};
    size_t i;
    for (i=0U;i<sizeof(values)/sizeof(values[0]);++i)
        if (strcmp(value,values[i])==0) return true;
    return false;
}

static bool value_key_compare(router_cve_db_t *db,const jcve_value_key_t *a,
                              const jcve_value_key_t *b,int *order)
{
    const jcve_section_t *section=&db->sections[JCVE_STRING_SECTION];
    uint32_t i;
    if(!work_take(db,1U)) return false;
    ++db->string_sort_comparisons;
    if(a->hash!=b->hash) { *order=a->hash<b->hash?-1:1; return true; }
    if(a->length!=b->length) { *order=a->length<b->length?-1:1; return true; }
    for(i=0U;i<a->length;++i) {
        uint8_t av=db->cache[section->offset+a->relative+1U+i];
        uint8_t bv=db->cache[section->offset+b->relative+1U+i];
        if(!work_take(db,1U)) return false;
        ++db->string_compare_bytes;
        if(av!=bv) { *order=av<bv?-1:1; return true; }
    }
    *order=0;
    return true;
}

static router_cve_db_result_t validate_strings(router_cve_db_t *db)
{
    const jcve_section_t *section=&db->sections[JCVE_STRING_SECTION];
    uint32_t cursor=0U,count=0U,i;
    jcve_value_key_t *storage,*source,*target;
    while(cursor<section->count) {
        uint8_t len,bytes[JCVE_STRING_MAX];
        uint32_t k;
        if(!work_take(db,1U)||!db_read(db,section->offset+cursor,&len,1U)||
           len==0U||(uint32_t)len>section->count-cursor-1U||
           !db_read(db,section->offset+cursor+1U,bytes,len)||
           !valid_utf8(bytes,len)) return ROUTER_CVE_DB_FORMAT;
        for(k=0U;k<len;++k) if(bytes[k]<0x20U||bytes[k]>0x7EU)
            return ROUTER_CVE_DB_FORMAT;
        if(++count>ROUTER_CVE_DB_MAX_STRING_ENTRIES)
            return ROUTER_CVE_DB_CAPACITY;
        cursor += 1U+(uint32_t)len;
    }
    if(cursor!=section->count||count==0U) return ROUTER_CVE_DB_FORMAT;
    db->strings=db->allocator.allocate(db->allocator.context,
                                       count*sizeof(*db->strings));
    if(db->strings==NULL) return ROUTER_CVE_DB_CAPACITY;
    memset(db->strings,0,count*sizeof(*db->strings));
    db->string_count=count;
    cursor=0U;
    for(i=0U;i<count;++i) {
        uint8_t len;
        if(!db_read(db,section->offset+cursor,&len,1U)) return ROUTER_CVE_DB_IO;
        db->strings[i].relative=cursor;
        db->strings[i].length=len;
        cursor+=1U+(uint32_t)len;
    }
    storage=db->allocator.allocate(db->allocator.context,
                                   2U*count*sizeof(*storage));
    if(storage==NULL) return ROUTER_CVE_DB_CAPACITY;
    for(i=0U;i<count;++i) {
        const jcve_string_entry_t *entry=&db->strings[i];
        uint64_t hash=UINT64_C(14695981039346656037);
        uint32_t byte;
        for(byte=0U;byte<entry->length;++byte) {
            if(!work_take(db,1U)) {
                db->allocator.release(db->allocator.context,storage,
                                      2U*count*sizeof(*storage));
                return ROUTER_CVE_DB_CAPACITY;
            }
            ++db->string_hash_bytes;
            hash^=db->cache[section->offset+entry->relative+1U+byte];
            hash*=UINT64_C(1099511628211);
        }
        storage[i].hash=hash;
        storage[i].relative=entry->relative;
        storage[i].length=entry->length;
    }
    source=storage;
    target=storage+count;
    {
        uint32_t width;
        for(width=1U;width<count;width*=2U) {
            uint32_t left;
            for(left=0U;left<count;left+=2U*width) {
                uint32_t middle=left+width<count?left+width:count;
                uint32_t end=left+2U*width<count?left+2U*width:count;
                uint32_t a=left,b=middle,out=left;
                while(a<middle&&b<end) {
                    int order;
                    if(!value_key_compare(db,&source[a],&source[b],&order)) {
                        db->allocator.release(db->allocator.context,storage,
                                              2U*count*sizeof(*storage));
                        return ROUTER_CVE_DB_CAPACITY;
                    }
                    target[out++]=order<=0?source[a++]:source[b++];
                }
                while(a<middle) target[out++]=source[a++];
                while(b<end) target[out++]=source[b++];
            }
            { jcve_value_key_t *swap=source; source=target; target=swap; }
            if(width>count/2U) break;
        }
    }
    for(i=1U;i<count;++i) {
        int order;
        if(!value_key_compare(db,&source[i-1U],&source[i],&order)) {
            db->allocator.release(db->allocator.context,storage,
                                  2U*count*sizeof(*storage));
            return ROUTER_CVE_DB_CAPACITY;
        }
        if(order==0) {
            db->allocator.release(db->allocator.context,storage,
                                  2U*count*sizeof(*storage));
            return ROUTER_CVE_DB_FORMAT;
        }
    }
    db->allocator.release(db->allocator.context,storage,
                          2U*count*sizeof(*storage));
    return ROUTER_CVE_DB_OK;
}

static bool get_text(router_cve_db_t *db, unsigned section,
                     uint32_t index, unsigned field,
                     char output[JCVE_STRING_MAX+1U])
{
    uint32_t offset;
    return record_u32(db,section,index,field,&offset) &&
           string_at(db,offset,output,NULL);
}

static void sha_literal(jcve_sha256_t *sha, const char *text)
{
    sha_update(sha,text,strlen(text));
}

static void sha_json_string(jcve_sha256_t *sha, const char *text)
{
    const uint8_t *p=(const uint8_t *)text;
    static const char hex[]="0123456789abcdef";
    sha_literal(sha,"\"");
    while(*p!=0U) {
        uint8_t c=*p++;
        if(c=='\"'||c=='\\') { char pair[2]={'\\',(char)c}; sha_update(sha,pair,2U); }
        else if(c=='\b') sha_literal(sha,"\\b");
        else if(c=='\f') sha_literal(sha,"\\f");
        else if(c=='\n') sha_literal(sha,"\\n");
        else if(c=='\r') sha_literal(sha,"\\r");
        else if(c=='\t') sha_literal(sha,"\\t");
        else if(c<0x20U) {
            char escaped[6]={'\\','u','0','0',hex[c>>4U],hex[c&15U]};
            sha_update(sha,escaped,sizeof(escaped));
        } else sha_update(sha,&c,1U);
    }
    sha_literal(sha,"\"");
}

static bool validate_sources(router_cve_db_t *db,uint8_t digest[32U])
{
    uint32_t i;
    char fields[6U][JCVE_STRING_MAX+1U];
    char previous[JCVE_STRING_MAX+1U]={0};
    jcve_sha256_t sha;
    sha_init(&sha);
    sha_literal(&sha,"{\"sources\":[");
    for(i=0U;i<db->sections[JCVE_SOURCE_SECTION].count;++i) {
        unsigned f;
        for(f=0U;f<6U;++f)
            if(!get_text(db,JCVE_SOURCE_SECTION,i,f,fields[f])) return false;
        if(!canonical_id(fields[0]) || !canonical_https(fields[1]) ||
           !retrieved_time(fields[2]) || fields[3][0]=='\0' || fields[4][0]=='\0' ||
           !lower_hex64(fields[5])) return false;
        if(i>0U && strcmp(previous,fields[0])>=0) return false;
        memcpy(previous,fields[0],strlen(fields[0])+1U);
        if(i>0U) sha_literal(&sha,",");
        sha_literal(&sha,"{\"id\":"); sha_json_string(&sha,fields[0]);
        sha_literal(&sha,",\"license\":"); sha_json_string(&sha,fields[3]);
        sha_literal(&sha,",\"retrieved_utc\":"); sha_json_string(&sha,fields[2]);
        sha_literal(&sha,",\"revision\":"); sha_json_string(&sha,fields[4]);
        sha_literal(&sha,",\"sha256\":"); sha_json_string(&sha,fields[5]);
        sha_literal(&sha,",\"url\":"); sha_json_string(&sha,fields[1]);
        sha_literal(&sha,"}");
    }
    sha_literal(&sha,"]}\n");
    sha_final(&sha,digest);
    return true;
}

static bool validate_models(router_cve_db_t *db)
{
    uint32_t i,j;
    char vendor[JCVE_STRING_MAX+1U],model[JCVE_STRING_MAX+1U];
    char pv[JCVE_STRING_MAX+1U]={0},pm[JCVE_STRING_MAX+1U]={0};
    for(i=0U;i<db->sections[JCVE_MODEL_SECTION].count;++i) {
        if(!get_text(db,JCVE_MODEL_SECTION,i,0U,vendor) ||
           !get_text(db,JCVE_MODEL_SECTION,i,1U,model) ||
           !canonical_identity(vendor) || !canonical_identity(model)) return false;
        if(i>0U && (strcmp(pv,vendor)>0 ||
           (strcmp(pv,vendor)==0 && strcmp(pm,model)>=0))) return false;
        for(j=0U;j<i;++j) {
            char other[JCVE_STRING_MAX+1U];
            if(!get_text(db,JCVE_MODEL_SECTION,j,1U,other)) return false;
            if(strcmp(other,model)==0) return false;
        }
        memcpy(pv,vendor,strlen(vendor)+1U);
        memcpy(pm,model,strlen(model)+1U);
    }
    return true;
}

static bool validate_aliases(router_cve_db_t *db)
{
    uint32_t i,j,model_index;
    char alias[JCVE_STRING_MAX+1U],previous[JCVE_STRING_MAX+1U]={0};
    uint32_t previous_model=0U;
    for(i=0U;i<db->sections[JCVE_ALIAS_SECTION].count;++i) {
        if(!get_text(db,JCVE_ALIAS_SECTION,i,0U,alias) ||
           !record_u32(db,JCVE_ALIAS_SECTION,i,1U,&model_index) ||
           model_index>=db->sections[JCVE_MODEL_SECTION].count ||
           !canonical_identity(alias)) return false;
        if(i>0U && (strcmp(previous,alias)>0 ||
           (strcmp(previous,alias)==0 && previous_model>=model_index))) return false;
        if(i>0U && strcmp(previous,alias)==0) return false;
        for(j=0U;j<db->sections[JCVE_MODEL_SECTION].count;++j) {
            char primary[JCVE_STRING_MAX+1U];
            if(!get_text(db,JCVE_MODEL_SECTION,j,1U,primary)) return false;
            if(strcmp(primary,alias)==0 && j!=model_index) return false;
        }
        memcpy(previous,alias,strlen(alias)+1U);
        previous_model=model_index;
    }
    return true;
}

static bool validate_advisories(router_cve_db_t *db)
{
    uint32_t i,source,kev;
    char cve[JCVE_STRING_MAX+1U],url[JCVE_STRING_MAX+1U];
    char published[JCVE_STRING_MAX+1U],severity[JCVE_STRING_MAX+1U];
    char fixed[JCVE_STRING_MAX+1U],previous[JCVE_STRING_MAX+1U]={0};
    uint8_t tail[4U];
    for(i=0U;i<db->sections[JCVE_ADVISORY_SECTION].count;++i) {
        uint32_t base=db->sections[JCVE_ADVISORY_SECTION].offset+i*JCVE_ADVISORY_SIZE;
        if(!record_u32(db,JCVE_ADVISORY_SECTION,i,0U,&source) ||
           source>=db->sections[JCVE_SOURCE_SECTION].count ||
           !get_text(db,JCVE_ADVISORY_SECTION,i,1U,cve) ||
           !get_text(db,JCVE_ADVISORY_SECTION,i,2U,url) ||
           !get_text(db,JCVE_ADVISORY_SECTION,i,3U,published) ||
           !get_text(db,JCVE_ADVISORY_SECTION,i,4U,severity) ||
           !record_u32(db,JCVE_ADVISORY_SECTION,i,5U,&kev) ||
           !get_text(db,JCVE_ADVISORY_SECTION,i,6U,fixed) ||
           !db_read(db,base+28U,tail,sizeof(tail))) return false;
        if(!cve_text(cve)||!canonical_https(url)||!calendar_date(published)||
           !severity_text(severity)||fixed[0]=='\0'||(tail[0]&~1U)!=0U||
           tail[1]!=0U||tail[2]!=0U||tail[3]!=0U) return false;
        if(kev!=JCVE_NO_STRING) {
            char date[JCVE_STRING_MAX+1U];
            if(!string_at(db,kev,date,NULL)||!calendar_date(date)) return false;
        }
        if(i>0U && strcmp(previous,cve)>=0) return false;
        memcpy(previous,cve,strlen(cve)+1U);
    }
    return true;
}

static bool validate_rules(router_cve_db_t *db)
{
    uint32_t i,model,advisory,previous_model=0U,previous_advisory=0U;
    char firmware[JCVE_STRING_MAX+1U],previous[JCVE_STRING_MAX+1U]={0};
    for(i=0U;i<db->sections[JCVE_FIRMWARE_SECTION].count;++i) {
        if(!record_u32(db,JCVE_FIRMWARE_SECTION,i,0U,&model)||
           !record_u32(db,JCVE_FIRMWARE_SECTION,i,1U,&advisory)||
           !get_text(db,JCVE_FIRMWARE_SECTION,i,2U,firmware)||
           model>=db->sections[JCVE_MODEL_SECTION].count||
           advisory>=db->sections[JCVE_ADVISORY_SECTION].count||
           !canonical_identity(firmware)) return false;
        if(i>0U && (model<previous_model ||
           (model==previous_model && advisory<previous_advisory) ||
           (model==previous_model && advisory==previous_advisory &&
            strcmp(firmware,previous)<=0))) return false;
        previous_model=model; previous_advisory=advisory;
        memcpy(previous,firmware,strlen(firmware)+1U);
    }
    for(i=0U;i<db->sections[JCVE_MODEL_SECTION].count;++i) {
        uint32_t first,count,j,actual_first=0U,actual_count=0U;
        uint32_t unique_advisories=0U,prior_advisory=UINT32_MAX;
        if(!record_u32(db,JCVE_MODEL_SECTION,i,2U,&first)||
           !record_u32(db,JCVE_MODEL_SECTION,i,3U,&count)) return false;
        for(j=0U;j<db->sections[JCVE_FIRMWARE_SECTION].count;++j) {
            uint32_t owner,owned_advisory;
            if(!record_u32(db,JCVE_FIRMWARE_SECTION,j,0U,&owner)) return false;
            if(owner==i) {
                if(!record_u32(db,JCVE_FIRMWARE_SECTION,j,1U,&owned_advisory))
                    return false;
                if(actual_count==0U) actual_first=j;
                ++actual_count;
                if(owned_advisory!=prior_advisory) {
                    ++unique_advisories;
                    prior_advisory=owned_advisory;
                }
            }
        }
        if(actual_count>JCVE_MAX_RULES_PER_MODEL||
           unique_advisories>JCVE_MAX_ADVISORIES_PER_MODEL) return false;
        if(actual_count==0U) { if(first!=0U||count!=0U) return false; }
        else if(first!=actual_first||count!=actual_count) return false;
    }
    for(i=0U;i<db->sections[JCVE_ADVISORY_SECTION].count;++i) {
        uint32_t j; bool found=false;
        for(j=0U;j<db->sections[JCVE_FIRMWARE_SECTION].count;++j) {
            uint32_t advisory;
            if(!record_u32(db,JCVE_FIRMWARE_SECTION,j,1U,&advisory)) return false;
            if(advisory==i) found=true;
        }
        if(!found) return false;
    }
    return true;
}

static router_cve_db_result_t validate_image(router_cve_db_t *db)
{
    uint8_t header[JCVE_HEADER_SIZE],buffer[512U],digest[32U],provenance[32U];
    uint32_t declared,stored_crc,cursor,remaining,crc=0U;
    uint64_t created,expires,serial;
    unsigned i;
    jcve_sha256_t sha;
    static const uint32_t limits[JCVE_SECTION_COUNT]={
        JCVE_MAX_SOURCES,JCVE_MAX_MODELS,JCVE_MAX_ALIASES,
        JCVE_MAX_ADVISORIES,JCVE_MAX_RULES,ROUTER_CVE_DB_MAX_BYTES};
    static const uint32_t units[JCVE_SECTION_COUNT]={
        JCVE_SOURCE_SIZE,JCVE_MODEL_SIZE,JCVE_ALIAS_SIZE,
        JCVE_ADVISORY_SIZE,JCVE_FIRMWARE_SIZE,1U};
    if(db->file_size<JCVE_HEADER_SIZE||db->file_size>ROUTER_CVE_DB_MAX_BYTES)
        return ROUTER_CVE_DB_FORMAT;
    if(!db_read(db,0U,header,sizeof(header))) return ROUTER_CVE_DB_IO;
    if(memcmp(header,"JCVE",4U)!=0||header[4]!=1U||header[5]!=0U||
       header[6]!=0xC0U||header[7]!=0U||le32(header+8U)!=0U||
       le32(header+20U)!=0U||!all_zero(header+176U,16U))
        return ROUTER_CVE_DB_FORMAT;
    declared=le32(header+12U);
    if(declared!=db->file_size) return ROUTER_CVE_DB_FORMAT;
    created=le64(header+24U); expires=le64(header+32U); serial=le64(header+40U);
    if(expires<=created||expires-created>JCVE_MAX_VALIDITY||serial==0U||
       all_zero(header+112U,16U)) return ROUTER_CVE_DB_FORMAT;
    stored_crc=le32(header+16U);
    sha_init(&sha);
    cursor=JCVE_HEADER_SIZE;
    remaining=db->file_size-JCVE_HEADER_SIZE;
    while(remaining>0U) {
        size_t take=remaining>sizeof(buffer)?sizeof(buffer):(size_t)remaining;
        if(!db_read(db,cursor,buffer,take)) return ROUTER_CVE_DB_IO;
        crc=crc_update(crc,buffer,take);
        sha_update(&sha,buffer,take);
        cursor+=(uint32_t)take; remaining-=(uint32_t)take;
    }
    if(crc!=stored_crc) return ROUTER_CVE_DB_CRC;
    sha_final(&sha,digest);
    if(memcmp(digest,header+48U,32U)!=0) return ROUTER_CVE_DB_HASH;
    cursor=JCVE_HEADER_SIZE;
    for(i=0U;i<JCVE_SECTION_COUNT;++i) {
        uint32_t offset=le32(header+128U+i*8U);
        uint32_t count=le32(header+132U+i*8U);
        uint32_t bytes;
        if(offset!=cursor||count>limits[i]) return ROUTER_CVE_DB_FORMAT;
        if(i<JCVE_STRING_SECTION && count>UINT32_MAX/units[i])
            return ROUTER_CVE_DB_FORMAT;
        bytes=count*units[i];
        if(bytes>db->file_size-cursor) return ROUTER_CVE_DB_FORMAT;
        db->sections[i].offset=offset; db->sections[i].count=count;
        cursor+=bytes;
    }
    if(cursor!=db->file_size||db->sections[0].count==0U||
       db->sections[1].count==0U||db->sections[3].count==0U||
       db->sections[4].count==0U||db->sections[5].count==0U)
        return ROUTER_CVE_DB_FORMAT;
    db->created_epoch=created; db->expires_epoch=expires; db->serial=serial;
    memcpy(db->payload_sha256,header+48U,32U);
    memcpy(db->provenance_sha256,header+80U,32U);
    memcpy(db->key_id,header+112U,16U);
    router_cve_db_result_t string_result;
    db->validating=true;
    string_result=validate_strings(db);
    if(string_result!=ROUTER_CVE_DB_OK) {
        db->validating=false;
        return string_result;
    }
    if(!validate_sources(db,provenance)) {
        db->validating=false;
        return db->work_exhausted?ROUTER_CVE_DB_CAPACITY:ROUTER_CVE_DB_FORMAT;
    }
    if(memcmp(provenance,db->provenance_sha256,sizeof(provenance))!=0)
        { db->validating=false; return ROUTER_CVE_DB_HASH; }
    if(!validate_models(db)||!validate_aliases(db)||
       !validate_advisories(db)||!validate_rules(db)) {
        db->validating=false;
        return db->work_exhausted?ROUTER_CVE_DB_CAPACITY:ROUTER_CVE_DB_FORMAT;
    }
    for(i=0U;i<db->string_count;++i) if(!db->strings[i].referenced) {
        db->validating=false;
        return ROUTER_CVE_DB_FORMAT;
    }
    db->validating=false;
    return ROUTER_CVE_DB_OK;
}

router_cve_db_t *router_cve_db_open_with_io(
    const char *path,const router_cve_db_alloc_t *allocator,
    const router_cve_db_io_t *io,router_cve_db_result_t *result)
{
    router_cve_db_t *db;
    router_cve_io_result_t opened;
    router_cve_db_result_t checked;
    if(result==NULL) return NULL;
    *result=ROUTER_CVE_DB_IO;
    if(path==NULL||io==NULL||io->open==NULL||io->size==NULL||
       io->read_at==NULL||io->close==NULL||
       (allocator!=NULL&&(allocator->allocate==NULL||allocator->release==NULL)))
        return NULL;
    db=calloc(1U,sizeof(*db));
    if(db==NULL) return NULL;
    db->io=*io;
    if(allocator!=NULL) db->allocator=*allocator;
    else {
        db->allocator.allocate=default_allocate;
        db->allocator.release=default_release;
        db->allocator.context=NULL;
    }
    db->cache_release=db->allocator.release;
    db->cache_release_context=db->allocator.context;
    opened=db->io.open(db->io.context,path,&db->handle);
    if(opened!=ROUTER_CVE_IO_OK) {
        *result=opened==ROUTER_CVE_IO_MISSING?ROUTER_CVE_DB_NOT_FOUND:ROUTER_CVE_DB_IO;
        free(db); return NULL;
    }
    if(!db->io.size(db->io.context,db->handle,&db->file_size)) {
        (void)db->io.close(db->io.context,db->handle); free(db); return NULL;
    }
    if(db->file_size<JCVE_HEADER_SIZE||db->file_size>ROUTER_CVE_DB_MAX_BYTES) {
        (void)db->io.close(db->io.context,db->handle);
        free(db);
        *result=ROUTER_CVE_DB_FORMAT;
        return NULL;
    }
    db->cache=db->allocator.allocate(db->allocator.context,db->file_size);
    if(db->cache==NULL) {
        (void)db->io.close(db->io.context,db->handle);
        free(db);
        *result=ROUTER_CVE_DB_CAPACITY;
        return NULL;
    }
    {
        uint32_t cursor=0U;
        while(cursor<db->file_size) {
            size_t chunk=db->file_size-cursor>512U?512U:(size_t)(db->file_size-cursor);
            if(!db->io.read_at(db->io.context,db->handle,cursor,
                               db->cache+cursor,chunk)) {
                release_cache(db);
                (void)db->io.close(db->io.context,db->handle);
                free(db);
                return NULL;
            }
            cursor+=(uint32_t)chunk;
            ++db->snapshot_read_ops;
        }
    }
    checked=validate_image(db);
    if(checked!=ROUTER_CVE_DB_OK) {
        if(db->strings!=NULL)
            db->allocator.release(db->allocator.context,db->strings,
                                  db->string_count*sizeof(*db->strings));
        release_cache(db);
        (void)db->io.close(db->io.context,db->handle);
        memset(db,0,sizeof(*db)); free(db); *result=checked; return NULL;
    }
    if(!db->io.close(db->io.context,db->handle)) {
        if(db->strings!=NULL)
            db->allocator.release(db->allocator.context,db->strings,
                                  db->string_count*sizeof(*db->strings));
        release_cache(db);
        memset(db,0,sizeof(*db));
        free(db);
        *result=ROUTER_CVE_DB_IO;
        return NULL;
    }
    db->handle=NULL;
    *result=ROUTER_CVE_DB_OK;
    return db;
}

router_cve_db_t *router_cve_db_open(const char *path,
                                    const router_cve_db_alloc_t *allocator,
                                    router_cve_db_result_t *result)
{
    const router_cve_db_io_t io={
        .open=stdio_open,.size=stdio_size,.read_at=stdio_read,.close=stdio_close,
        .context=NULL};
    return router_cve_db_open_with_io(path,allocator,&io,result);
}

router_cve_db_t *router_cve_db_open_owned_snapshot_with_release(
    uint8_t *snapshot,uint32_t size,router_cve_db_release_fn release,
    void *release_context,router_cve_db_result_t *result)
{
    router_cve_db_t *db;
    router_cve_db_result_t checked;
    router_cve_db_release_fn snapshot_release=release!=NULL?release:default_release;
    if(result==NULL) { snapshot_release(release_context,snapshot,size); return NULL; }
    *result=ROUTER_CVE_DB_IO;
    if(snapshot==NULL||size<JCVE_HEADER_SIZE||size>ROUTER_CVE_DB_MAX_BYTES) {
        snapshot_release(release_context,snapshot,size);
        *result=ROUTER_CVE_DB_FORMAT;
        return NULL;
    }
    db=calloc(1U,sizeof(*db));
    if(db==NULL) {
        snapshot_release(release_context,snapshot,size);
        *result=ROUTER_CVE_DB_CAPACITY;
        return NULL;
    }
    db->allocator.allocate=default_allocate;
    db->allocator.release=default_release;
    db->allocator.context=NULL;
    db->cache=snapshot;
    db->cache_release=snapshot_release;
    db->cache_release_context=release_context;
    db->file_size=size;
    checked=validate_image(db);
    if(checked!=ROUTER_CVE_DB_OK) {
        if(db->strings!=NULL)
            db->allocator.release(db->allocator.context,db->strings,
                                  db->string_count*sizeof(*db->strings));
        release_cache(db);
        memset(db,0,sizeof(*db));
        free(db);
        *result=checked;
        return NULL;
    }
    *result=ROUTER_CVE_DB_OK;
    return db;
}


router_cve_db_t *router_cve_db_open_owned_snapshot(
    uint8_t *snapshot,uint32_t size,router_cve_db_result_t *result)
{
    return router_cve_db_open_owned_snapshot_with_release(
        snapshot,size,NULL,NULL,result);
}

router_cve_db_result_t router_cve_db_metadata(
    const router_cve_db_t *db,router_cve_db_metadata_t *metadata)
{
    router_cve_db_metadata_t value;
    if(db==NULL||metadata==NULL) return ROUTER_CVE_DB_FORMAT;
    memset(&value,0,sizeof(value));
    value.file_size=db->file_size; value.created_epoch=db->created_epoch;
    value.expires_epoch=db->expires_epoch; value.serial=db->serial;
    memcpy(value.key_id,db->key_id,sizeof(value.key_id));
    memcpy(value.payload_sha256,db->payload_sha256,sizeof(value.payload_sha256));
    memcpy(value.provenance_sha256,db->provenance_sha256,sizeof(value.provenance_sha256));
    value.source_count=db->sections[0].count; value.model_count=db->sections[1].count;
    value.alias_count=db->sections[2].count; value.advisory_count=db->sections[3].count;
    value.firmware_rule_count=db->sections[4].count;
    value.string_count=db->string_count;
    value.validation_work=db->validation_work;
    value.snapshot_read_ops=db->snapshot_read_ops;
    value.string_hash_bytes=db->string_hash_bytes;
    value.string_sort_comparisons=db->string_sort_comparisons;
    value.string_compare_bytes=db->string_compare_bytes;
    *metadata=value;
    return ROUTER_CVE_DB_OK;
}

static bool terminated_field(const char *value,size_t capacity)
{
    return memchr(value,'\0',capacity)!=NULL;
}

static bool find_model(router_cve_db_t *db,const router_fingerprint_t *fingerprint,
                       uint32_t *model_index)
{
    uint32_t i,index;
    char vendor[JCVE_STRING_MAX+1U],model[JCVE_STRING_MAX+1U],alias[JCVE_STRING_MAX+1U];
    for(i=0U;i<db->sections[JCVE_MODEL_SECTION].count;++i) {
        if(!get_text(db,JCVE_MODEL_SECTION,i,0U,vendor)||
           !get_text(db,JCVE_MODEL_SECTION,i,1U,model)) return false;
        if(strcmp(vendor,fingerprint->vendor)==0&&strcmp(model,fingerprint->model)==0) {
            *model_index=i; return true;
        }
    }
    for(i=0U;i<db->sections[JCVE_ALIAS_SECTION].count;++i) {
        if(!get_text(db,JCVE_ALIAS_SECTION,i,0U,alias)||
           !record_u32(db,JCVE_ALIAS_SECTION,i,1U,&index)||
           !get_text(db,JCVE_MODEL_SECTION,index,0U,vendor)) return false;
        if(strcmp(alias,fingerprint->model)==0&&strcmp(vendor,fingerprint->vendor)==0) {
            *model_index=index; return true;
        }
    }
    *model_index=UINT32_MAX;
    return true;
}

static router_cve_db_result_t rule_matches_firmware(
    router_cve_db_t *db,uint32_t rule,const char *firmware,bool *matches)
{
    char value[JCVE_STRING_MAX+1U];
    if(!get_text(db,JCVE_FIRMWARE_SECTION,rule,2U,value))
        return ROUTER_CVE_DB_FORMAT;
    *matches=strcmp(value,firmware)==0;
    return ROUTER_CVE_DB_OK;
}

static bool fill_result(router_cve_db_t *db,uint32_t advisory,
                        router_cve_match_t match,router_cve_result_t *output)
{
    uint32_t source,kev;
    char text[JCVE_STRING_MAX+1U];
    uint8_t flags;
    router_cve_result_t value;
    memset(&value,0,sizeof(value));
    value.match=match;
    if(!record_u32(db,JCVE_ADVISORY_SECTION,advisory,0U,&source)||
       !record_u32(db,JCVE_ADVISORY_SECTION,advisory,5U,&kev)||
       !get_text(db,JCVE_ADVISORY_SECTION,advisory,1U,text)) return false;
    memcpy(value.cve,text,strlen(text)+1U);
    if(!get_text(db,JCVE_ADVISORY_SECTION,advisory,2U,text)) return false;
    memcpy(value.advisory_url,text,strlen(text)+1U);
    if(!get_text(db,JCVE_ADVISORY_SECTION,advisory,4U,text)) return false;
    memcpy(value.severity,text,strlen(text)+1U);
    if(!get_text(db,JCVE_ADVISORY_SECTION,advisory,6U,text)) return false;
    memcpy(value.fixed_version,text,strlen(text)+1U);
    if(!get_text(db,JCVE_SOURCE_SECTION,source,0U,text)) return false;
    memcpy(value.source_id,text,strlen(text)+1U);
    if(kev!=JCVE_NO_STRING) {
        if(!string_at(db,kev,text,NULL)) return false;
        memcpy(value.kev_date,text,strlen(text)+1U);
        value.kev=true;
    }
    if(!db_read(db,db->sections[JCVE_ADVISORY_SECTION].offset+
                advisory*JCVE_ADVISORY_SIZE+28U,&flags,1U)) return false;
    value.eol=(flags&1U)!=0U;
    *output=value;
    return true;
}

router_cve_db_result_t router_cve_db_lookup(
    router_cve_db_t *db,const router_fingerprint_t *fingerprint,
    router_cve_result_t *results,size_t capacity,size_t *required)
{
    uint32_t model,first,count,i,advisory,previous=UINT32_MAX;
    size_t needed=0U,written=0U;
    bool exact=false,matched=false;
    router_cve_match_t match;
    router_cve_result_t *materialized=NULL;
    router_cve_db_result_t read_result;
    if(db==NULL||fingerprint==NULL||required==NULL||
       (capacity>0U&&results==NULL)||
       !terminated_field(fingerprint->vendor,sizeof(fingerprint->vendor))||
       !terminated_field(fingerprint->model,sizeof(fingerprint->model))||
       !terminated_field(fingerprint->firmware,sizeof(fingerprint->firmware)))
        return ROUTER_CVE_DB_FORMAT;
    if(fingerprint->confidence!=ROUTER_CONFIDENCE_CONFIRMED||
       fingerprint->conflict||fingerprint->truncated||fingerprint->vendor[0]=='\0'||
       fingerprint->model[0]=='\0'||!canonical_identity(fingerprint->vendor)||
       !canonical_identity(fingerprint->model)||
       (fingerprint->firmware[0]!='\0'&&!canonical_identity(fingerprint->firmware))) {
        *required=0U; return ROUTER_CVE_DB_OK;
    }
    if(!find_model(db,fingerprint,&model)) return ROUTER_CVE_DB_FORMAT;
    if(model==UINT32_MAX) { *required=0U; return ROUTER_CVE_DB_OK; }
    if(!record_u32(db,JCVE_MODEL_SECTION,model,2U,&first)||
       !record_u32(db,JCVE_MODEL_SECTION,model,3U,&count)) return ROUTER_CVE_DB_FORMAT;
    if(fingerprint->firmware[0]!='\0') {
        for(i=0U;i<count;++i) {
            read_result=rule_matches_firmware(db,first+i,fingerprint->firmware,&matched);
            if(read_result!=ROUTER_CVE_DB_OK) return read_result;
            if(matched) exact=true;
        }
    }
    match=exact?ROUTER_CVE_EXACT_FIRMWARE:ROUTER_CVE_MODEL_CANDIDATE;
    for(i=0U;i<count;++i) {
        if(exact) {
            read_result=rule_matches_firmware(db,first+i,fingerprint->firmware,&matched);
            if(read_result!=ROUTER_CVE_DB_OK) return read_result;
            if(!matched) continue;
        }
        if(!record_u32(db,JCVE_FIRMWARE_SECTION,first+i,1U,&advisory))
            return ROUTER_CVE_DB_FORMAT;
        if(advisory!=previous) { ++needed; previous=advisory; }
    }
    if(capacity<needed) { *required=needed; return ROUTER_CVE_DB_CAPACITY; }
    if(needed==0U) { *required=0U; return ROUTER_CVE_DB_OK; }
    if(needed>SIZE_MAX/sizeof(*materialized)) return ROUTER_CVE_DB_CAPACITY;
    materialized=db->allocator.allocate(db->allocator.context,
                                        needed*sizeof(*materialized));
    if(materialized==NULL) { *required=needed; return ROUTER_CVE_DB_CAPACITY; }
    previous=UINT32_MAX;
    for(i=0U;i<count;++i) {
        if(exact) {
            read_result=rule_matches_firmware(db,first+i,fingerprint->firmware,&matched);
            if(read_result!=ROUTER_CVE_DB_OK) goto materialize_failed;
            if(!matched) continue;
        }
        if(!record_u32(db,JCVE_FIRMWARE_SECTION,first+i,1U,&advisory)) {
            read_result=ROUTER_CVE_DB_FORMAT;
            goto materialize_failed;
        }
        if(advisory==previous) continue;
        previous=advisory;
        if(!fill_result(db,advisory,match,&materialized[written])) {
            read_result=ROUTER_CVE_DB_FORMAT;
            goto materialize_failed;
        }
        ++written;
    }
    memcpy(results,materialized,needed*sizeof(*materialized));
    db->allocator.release(db->allocator.context,materialized,
                          needed*sizeof(*materialized));
    *required=needed;
    return ROUTER_CVE_DB_OK;

materialize_failed:
    memset(materialized,0,needed*sizeof(*materialized));
    db->allocator.release(db->allocator.context,materialized,
                          needed*sizeof(*materialized));
    return read_result;
}

void router_cve_db_close(router_cve_db_t *db)
{
    if(db==NULL) return;
    if(db->strings!=NULL&&db->allocator.release!=NULL)
        db->allocator.release(db->allocator.context,db->strings,
                              db->string_count*sizeof(*db->strings));
    release_cache(db);
    if(db->handle!=NULL&&db->io.close!=NULL)
        (void)db->io.close(db->io.context,db->handle);
    memset(db,0,sizeof(*db));
    free(db);
}




