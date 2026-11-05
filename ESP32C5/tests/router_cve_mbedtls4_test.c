#include "router_cve_verify.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"

typedef struct {
    uint8_t *bytes;
    size_t size;
} blob_t;

static bool load_blob(const char *path, blob_t *blob)
{
    FILE *file=fopen(path,"rb");
    long length;
    if(file==NULL || fseek(file,0,SEEK_END)!=0 ||
       (length=ftell(file))<=0 || fseek(file,0,SEEK_SET)!=0) {
        if(file!=NULL) fclose(file);
        return false;
    }
    blob->bytes=malloc((size_t)length);
    blob->size=(size_t)length;
    if(blob->bytes==NULL || fread(blob->bytes,1U,blob->size,file)!=blob->size) {
        free(blob->bytes);
        blob->bytes=NULL;
        blob->size=0U;
        fclose(file);
        return false;
    }
    return fclose(file)==0;
}

static void release_blob(blob_t *blob)
{
    free(blob->bytes);
    blob->bytes=NULL;
    blob->size=0U;
}

static bool verify(const blob_t *key, const uint8_t digest[32U],
                   const blob_t *signature)
{
    return router_cve_mbedtls_p256_verify(
        NULL,key->bytes,key->size,digest,signature->bytes,signature->size);
}

#define REQUIRE(condition) do {                                                \
    if(!(condition)) {                                                        \
        fprintf(stderr,"failed: %s (%s:%d)\n",#condition,__FILE__,__LINE__); \
        result=1;                                                             \
        goto done;                                                            \
    }                                                                         \
} while(0)

int main(int argc, char **argv)
{
    blob_t p256={0},digest={0},signature={0},tampered={0};
    blob_t rsa={0},secp256k1={0},p384={0};
    uint8_t changed_digest[32U];
    static const uint8_t malformed[]={0x30U};
    int result=0;

    if(argc!=8) return 2;
    REQUIRE(psa_crypto_init()==PSA_SUCCESS);
    REQUIRE(load_blob(argv[1],&p256));
    REQUIRE(load_blob(argv[2],&digest) && digest.size==sizeof(changed_digest));
    REQUIRE(load_blob(argv[3],&signature));
    REQUIRE(load_blob(argv[4],&tampered));
    REQUIRE(load_blob(argv[5],&rsa));
    REQUIRE(load_blob(argv[6],&secp256k1));
    REQUIRE(load_blob(argv[7],&p384));

    REQUIRE(verify(&p256,digest.bytes,&signature));
    REQUIRE(!verify(&p256,digest.bytes,&tampered));
    memcpy(changed_digest,digest.bytes,sizeof(changed_digest));
    changed_digest[0]^=0x80U;
    REQUIRE(!verify(&p256,changed_digest,&signature));
    REQUIRE(!verify(&rsa,digest.bytes,&signature));
    REQUIRE(!verify(&secp256k1,digest.bytes,&signature));
    REQUIRE(!verify(&p384,digest.bytes,&signature));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,malformed,sizeof(malformed),digest.bytes,
        signature.bytes,signature.size));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,p256.bytes,p256.size,digest.bytes,
        malformed,sizeof(malformed)));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,NULL,p256.size,digest.bytes,signature.bytes,signature.size));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,p256.bytes,p256.size,NULL,signature.bytes,signature.size));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,p256.bytes,p256.size,digest.bytes,NULL,signature.size));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,p256.bytes,0U,digest.bytes,signature.bytes,signature.size));
    REQUIRE(!router_cve_mbedtls_p256_verify(
        NULL,p256.bytes,p256.size,digest.bytes,signature.bytes,0U));

done:
    release_blob(&p256);
    release_blob(&digest);
    release_blob(&signature);
    release_blob(&tampered);
    release_blob(&rsa);
    release_blob(&secp256k1);
    release_blob(&p384);
    mbedtls_psa_crypto_free();
    return result;
}
