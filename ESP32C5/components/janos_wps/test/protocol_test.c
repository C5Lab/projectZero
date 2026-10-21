#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "protocol.h"
static void be16(unsigned char *p, unsigned n) {p[0]=n>>8;p[1]=n;}
static size_t attr(unsigned char *p, unsigned type, unsigned n, unsigned value) {
    be16(p,type);be16(p+2,n);memset(p+4,value,n);return n+4;
}
int main(void) {
    unsigned char identity[]={1,0,0,5,1,17,0,5,1}, out[64], id=0;
    assert(probe_parse(identity,sizeof(identity),&id)==PROBE_IDENTITY && id==17);
    size_t n=probe_identity(id,out,sizeof(out));
    const char *name="WFA-SimpleConfig-Registrar-1-0";
    assert(n==9+strlen(name) && out[4]==2 && out[5]==17 && out[8]==1);
    assert(memcmp(out+9,name,strlen(name))==0);
    assert(probe_identity(id,out,4)==0);
    unsigned char m[300]={1,0,0,0,1,23,0,0,254,0,0x37,0x2a,0,0,0,1,4,0};
    n=18;
    n+=attr(m+n,0x1022,1,4); n+=attr(m+n,0x101a,16,7);
    n+=attr(m+n,0x1020,6,2); n+=attr(m+n,0x1032,192,3);
    be16(m+2,n-4);be16(m+6,n-4);
    assert(probe_parse(m,n,&id)==PROBE_M1 && id==23);
    for(size_t i=0;i<n;i++) assert(probe_parse(m,i,&id)!=PROBE_M1);
    m[17]=1; assert(probe_parse(m,n,&id)==PROBE_FRAGMENT);m[17]=0;
    m[22]=5; assert(probe_parse(m,n,&id)!=PROBE_M1);m[22]=4;
    m[12]=1; assert(probe_parse(m,n,&id)!=PROBE_M1);m[12]=0;
    n+=attr(m+n,0x1022,1,4);be16(m+2,n-4);be16(m+6,n-4);
    assert(probe_parse(m,n,&id)==PROBE_INVALID);
    puts("PASS: identity, M1, truncation, vendor, fragmentation, duplicate attributes");
}
