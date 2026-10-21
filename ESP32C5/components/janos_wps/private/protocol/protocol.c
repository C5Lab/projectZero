#include "protocol.h"
#include <string.h>
static unsigned be16(const uint8_t *p) { return ((unsigned)p[0]<<8)|p[1]; }
enum probe_message probe_parse(const uint8_t *data, size_t length, uint8_t *id) {
    if (!data || !id || length<8 || data[0]<1 || data[0]>3 || data[1]!=0) return PROBE_INVALID;
    size_t size=be16(data+2);
    if(size<4 || size>length-4 || be16(data+6)!=size) return PROBE_INVALID;
    *id=data[5];
    if(data[4]==4) return size==4 ? PROBE_FAILURE : PROBE_INVALID;
    if(data[4]!=1 || size<5) return PROBE_OTHER;
    if(data[8]==1) return PROBE_IDENTITY;
    if(data[8]!=254) return PROBE_OTHER;
    if(size<14 || data[9]!=0 || data[10]!=0x37 || data[11]!=0x2a ||
       data[12]!=0 || data[13]!=0 || data[14]!=0 || data[15]!=1) return PROBE_INVALID;
    if(data[17]&~3u) return PROBE_INVALID;
    if(data[17]&3u) return PROBE_FRAGMENT;
    if(data[16]!=4) return PROBE_OTHER;
    unsigned seen=0, message=0;
    for(size_t pos=18;pos<size+4;) {
        if(size+4-pos<4) return PROBE_INVALID;
        unsigned type=be16(data+pos), n=be16(data+pos+2), bit=0, want=0;
        pos+=4;
        if(n>size+4-pos) return PROBE_INVALID;
        if(type==0x1022) {bit=1;want=1;}
        if(type==0x101a) {bit=2;want=16;}
        if(type==0x1020) {bit=4;want=6;}
        if(type==0x1032) {bit=8;want=192;}
        if(bit) {
            if((seen&bit) || n!=want) return PROBE_INVALID;
            seen|=bit;
            if(bit==1) message=data[pos];
        }
        pos+=n;
    }
    return seen==15 && message==4 ? PROBE_M1 : PROBE_OTHER;
}
size_t probe_identity(uint8_t id, uint8_t *out, size_t capacity) {
    static const char name[]="WFA-SimpleConfig-Registrar-1-0";
    size_t n=9+sizeof(name)-1;
    if(!out || capacity<n) return 0;
    memset(out,0,n);out[0]=1;out[3]=n-4;out[4]=2;out[5]=id;out[7]=n-4;out[8]=1;
    memcpy(out+9,name,sizeof(name)-1);return n;
}
