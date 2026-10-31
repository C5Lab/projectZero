#ifndef LAB_C5_SECURE_CLEAR_H
#define LAB_C5_SECURE_CLEAR_H

#include <stddef.h>

/* Volatile stores keep credential cleanup from being optimized away. */
static inline void c5_secure_clear(void* memory, size_t length) {
    volatile unsigned char* bytes = memory;
    while(length--) *bytes++ = 0;
}

#endif
