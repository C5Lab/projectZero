/**
 * @file pcap_serializer.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implementation of PCAP serializer
 */
#include "pcap_serializer.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

static const char *TAG = "pcap_serializer";


/**
 * @brief Constanst according to reference
 * 
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
//@{
#define SNAPLEN 65535
#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
//@}

/**
 * @brief Constanst according to reference
 * 
 * @see Ref: http://www.tcpdump.org/linktypes.html (LINKTYPE_IEEE802_11)
 */
#define LINKTYPE_IEEE802_11 105

static size_t pcap_size = 0;
static size_t pcap_capacity = 0;
static size_t pcap_limit = 0;
static bool pcap_use_psram = false;
static uint8_t *pcap_buffer = NULL;

static void pcap_free_buffer(uint8_t *buffer, bool use_psram)
{
#ifndef ESP_PLATFORM
    (void)use_psram;
#endif
#ifdef ESP_PLATFORM
    if (use_psram) {
        heap_caps_free(buffer);
        return;
    }
#endif
    free(buffer);
}

static void *pcap_allocate(size_t size, bool use_psram)
{
#ifndef ESP_PLATFORM
    (void)use_psram;
#endif
#ifdef ESP_PLATFORM
    if (use_psram) {
        return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
#endif
    return malloc(size);
}

static void *pcap_reallocate(void *buffer, size_t size)
{
#ifdef ESP_PLATFORM
    if (pcap_use_psram) {
        return heap_caps_realloc(buffer, size,
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
#endif
    return realloc(buffer, size);
}

static uint8_t *pcap_serializer_init_internal(size_t initial_capacity,
                                              size_t max_size,
                                              bool use_psram)
{
    const size_t header_size = sizeof(pcap_global_header_t);

    if ((max_size != 0 && max_size < header_size) ||
        initial_capacity > UINT_MAX || max_size > UINT_MAX) {
        return NULL;
    }
    if (initial_capacity < header_size) initial_capacity = header_size;
    if (max_size != 0 && initial_capacity > max_size) {
        initial_capacity = max_size;
    }

    // Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
    pcap_global_header_t pcap_global_header = {
        .magic_number = PCAP_MAGIC_NUMBER,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = SNAPLEN,
        .network = LINKTYPE_IEEE802_11
    };

    uint8_t *new_buffer =
        (uint8_t *)pcap_allocate(initial_capacity, use_psram);
    if (new_buffer == NULL) return NULL;
    memcpy(new_buffer, &pcap_global_header, sizeof(pcap_global_header_t));

    uint8_t *old_buffer = pcap_buffer;
    const bool old_use_psram = pcap_use_psram;
    pcap_buffer = new_buffer;
    pcap_size = header_size;
    pcap_capacity = initial_capacity;
    pcap_limit = max_size;
    pcap_use_psram = use_psram;
    pcap_free_buffer(old_buffer, old_use_psram);
    return pcap_buffer;
}

uint8_t *pcap_serializer_init()
{
    return pcap_serializer_init_internal(sizeof(pcap_global_header_t), 0, false);
}

uint8_t *pcap_serializer_init_bounded(size_t initial_capacity,
                                      size_t max_size,
                                      bool use_psram)
{
    return pcap_serializer_init_internal(initial_capacity, max_size, use_psram);
}

pcap_serializer_append_result_t pcap_serializer_append_frame_checked(
    const uint8_t *buffer, unsigned size, unsigned ts_usec)
{
    if (pcap_buffer == NULL) return PCAP_SERIALIZER_APPEND_NOT_INITIALIZED;
    if(size == 0){
        return PCAP_SERIALIZER_APPEND_OK;
    }
    if (buffer == NULL) return PCAP_SERIALIZER_APPEND_INVALID;

    // Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#record-packet-header
    pcap_record_header_t pcap_record_header = {
        .ts_sec = ts_usec / 1000000,
        .ts_usec = ts_usec % 1000000,
        .incl_len = size,
        .orig_len = size,
    };
    // Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#record-packet-header
    // Stored packet/frame cannot be larger than SNAPLEN
    if(size > SNAPLEN){
        size = SNAPLEN;
        pcap_record_header.incl_len = SNAPLEN;
    }

#if SIZE_MAX == UINT_MAX
    if (size > SIZE_MAX - sizeof(pcap_record_header_t)) {
        return PCAP_SERIALIZER_APPEND_LIMIT;
    }
#endif
    const size_t record_size = sizeof(pcap_record_header_t) + (size_t)size;
    if (record_size > SIZE_MAX - pcap_size) {
        return PCAP_SERIALIZER_APPEND_LIMIT;
    }
    const size_t required = pcap_size + record_size;
    if (required > UINT_MAX) return PCAP_SERIALIZER_APPEND_LIMIT;
    if (pcap_limit != 0 && required > pcap_limit) {
        return PCAP_SERIALIZER_APPEND_LIMIT;
    }

    if (required > pcap_capacity) {
        size_t new_capacity = pcap_capacity;
        while (new_capacity < required) {
            if (new_capacity > SIZE_MAX / 2U) {
                new_capacity = required;
                break;
            }
            new_capacity *= 2U;
        }
        if (pcap_limit != 0 && new_capacity > pcap_limit) {
            new_capacity = pcap_limit;
        }
        if (new_capacity < required) {
            return PCAP_SERIALIZER_APPEND_LIMIT;
        }

        uint8_t *reallocated_pcap_buffer =
            (uint8_t *)pcap_reallocate(pcap_buffer, new_capacity);
        if (reallocated_pcap_buffer == NULL) {
            return PCAP_SERIALIZER_APPEND_ALLOC_FAILED;
        }
        pcap_buffer = reallocated_pcap_buffer;
        pcap_capacity = new_capacity;
    }

    memcpy(&pcap_buffer[pcap_size], &pcap_record_header,
           sizeof(pcap_record_header_t));
    memcpy(&pcap_buffer[pcap_size + sizeof(pcap_record_header_t)], buffer, size);
    pcap_size = required;
    return PCAP_SERIALIZER_APPEND_OK;
}

void pcap_serializer_append_frame(const uint8_t *buffer, unsigned size,
                                  unsigned ts_usec)
{
    pcap_serializer_append_result_t result =
        pcap_serializer_append_frame_checked(buffer, size, ts_usec);
    if (result == PCAP_SERIALIZER_APPEND_ALLOC_FAILED ||
        result == PCAP_SERIALIZER_APPEND_LIMIT) {
        ESP_LOGE(TAG, "Error reallocating PCAP buffer! PCAP buffer may not be complete.");
    } else if (result == PCAP_SERIALIZER_APPEND_NOT_INITIALIZED ||
               result == PCAP_SERIALIZER_APPEND_INVALID) {
        ESP_LOGE(TAG, "PCAP serializer is not initialized or frame is invalid.");
    }
}

void pcap_serializer_deinit(){
    pcap_free_buffer(pcap_buffer, pcap_use_psram);
    pcap_buffer = NULL;
    pcap_size = 0;
    pcap_capacity = 0;
    pcap_limit = 0;
    pcap_use_psram = false;
}

unsigned pcap_serializer_get_size(){
    return (unsigned)pcap_size;
}

uint8_t *pcap_serializer_get_buffer(){
    return pcap_buffer;
}

size_t pcap_serializer_get_capacity(void)
{
    return pcap_capacity;
}

size_t pcap_serializer_get_limit(void)
{
    return pcap_limit;
}
