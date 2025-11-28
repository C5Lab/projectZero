/**
 * @file attack_handshake.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides interface to control attacks on WPA handshake
 */
#ifndef ATTACK_HANDSHAKE_H
#define ATTACK_HANDSHAKE_H

#include <stdbool.h>
#include "esp_wifi_types.h"

/**
 * @brief Available methods that can be chosen for the attack.
 * 
 */
typedef enum{
    ATTACK_HANDSHAKE_METHOD_BROADCAST,  ///< Method that sends deauth frames to capture handshake
    ATTACK_HANDSHAKE_METHOD_PASSIVE,    ///< Passive method that does not intervene communication on network, just passively capture handshake frames
} attack_handshake_methods_t;

/**
 * @brief Starts handshake attack for given AP.
 * 
 * To stop handshake attack, call attack_handshake_stop().
 * 
 * @param ap_record target AP record
 * @param method attack method chosen 
 */
void attack_handshake_start(const wifi_ap_record_t *ap_record, attack_handshake_methods_t method);

/**
 * @brief Stops handshake attack.
 * 
 * This function stops everything that attack_handshake_start() started and resets all values to default state.
 */
void attack_handshake_stop();

/**
 * @brief Returns captured handshake data in PCAP format
 * 
 * @param size pointer to store the size of captured data
 * @return uint8_t* pointer to PCAP buffer or NULL if no data
 */
uint8_t *attack_handshake_get_pcap(unsigned *size);

/**
 * @brief Returns captured handshake data in HCCAPX format
 * 
 * @return pointer to hccapx structure or NULL if no complete handshake
 */
void *attack_handshake_get_hccapx();

/**
 * @brief Saves complete handshake to SD card
 * 
 * Only saves if a complete 4-way handshake was captured.
 * Files are saved to /sdcard/lab/handshakes/ with SSID and timestamp in filename.
 * 
 * @return true if handshake was complete and saved successfully
 * @return false if no complete handshake or save failed
 */
bool attack_handshake_save_to_sd();

/**
 * @brief Checks if all 4 handshake messages have been captured
 * 
 * This is faster than checking HCCAPX as it directly checks capture flags.
 * 
 * @return true if M1, M2, M3, and M4 have all been captured
 * @return false otherwise
 */
bool attack_handshake_is_complete();

#endif

