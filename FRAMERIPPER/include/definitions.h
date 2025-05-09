#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define AP_SSID "3Kali-Deauther"
#define AP_PASS "esp32wroom32"

#define LED 2
#define SERIAL_DEBUG
#define CHANNEL_MAX 13
#define NUM_FRAMES_PER_DEAUTH 16
#define DEAUTH_BLINK_TIMES 2
#define DEAUTH_BLINK_DURATION 20

#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL 1
#define DEAUTH_TYPE_ALL_EXCEPT 2
#define DEAUTH_TYPE_TARGETED 3

#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif
#ifndef SERIAL_DEBUG
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif
#ifdef LED
#define BLINK_LED(num_times, blink_duration) blink_led(num_times, blink_duration)
#endif
#ifndef LED
#define BLINK_LED()
#endif

// Whitelist for the all_except 
#ifndef WHITELIST_H
#define WHITELIST_H

#define MAX_WHITELISTED 20 // max no being 20

extern uint8_t whitelist[MAX_WHITELISTED][6]; 
extern int whitelist_count;

bool add_to_whitelist(const char *mac_str); 
bool is_whitelisted(const uint8_t *mac);

#endif


void blink_led(int num_times, int blink_duration);

#endif