// Copyright 2018 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __ESP_EVENT_H__
#define __ESP_EVENT_H__

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "esp_wifi_types.h"
#ifndef RIOT_VERSION
#include "lwip/ip_addr.h"
#include "tcpip_adapter.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_EVENT_IPV6 LWIP_IPV6

typedef enum {
    SYSTEM_EVENT_WIFI_READY = 0,           /**< ESP8266 WiFi ready */
    SYSTEM_EVENT_SCAN_DONE,                /**< ESP8266 finish scanning AP */
    SYSTEM_EVENT_STA_START,                /**< ESP8266 station start */
    SYSTEM_EVENT_STA_STOP,                 /**< ESP8266 station stop */
    SYSTEM_EVENT_STA_CONNECTED,            /**< ESP8266 station connected to AP */
    SYSTEM_EVENT_STA_DISCONNECTED,         /**< ESP8266 station disconnected from AP */
    SYSTEM_EVENT_STA_AUTHMODE_CHANGE,      /**< the auth mode of AP connected by ESP8266 station changed */
    SYSTEM_EVENT_STA_GOT_IP,               /**< ESP8266 station got IP from connected AP */
    SYSTEM_EVENT_STA_LOST_IP,              /**< ESP8266 station lost IP and the IP is reset to 0 */
    SYSTEM_EVENT_STA_WPS_ER_SUCCESS,       /**< ESP8266 station wps succeeds in enrollee mode */
    SYSTEM_EVENT_STA_WPS_ER_FAILED,        /**< ESP8266 station wps fails in enrollee mode */
    SYSTEM_EVENT_STA_WPS_ER_TIMEOUT,       /**< ESP8266 station wps timeout in enrollee mode */
    SYSTEM_EVENT_STA_WPS_ER_PIN,           /**< ESP8266 station wps pin code in enrollee mode */
    SYSTEM_EVENT_AP_START,                 /**< ESP8266 soft-AP start */
    SYSTEM_EVENT_AP_STOP,                  /**< ESP8266 soft-AP stop */
    SYSTEM_EVENT_AP_STACONNECTED,          /**< a station connected to ESP8266 soft-AP */
    SYSTEM_EVENT_AP_STADISCONNECTED,       /**< a station disconnected from ESP8266 soft-AP */
    SYSTEM_EVENT_AP_STAIPASSIGNED,         /**< ESP8266 soft-AP assign an IP to a connected station */
    SYSTEM_EVENT_AP_PROBEREQRECVED,        /**< Receive probe request packet in soft-AP interface */
    SYSTEM_EVENT_GOT_IP6,                  /**< ESP8266 station or ap or ethernet interface v6IP addr is preferred */
    SYSTEM_EVENT_ETH_START,                /**< ESP8266 ethernet start */
    SYSTEM_EVENT_ETH_STOP,                 /**< ESP8266 ethernet stop */
    SYSTEM_EVENT_ETH_CONNECTED,            /**< ESP8266 ethernet phy link up */
    SYSTEM_EVENT_ETH_DISCONNECTED,         /**< ESP8266 ethernet phy link down */
    SYSTEM_EVENT_ETH_GOT_IP,               /**< ESP8266 ethernet got IP from connected AP */
    SYSTEM_EVENT_MAX
} system_event_id_t;

/* add this macro define for compatible with old IDF version */
#ifndef SYSTEM_EVENT_AP_STA_GOT_IP6
#define SYSTEM_EVENT_AP_STA_GOT_IP6 SYSTEM_EVENT_GOT_IP6
#endif

typedef enum {
    WPS_FAIL_REASON_NORMAL = 0,                   /**< ESP8266 WPS normal fail reason */
    WPS_FAIL_REASON_RECV_M2D,                       /**< ESP8266 WPS receive M2D frame */
    WPS_FAIL_REASON_MAX
}system_event_sta_wps_fail_reason_t;

typedef struct {
    uint32_t status;          /**< status of scanning APs */
    uint8_t  number;
    uint8_t  scan_id;
} system_event_sta_scan_done_t;

typedef struct {
    uint8_t ssid[32];         /**< SSID of connected AP */
    uint8_t ssid_len;         /**< SSID length of connected AP */
    uint8_t bssid[6];         /**< BSSID of connected AP*/
    uint8_t channel;          /**< channel of connected AP*/
    wifi_auth_mode_t authmode;
} system_event_sta_connected_t;

typedef struct {
    uint8_t ssid[32];         /**< SSID of disconnected AP */
    uint8_t ssid_len;         /**< SSID length of disconnected AP */
    uint8_t bssid[6];         /**< BSSID of disconnected AP */
    uint8_t reason;           /**< reason of disconnection */
} system_event_sta_disconnected_t;

typedef struct {
    wifi_auth_mode_t old_mode;         /**< the old auth mode of AP */
    wifi_auth_mode_t new_mode;         /**< the new auth mode of AP */
} system_event_sta_authmode_change_t;

#ifndef RIOT_VERSION
typedef struct {
    tcpip_adapter_ip_info_t ip_info;
    bool ip_changed;
} system_event_sta_got_ip_t;
#endif

typedef struct {
    uint8_t pin_code[8];         /**< PIN code of station in enrollee mode */
} system_event_sta_wps_er_pin_t;

#ifndef RIOT_VERSION
typedef struct {
    tcpip_adapter_if_t if_index;
    tcpip_adapter_ip6_info_t ip6_info;
} system_event_got_ip6_t;
#endif

typedef struct {
    uint8_t mac[6];           /**< MAC address of the station connected to ESP8266 soft-AP */
    uint8_t aid;              /**< the aid that ESP8266 soft-AP gives to the station connected to  */
} system_event_ap_staconnected_t;

typedef struct {
    uint8_t mac[6];           /**< MAC address of the station disconnects to ESP8266 soft-AP */
    uint8_t aid;              /**< the aid that ESP8266 soft-AP gave to the station disconnects to  */
} system_event_ap_stadisconnected_t;

typedef struct {
    int rssi;                 /**< Received probe request signal strength */
    uint8_t mac[6];           /**< MAC address of the station which send probe request */
} system_event_ap_probe_req_rx_t;

typedef union {
    system_event_sta_connected_t               connected;          /**< ESP8266 station connected to AP */
    system_event_sta_disconnected_t            disconnected;       /**< ESP8266 station disconnected to AP */
    system_event_sta_scan_done_t               scan_done;          /**< ESP8266 station scan (APs) done */
    system_event_sta_authmode_change_t         auth_change;        /**< the auth mode of AP ESP8266 station connected to changed */
#ifndef RIOT_VERSION
    system_event_sta_got_ip_t                  got_ip;             /**< ESP8266 station got IP, first time got IP or when IP is changed */
#endif
    system_event_sta_wps_er_pin_t              sta_er_pin;         /**< ESP8266 station WPS enrollee mode PIN code received */
    system_event_sta_wps_fail_reason_t         sta_er_fail_reason;/**< ESP8266 station WPS enrollee mode failed reason code received */
    system_event_ap_staconnected_t             sta_connected;      /**< a station connected to ESP8266 soft-AP */
    system_event_ap_stadisconnected_t          sta_disconnected;   /**< a station disconnected to ESP8266 soft-AP */
    system_event_ap_probe_req_rx_t             ap_probereqrecved;  /**< ESP8266 soft-AP receive probe request packet */
#ifndef RIOT_VERSION
    system_event_got_ip6_t                     got_ip6;            /**< ESP8266 station???or ap or ethernet ipv6 addr state change to preferred */
#endif
} system_event_info_t;

typedef struct {
    system_event_id_t     event_id;      /**< event ID */
    system_event_info_t   event_info;    /**< event information */
} system_event_t;

typedef esp_err_t (*system_event_handler_t)(system_event_t *event);

/**
  * @brief  Send a event to event task
  *
  * @attention 1. Other task/modules, such as the TCPIP module, can call this API to send an event to event task
  *
  * @param  system_event_t * event : event
  *
  * @return ESP_OK : succeed
  * @return others : fail
  */
esp_err_t esp_event_send(system_event_t *event);

/**
  * @brief  Default event handler for system events
  *
  * This function performs default handling of system events.
  * When using esp_event_loop APIs, it is called automatically before invoking the user-provided
  * callback function.
  *
  * Applications which implement a custom event loop must call this function
  * as part of event processing.
  *
  * @param  event pointer to event to be handled
  * @return ESP_OK if an event was handled successfully
  */
esp_err_t esp_event_process_default(system_event_t *event);

/**
  * @brief  Install default event handlers for Wi-Fi interfaces (station and AP)
  *
  */
void esp_event_set_default_wifi_handlers(void);

#ifdef __cplusplus
}
#endif

#endif /* __ESP_EVENT_H__ */
