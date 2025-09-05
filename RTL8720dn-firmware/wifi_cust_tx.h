#ifndef WIFI_CUST_TX
#define WIFI_CUST_TX

#include <Arduino.h>
#include "wifi_frame_parser.h"

typedef struct {
  uint16_t frame_control = 0xC0;
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x06;
} DeauthFrame;

typedef struct {
  uint16_t frame_control = 0x80;
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  const uint64_t timestamp = 0;
  uint16_t beacon_interval = 0x64;
  uint16_t ap_capabilities = 0x21;
  const uint8_t ssid_tag = 0;
  uint8_t ssid_length = 0;
  uint8_t ssid[255];
} BeaconFrame;

/*
 * Import the needed c functions from the closed-source libraries
 * The function definitions might not be 100% accurate with the arguments as the types get lost during compilation and cannot be retrieved back during decompilation
 * However, these argument types seem to work perfect
*/
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);

// WiFi帧接收相关函数
void wifi_rx_init();
void wifi_rx_start_monitor();
void wifi_rx_stop_monitor();
bool wifi_rx_is_monitoring();
void wifi_rx_process_packet(const uint8_t* packet, size_t length);

// 回调函数类型定义
typedef void (*wifi_rx_callback_t)(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac);

// 设置接收回调函数
void wifi_rx_set_callback(wifi_rx_callback_t callback);

// WEP数据包处理回调函数类型
typedef void (*wep_packet_callback_t)(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac);

// 设置WEP数据包处理回调函数
void wifi_rx_set_wep_callback(wep_packet_callback_t callback);

// EAP数据包处理回调函数类型
typedef void (*eap_packet_callback_t)(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac);

// 设置EAP数据包处理回调函数
void wifi_rx_set_eap_callback(eap_packet_callback_t callback);

#endif
