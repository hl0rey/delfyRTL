#include "wifi_frame_parser.h"
#include "debug.h"

// 解析802.11帧
bool parse_wifi_frame(const uint8_t* packet, size_t length, WiFiFrameInfo* frame_info) {
    if (!packet || !frame_info || length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    memset(frame_info, 0, sizeof(WiFiFrameInfo));

    // 解析帧控制字段
    frame_info->frame_control = packet[0] | (packet[1] << 8);
    frame_info->frame_type = (frame_info->frame_control & WIFI_FC_TYPE_MASK) >> 2;
    frame_info->frame_subtype = (frame_info->frame_control & WIFI_FC_SUBTYPE_MASK) >> 4;
    frame_info->to_ds = (frame_info->frame_control & WIFI_FC_TO_DS_MASK) != 0;
    frame_info->from_ds = (frame_info->frame_control & WIFI_FC_FROM_DS_MASK) != 0;
    frame_info->is_wep_encrypted = (frame_info->frame_control & WIFI_FC_WEP_MASK) != 0;
    frame_info->is_qos = is_qos_data_frame(packet, length);

    // 解析地址字段
    memcpy(frame_info->addr1, packet + WIFI_ADDR1_OFFSET, 6);
    memcpy(frame_info->addr2, packet + WIFI_ADDR2_OFFSET, 6);
    memcpy(frame_info->addr3, packet + WIFI_ADDR3_OFFSET, 6);

    // 检查是否有第四地址（WDS模式）
    if (frame_info->to_ds && frame_info->from_ds) {
        if (length >= 30) {
            memcpy(frame_info->addr4, packet + WIFI_ADDR4_OFFSET, 6);
        }
    }

    // 计算载荷偏移
    size_t header_length = get_wifi_frame_header_length(packet, length);
    if (header_length == 0 || header_length >= length) {
        return false;
    }

    // 设置载荷数据
    frame_info->payload = (uint8_t*)(packet + header_length);
    frame_info->payload_length = length - header_length;

    // 检查WEP加密
    if (frame_info->is_wep_encrypted && frame_info->payload_length >= 8) {
        // WEP数据包：IV(3) + KeyID(1) + Data + ICV(4)
        frame_info->payload_length -= 8; // 减去WEP头部和尾部
        frame_info->payload += 4; // 跳过IV和KeyID
    }

    frame_info->is_valid = true;
    return true;
}

// 检查是否为数据帧
bool is_wifi_data_frame(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    uint8_t frame_type = (frame_control & WIFI_FC_TYPE_MASK) >> 2;
    
    return frame_type == WIFI_FRAME_TYPE_DATA;
}

// 检查是否为管理帧
bool is_wifi_management_frame(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    uint8_t frame_type = (frame_control & WIFI_FC_TYPE_MASK) >> 2;
    
    return frame_type == WIFI_FRAME_TYPE_MANAGEMENT;
}

// 检查是否为控制帧
bool is_wifi_control_frame(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    uint8_t frame_type = (frame_control & WIFI_FC_TYPE_MASK) >> 2;
    
    return frame_type == WIFI_FRAME_TYPE_CONTROL;
}

// 检查是否为WEP加密帧
bool is_wep_encrypted_frame(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    
    // 检查是否为数据帧
    uint8_t frame_type = (frame_control & WIFI_FC_TYPE_MASK) >> 2;
    if (frame_type != WIFI_FRAME_TYPE_DATA) {
        return false;
    }

    // 检查WEP加密标志
    return (frame_control & WIFI_FC_WEP_MASK) != 0;
}

// 检查是否为EAPOL帧
bool is_eapol_frame(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH + 8) {
        return false;
    }

    // 首先检查是否为数据帧
    if (!is_wifi_data_frame(packet, length)) {
        return false;
    }

    // 计算载荷偏移
    size_t header_length = get_wifi_frame_header_length(packet, length);
    if (header_length == 0 || header_length + 8 > length) {
        return false;
    }

    // 检查EAPOL EtherType (0x888E)
    const uint8_t* payload = packet + header_length;
    if (payload[0] == 0x88 && payload[1] == 0x8E) {
        return true;
    }

    return false;
}

// 检查是否为EAP帧
bool is_eap_frame(const uint8_t* packet, size_t length) {
    if (!is_eapol_frame(packet, length)) {
        return false;
    }

    // 计算EAPOL载荷偏移
    size_t header_length = get_wifi_frame_header_length(packet, length);
    if (header_length + 4 > length) {
        return false;
    }

    const uint8_t* eapol_payload = packet + header_length + 2; // 跳过EtherType
    if (eapol_payload[0] == 0x01 && eapol_payload[1] == 0x00) { // EAPOL版本1，类型0（EAP-Packet）
        return true;
    }

    return false;
}

// 提取MAC地址
void extract_mac_addresses(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac, uint8_t* bssid) {
    if (!packet || length < WIFI_FRAME_MIN_LENGTH || !src_mac || !dst_mac || !bssid) {
        return;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    bool to_ds = (frame_control & WIFI_FC_TO_DS_MASK) != 0;
    bool from_ds = (frame_control & WIFI_FC_FROM_DS_MASK) != 0;

    // 根据ToDS和FromDS标志确定地址含义
    if (!to_ds && !from_ds) {
        // IBSS模式
        memcpy(dst_mac, packet + WIFI_ADDR1_OFFSET, 6);  // 接收方
        memcpy(src_mac, packet + WIFI_ADDR2_OFFSET, 6);  // 发送方
        memcpy(bssid, packet + WIFI_ADDR3_OFFSET, 6);    // BSSID
    } else if (to_ds && !from_ds) {
        // 客户端到AP
        memcpy(dst_mac, packet + WIFI_ADDR1_OFFSET, 6);  // AP地址
        memcpy(src_mac, packet + WIFI_ADDR2_OFFSET, 6);  // 客户端地址
        memcpy(bssid, packet + WIFI_ADDR3_OFFSET, 6);    // BSSID
    } else if (!to_ds && from_ds) {
        // AP到客户端
        memcpy(dst_mac, packet + WIFI_ADDR1_OFFSET, 6);  // 客户端地址
        memcpy(src_mac, packet + WIFI_ADDR2_OFFSET, 6);  // AP地址
        memcpy(bssid, packet + WIFI_ADDR3_OFFSET, 6);    // BSSID
    } else if (to_ds && from_ds) {
        // WDS模式
        memcpy(dst_mac, packet + WIFI_ADDR1_OFFSET, 6);  // 接收方
        memcpy(src_mac, packet + WIFI_ADDR2_OFFSET, 6);  // 发送方
        memcpy(bssid, packet + WIFI_ADDR3_OFFSET, 6);    // BSSID
    }
}

// 获取802.11帧头部长度
size_t get_wifi_frame_header_length(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH) {
        return 0;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    bool to_ds = (frame_control & WIFI_FC_TO_DS_MASK) != 0;
    bool from_ds = (frame_control & WIFI_FC_FROM_DS_MASK) != 0;
    bool is_qos = is_qos_data_frame(packet, length);

    size_t header_length = 24; // 基本头部长度

    // 如果有第四地址（WDS模式）
    if (to_ds && from_ds) {
        header_length += 6;
    }

    // 如果是QoS数据帧
    if (is_qos) {
        header_length += 2;
    }

    return header_length;
}

// 检查是否为QoS数据帧
bool is_qos_data_frame(const uint8_t* packet, size_t length) {
    if (length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    uint16_t frame_control = packet[0] | (packet[1] << 8);
    uint8_t frame_type = (frame_control & WIFI_FC_TYPE_MASK) >> 2;
    uint8_t frame_subtype = (frame_control & WIFI_FC_SUBTYPE_MASK) >> 4;

    return (frame_type == WIFI_FRAME_TYPE_DATA && frame_subtype == 0x08);
}

// 打印WiFi帧信息
void print_wifi_frame_info(const WiFiFrameInfo* frame_info) {
    if (!frame_info) {
        return;
    }

    DEBUG_SER_PRINT("WiFi Frame: Type=%d, SubType=%d, ToDS=%d, FromDS=%d, WEP=%d, QoS=%d\n",
                   frame_info->frame_type, frame_info->frame_subtype,
                   frame_info->to_ds, frame_info->from_ds,
                   frame_info->is_wep_encrypted, frame_info->is_qos);

    DEBUG_SER_PRINT("Addr1: ");
    print_mac_address(frame_info->addr1);
    DEBUG_SER_PRINT("Addr2: ");
    print_mac_address(frame_info->addr2);
    DEBUG_SER_PRINT("Addr3: ");
    print_mac_address(frame_info->addr3);
    DEBUG_SER_PRINT("Payload Length: %d\n", frame_info->payload_length);
}

// 打印MAC地址
void print_mac_address(const uint8_t* mac) {
    if (!mac) {
        return;
    }

    for (int i = 0; i < 6; i++) {
        DEBUG_SER_PRINT("%02X", mac[i]);
        if (i < 5) DEBUG_SER_PRINT(":");
    }
    DEBUG_SER_PRINT("\n");
}

// MAC地址转字符串
String mac_to_string(const uint8_t* mac) {
    if (!mac) {
        return "";
    }

    String result = "";
    for (int i = 0; i < 6; i++) {
        if (mac[i] < 16) result += "0";
        result += String(mac[i], HEX);
        if (i < 5) result += ":";
    }
    return result;
}
