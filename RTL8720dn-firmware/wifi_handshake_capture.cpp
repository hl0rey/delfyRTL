#include "wifi_handshake_capture.h"
#include "wifi_frame_parser.h"
#include "debug.h"

// 全局变量定义
HandshakeSession handshake_sessions[MAX_HANDSHAKE_SESSIONS];
uint8_t handshake_session_count = 0;
bool handshake_capture_enabled = false;
uint32_t handshake_capture_timeout = 300000; // 5分钟超时

// 初始化握手包捕获系统
void init_handshake_capture() {
    handshake_session_count = 0;
    memset(handshake_sessions, 0, sizeof(handshake_sessions));
    handshake_capture_enabled = false;
    DEBUG_SER_PRINT("Handshake capture system initialized\n");
}

// 启用握手包捕获
void enable_handshake_capture() {
    handshake_capture_enabled = true;
    DEBUG_SER_PRINT("Handshake capture enabled\n");
}

// 禁用握手包捕获
void disable_handshake_capture() {
    handshake_capture_enabled = false;
    DEBUG_SER_PRINT("Handshake capture disabled\n");
}

// 检查握手包捕获是否启用
bool is_handshake_capture_enabled() {
    return handshake_capture_enabled;
}

// 处理EAPOL数据包
bool process_eapol_packet(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac) {
    if (!handshake_capture_enabled || length < WIFI_FRAME_MIN_LENGTH) {
        return false;
    }

    // 使用新的帧解析器检查是否为EAPOL包
    if (!is_eapol_frame(packet, length)) {
        return false;
    }

    DEBUG_SER_PRINT("EAPOL packet detected\n");

    // 解析802.11帧
    WiFiFrameInfo frame_info;
    if (!parse_wifi_frame(packet, length, &frame_info)) {
        return false;
    }

    // 提取MAC地址
    uint8_t ap_mac[6], client_mac[6], bssid[6];
    extract_mac_addresses(packet, length, src_mac, dst_mac, bssid);
    
    // 根据帧方向确定AP和客户端
    if (frame_info.from_ds && !frame_info.to_ds) {
        // AP到客户端
        memcpy(ap_mac, src_mac, 6);
        memcpy(client_mac, dst_mac, 6);
    } else if (!frame_info.from_ds && frame_info.to_ds) {
        // 客户端到AP
        memcpy(ap_mac, dst_mac, 6);
        memcpy(client_mac, src_mac, 6);
    } else {
        // 其他情况，使用BSSID作为AP地址
        memcpy(ap_mac, bssid, 6);
        memcpy(client_mac, src_mac, 6);
    }

    // 检查EAPOL载荷
    if (frame_info.payload_length < 4) {
        return false;
    }

    const uint8_t* eapol_data = frame_info.payload;
    size_t eapol_length = frame_info.payload_length;

    // 检查EAPOL版本 (应该是1)
    if (eapol_data[1] != 0x01) {
        return false;
    }

    // 检查EAPOL类型 (应该是3 = EAPOL-Key)
    if (eapol_data[2] != 0x03) {
        return false;
    }

    // 识别握手包类型
    HandshakeType type = identify_handshake_type(eapol_data, eapol_length);
    if (type == HANDSHAKE_NONE) {
        return false;
    }

    // 检查是否为PMKID包
    if (type == HANDSHAKE_PMKID) {
        PMKIDPacket pmkid;
        if (extract_pmkid_data(eapol_data, eapol_length, &pmkid)) {
            // 查找或创建会话
            HandshakeSession* session = find_or_create_session(ap_mac, client_mac);
            if (session && update_pmkid_session(session, &pmkid)) {
                DEBUG_SER_PRINT("PMKID captured successfully\n");
                export_pmkid_data(session);
                return true;
            }
        }
        return false;
    }

    // 提取握手包数据
    HandshakePacket handshake;
    if (!extract_handshake_data(eapol_data, eapol_length, &handshake)) {
        return false;
    }

    // 查找或创建会话
    HandshakeSession* session = find_or_create_session(ap_mac, client_mac);
    if (!session) {
        DEBUG_SER_PRINT("Failed to create handshake session\n");
        return false;
    }

    // 更新会话
    if (update_handshake_session(session, &handshake)) {
        DEBUG_SER_PRINT("Handshake packet processed successfully\n");
        
        // 检查握手是否完整
        if (is_handshake_complete(session)) {
            DEBUG_SER_PRINT("Complete handshake captured!\n");
            export_handshake_data(session);
        }
        return true;
    }

    return false;
}

// 识别握手包类型
HandshakeType identify_handshake_type(const uint8_t* eapol_data, size_t length) {
    if (length < 17) { // 最小EAPOL-Key长度
        return HANDSHAKE_NONE;
    }

    // 获取Key Information字段 (字节5-6)
    uint16_t key_info = (eapol_data[5] << 8) | eapol_data[6];
    
    // 检查是否为Pairwise Key
    if (!(key_info & EAPOL_KEY_INFO_KEY_TYPE_MASK)) {
        return HANDSHAKE_GROUP;
    }

    // 根据Key Information位判断消息类型
    bool key_ack = key_info & EAPOL_KEY_INFO_KEY_ACK_MASK;
    bool key_mic = key_info & EAPOL_KEY_INFO_KEY_MIC_MASK;
    bool secure = key_info & EAPOL_KEY_INFO_SECURE_MASK;
    bool install = key_info & EAPOL_KEY_INFO_INSTALL_MASK;

    if (key_ack && !key_mic && !secure) {
        return HANDSHAKE_M1; // Message 1 of 4
    } else if (!key_ack && key_mic && !secure) {
        return HANDSHAKE_M2; // Message 2 of 4
    } else if (key_ack && key_mic && secure && install) {
        return HANDSHAKE_M3; // Message 3 of 4
    } else if (!key_ack && key_mic && secure) {
        return HANDSHAKE_M4; // Message 4 of 4
    }

    // 检查是否为PMKID包
    // PMKID通常在M1或M2消息中，包含在Key Data字段中
    if (length > 83) {
        const uint8_t* key_data = eapol_data + 83;
        size_t key_data_len = length - 83;
        
        // 查找PMKID KDE (Key Data Element)
        // PMKID KDE格式: Type(1) + Length(1) + OUI(3) + Data Type(1) + PMKID(16)
        // 总长度: 1 + 1 + 3 + 1 + 16 = 22字节
        for (size_t i = 0; i < key_data_len - 21; i++) {
            if (key_data[i] == 0xDD && key_data[i+1] == 0x16 && 
                key_data[i+2] == 0x00 && key_data[i+3] == 0x0F && key_data[i+4] == 0xAC &&
                key_data[i+5] == 0x0A) {
                return HANDSHAKE_PMKID;
            }
        }
    }

    return HANDSHAKE_NONE;
}

// 提取握手包数据
bool extract_handshake_data(const uint8_t* eapol_data, size_t length, HandshakePacket* handshake) {
    if (length < 17) {
        return false;
    }

    memset(handshake, 0, sizeof(HandshakePacket));
    handshake->timestamp = millis();

    // 提取Key Information
    handshake->key_info = (eapol_data[5] << 8) | eapol_data[6];

    // 提取Key Length
    uint16_t key_length = (eapol_data[7] << 8) | eapol_data[8];

    // 提取Replay Counter (字节9-16)
    memcpy(handshake->key_replay_counter, eapol_data + 9, 8);

    // 提取Key Nonce (字节17-48)
    if (length >= 48) {
        memcpy(handshake->anonce, eapol_data + 17, 32);
    }

    // 提取Key IV (字节49-56)
    // 提取Key RSC (字节57-64)
    // 提取Key ID (字节65-66)
    // 提取Key MIC (字节67-82)
    if (length >= 82) {
        memcpy(handshake->mic, eapol_data + 67, 16);
    }

    // 提取Key Data (从字节83开始)
    if (length > 83) {
        size_t key_data_start = 83;
        size_t key_data_available = length - key_data_start;
        size_t key_data_to_copy = min(key_data_available, (size_t)256);
        
        memcpy(handshake->key_data, eapol_data + key_data_start, key_data_to_copy);
        handshake->key_data_length = key_data_to_copy;
    }

    handshake->is_valid = true;
    return true;
}

// 查找或创建握手会话
HandshakeSession* find_or_create_session(uint8_t* ap_mac, uint8_t* client_mac) {
    // 查找现有会话
    for (auto& session : handshake_sessions) {
        if (memcmp(session.ap_mac, ap_mac, 6) == 0 && 
            memcmp(session.client_mac, client_mac, 6) == 0) {
            return &session;
        }
    }

    // 创建新会话
    HandshakeSession new_session;
    memset(&new_session, 0, sizeof(HandshakeSession));
    memcpy(new_session.ap_mac, ap_mac, 6);
    memcpy(new_session.client_mac, client_mac, 6);
    new_session.start_time = millis();
    new_session.last_update = millis();
    new_session.m1_received = false;
    new_session.m2_received = false;
    new_session.m3_received = false;
    new_session.m4_received = false;
    new_session.pmkid_received = false;
    new_session.is_complete = false;
    new_session.has_pmkid = false;

    handshake_sessions.push_back(new_session);
    return &handshake_sessions.back();
}

// 更新握手会话
bool update_handshake_session(HandshakeSession* session, const HandshakePacket* packet) {
    if (!session || !packet || !packet->is_valid) {
        return false;
    }

    session->last_update = millis();

    // 根据握手包类型更新相应的数据
    switch (packet->type) {
        case HANDSHAKE_M1:
            if (!session->m1_received) {
                session->packets[0] = *packet;
                session->m1_received = true;
                DEBUG_SER_PRINT("M1 received\n");
            }
            break;
            
        case HANDSHAKE_M2:
            if (!session->m2_received) {
                session->packets[1] = *packet;
                session->m2_received = true;
                DEBUG_SER_PRINT("M2 received\n");
            }
            break;
            
        case HANDSHAKE_M3:
            if (!session->m3_received) {
                session->packets[2] = *packet;
                session->m3_received = true;
                DEBUG_SER_PRINT("M3 received\n");
            }
            break;
            
        case HANDSHAKE_M4:
            if (!session->m4_received) {
                session->packets[3] = *packet;
                session->m4_received = true;
                DEBUG_SER_PRINT("M4 received\n");
            }
            break;
            
        default:
            return false;
    }

    return true;
}

// 检查握手是否完整
bool is_handshake_complete(const HandshakeSession* session) {
    if (!session) {
        return false;
    }

    return session->m1_received && session->m2_received && 
           session->m3_received && session->m4_received;
}

// 导出握手数据
void export_handshake_data(const HandshakeSession* session) {
    if (!session) {
        return;
    }

    String handshake_data = format_handshake_for_export(session);
    send_handshake_data_via_uart(session);
    
    DEBUG_SER_PRINT("Handshake data exported\n");
}

// 导出所有握手数据
void export_all_handshakes() {
    for (const auto& session : handshake_sessions) {
        if (is_handshake_complete(&session)) {
            export_handshake_data(&session);
        }
    }
}

// 格式化握手数据用于导出
String format_handshake_for_export(const HandshakeSession* session) {
    String result = "HANDSHAKE:";
    
    // AP MAC
    result += "AP:";
    for (int i = 0; i < 6; i++) {
        if (session->ap_mac[i] < 16) result += "0";
        result += String(session->ap_mac[i], HEX);
        if (i < 5) result += ":";
    }
    
    // Client MAC
    result += "|CLIENT:";
    for (int i = 0; i < 6; i++) {
        if (session->client_mac[i] < 16) result += "0";
        result += String(session->client_mac[i], HEX);
        if (i < 5) result += ":";
    }
    
    // SSID
    result += "|SSID:" + session->ssid;
    
    // Channel
    result += "|CHANNEL:" + String(session->channel);
    
    // Timestamp
    result += "|TIME:" + String(session->start_time);
    
    result += "\n";
    return result;
}

// 通过UART发送握手数据
void send_handshake_data_via_uart(const HandshakeSession* session) {
    String data = format_handshake_for_export(session);
    Serial1.print(data);
    Serial.print(data);
    
    // 发送详细的握手包数据
    for (int i = 0; i < 4; i++) {
        if (session->packets[i].is_valid) {
            String packet_data = "PACKET" + String(i+1) + ":";
            
            // 发送Nonce数据
            packet_data += "NONCE:";
            for (int j = 0; j < 32; j++) {
                if (session->packets[i].anonce[j] < 16) packet_data += "0";
                packet_data += String(session->packets[i].anonce[j], HEX);
            }
            
            // 发送MIC数据
            packet_data += "|MIC:";
            for (int j = 0; j < 16; j++) {
                if (session->packets[i].mic[j] < 16) packet_data += "0";
                packet_data += String(session->packets[i].mic[j], HEX);
            }
            
            packet_data += "\n";
            Serial1.print(packet_data);
            Serial.print(packet_data);
        }
    }
}

// 清理过期会话
void cleanup_old_sessions() {
    uint32_t current_time = millis();
    
    for (auto it = handshake_sessions.begin(); it != handshake_sessions.end();) {
        if (current_time - it->last_update > handshake_capture_timeout) {
            it = handshake_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

// 清除所有握手数据
void clear_all_handshakes() {
    handshake_sessions.clear();
    DEBUG_SER_PRINT("All handshake data cleared\n");
}

// 获取握手包数量
uint32_t get_handshake_count() {
    return handshake_sessions.size();
}

// 获取完整握手包数量
uint32_t get_complete_handshake_count() {
    uint32_t count = 0;
    for (const auto& session : handshake_sessions) {
        if (is_handshake_complete(&session)) {
            count++;
        }
    }
    return count;
}

// 获取PMKID数量
uint32_t get_pmkid_count() {
    uint32_t count = 0;
    for (const auto& session : handshake_sessions) {
        if (session.has_pmkid) {
            count++;
        }
    }
    return count;
}

// 提取PMKID数据
bool extract_pmkid_data(const uint8_t* eapol_data, size_t length, PMKIDPacket* pmkid) {
    if (length < 83) {
        return false;
    }

    memset(pmkid, 0, sizeof(PMKIDPacket));
    pmkid->timestamp = millis();

    // 提取Key Information
    pmkid->key_info = (eapol_data[5] << 8) | eapol_data[6];

    // 提取Key Length
    uint16_t key_length = (eapol_data[7] << 8) | eapol_data[8];

    // 提取Replay Counter (字节9-16)
    memcpy(pmkid->key_replay_counter, eapol_data + 9, 8);

    // 提取Key Nonce (字节17-48)
    if (length >= 48) {
        memcpy(pmkid->anonce, eapol_data + 17, 32);
    }

    // 提取Key MIC (字节67-82)
    if (length >= 82) {
        memcpy(pmkid->mic, eapol_data + 67, 16);
    }

    // 提取Key Data并查找PMKID
    if (length > 83) {
        const uint8_t* key_data = eapol_data + 83;
        size_t key_data_len = length - 83;
        
        // 查找PMKID KDE
        for (size_t i = 0; i < key_data_len - 21; i++) {
            if (key_data[i] == 0xDD && key_data[i+1] == 0x16 && 
                key_data[i+2] == 0x00 && key_data[i+3] == 0x0F && key_data[i+4] == 0xAC &&
                key_data[i+5] == 0x0A) {
                // 找到PMKID KDE，提取PMKID值
                memcpy(pmkid->pmkid, key_data + i + 6, 16);
                pmkid->is_valid = true;
                DEBUG_SER_PRINT("PMKID extracted successfully\n");
                return true;
            }
        }
    }

    return false;
}

// 更新PMKID会话
bool update_pmkid_session(HandshakeSession* session, const PMKIDPacket* pmkid) {
    if (!session || !pmkid || !pmkid->is_valid) {
        return false;
    }

    session->last_update = millis();
    session->pmkid_packet = *pmkid;
    session->pmkid_received = true;
    session->has_pmkid = true;

    DEBUG_SER_PRINT("PMKID session updated\n");
    return true;
}

// 检查会话是否有PMKID
bool has_pmkid(const HandshakeSession* session) {
    if (!session) {
        return false;
    }
    return session->has_pmkid;
}

// 导出PMKID数据
void export_pmkid_data(const HandshakeSession* session) {
    if (!session || !session->has_pmkid) {
        return;
    }

    String pmkid_data = format_pmkid_for_export(session);
    send_pmkid_data_via_uart(session);
    
    DEBUG_SER_PRINT("PMKID data exported\n");
}

// 导出所有PMKID数据
void export_all_pmkids() {
    for (const auto& session : handshake_sessions) {
        if (session.has_pmkid) {
            export_pmkid_data(&session);
        }
    }
}

// 格式化PMKID数据用于导出
String format_pmkid_for_export(const HandshakeSession* session) {
    String result = "PMKID:";
    
    // AP MAC
    result += "AP:";
    for (int i = 0; i < 6; i++) {
        if (session->ap_mac[i] < 16) result += "0";
        result += String(session->ap_mac[i], HEX);
        if (i < 5) result += ":";
    }
    
    // Client MAC
    result += "|CLIENT:";
    for (int i = 0; i < 6; i++) {
        if (session->client_mac[i] < 16) result += "0";
        result += String(session->client_mac[i], HEX);
        if (i < 5) result += ":";
    }
    
    // SSID
    result += "|SSID:" + session->ssid;
    
    // Channel
    result += "|CHANNEL:" + String(session->channel);
    
    // PMKID
    result += "|PMKID:";
    for (int i = 0; i < 16; i++) {
        if (session->pmkid_packet.pmkid[i] < 16) result += "0";
        result += String(session->pmkid_packet.pmkid[i], HEX);
    }
    
    // Timestamp
    result += "|TIME:" + String(session->start_time);
    
    result += "\n";
    return result;
}

// 通过UART发送PMKID数据
void send_pmkid_data_via_uart(const HandshakeSession* session) {
    String data = format_pmkid_for_export(session);
    Serial1.print(data);
    Serial.print(data);
    
    // 发送详细的PMKID数据
    String detail_data = "PMKID_DETAIL:";
    
    // 发送ANonce数据
    detail_data += "ANONCE:";
    for (int i = 0; i < 32; i++) {
        if (session->pmkid_packet.anonce[i] < 16) detail_data += "0";
        detail_data += String(session->pmkid_packet.anonce[i], HEX);
    }
    
    // 发送MIC数据
    detail_data += "|MIC:";
    for (int i = 0; i < 16; i++) {
        if (session->pmkid_packet.mic[i] < 16) detail_data += "0";
        detail_data += String(session->pmkid_packet.mic[i], HEX);
    }
    
    // 发送Key Info
    detail_data += "|KEY_INFO:" + String(session->pmkid_packet.key_info, HEX);
    
    detail_data += "\n";
    Serial1.print(detail_data);
    Serial.print(detail_data);
}
