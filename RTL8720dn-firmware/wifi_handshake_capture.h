#ifndef WIFI_HANDSHAKE_CAPTURE_H
#define WIFI_HANDSHAKE_CAPTURE_H

#include <Arduino.h>
#include "wifi_frame_parser.h"

// 握手包捕获常量定义
#define MAX_HANDSHAKE_SESSIONS 20

// WPA/WPA2 握手包类型定义
#define EAPOL_KEY_TYPE_PAIRWISE 0x8
#define EAPOL_KEY_TYPE_GROUP    0x0

// EAPOL Key Information 位定义
#define EAPOL_KEY_INFO_KEY_TYPE_MASK    0x0008
#define EAPOL_KEY_INFO_KEY_INDEX_MASK   0x0003
#define EAPOL_KEY_INFO_INSTALL_MASK     0x0040
#define EAPOL_KEY_INFO_KEY_ACK_MASK     0x0080
#define EAPOL_KEY_INFO_KEY_MIC_MASK     0x0100
#define EAPOL_KEY_INFO_SECURE_MASK      0x0200
#define EAPOL_KEY_INFO_ERROR_MASK       0x0400
#define EAPOL_KEY_INFO_REQUEST_MASK     0x0800
#define EAPOL_KEY_INFO_ENCRYPTED_MASK   0x1000

// 握手包类型
typedef enum {
    HANDSHAKE_NONE = 0,
    HANDSHAKE_M1,    // Message 1 of 4 (AP -> Client)
    HANDSHAKE_M2,    // Message 2 of 4 (Client -> AP)
    HANDSHAKE_M3,    // Message 3 of 4 (AP -> Client)
    HANDSHAKE_M4,    // Message 4 of 4 (Client -> AP)
    HANDSHAKE_GROUP, // Group Key Handshake
    HANDSHAKE_PMKID  // PMKID capture
} HandshakeType;

// PMKID数据结构
typedef struct {
    uint8_t ap_mac[6];           // AP的MAC地址
    uint8_t client_mac[6];       // 客户端的MAC地址
    uint8_t pmkid[16];           // PMKID值
    uint8_t anonce[32];          // AP的随机数（如果可用）
    uint8_t snonce[32];          // 客户端的随机数（如果可用）
    uint8_t mic[16];             // 消息完整性校验码
    uint8_t key_data[256];       // 密钥数据
    uint16_t key_data_length;    // 密钥数据长度
    uint16_t key_info;           // 密钥信息
    uint8_t key_replay_counter[8]; // 重放计数器
    uint32_t timestamp;          // 时间戳
    bool is_valid;               // 数据是否有效
} PMKIDPacket;

// 握手包数据结构
typedef struct {
    uint8_t ap_mac[6];           // AP的MAC地址
    uint8_t client_mac[6];       // 客户端的MAC地址
    uint8_t anonce[32];          // AP的随机数
    uint8_t snonce[32];          // 客户端的随机数
    uint8_t mic[16];             // 消息完整性校验码
    uint8_t key_data[256];       // 密钥数据
    uint16_t key_data_length;    // 密钥数据长度
    uint16_t key_info;           // 密钥信息
    uint8_t key_replay_counter[8]; // 重放计数器
    HandshakeType type;          // 握手包类型
    uint32_t timestamp;          // 时间戳
    bool is_valid;               // 数据是否有效
} HandshakePacket;

// 握手包捕获会话
typedef struct {
    uint8_t ap_mac[6];           // 目标AP的MAC地址
    uint8_t client_mac[6];       // 目标客户端的MAC地址
    char ssid[33];               // 网络SSID (固定大小)
    uint8_t channel;             // 信道
    HandshakePacket packets[4];  // 存储4个握手包
    PMKIDPacket pmkid_packet;    // PMKID数据包
    bool m1_received;            // M1是否已接收
    bool m2_received;            // M2是否已接收
    bool m3_received;            // M3是否已接收
    bool m4_received;            // M4是否已接收
    bool pmkid_received;         // PMKID是否已接收
    bool is_complete;            // 握手是否完整
    bool has_pmkid;              // 是否有PMKID
    uint32_t start_time;         // 开始时间
    uint32_t last_update;        // 最后更新时间
} HandshakeSession;

// 全局变量声明
extern HandshakeSession handshake_sessions[MAX_HANDSHAKE_SESSIONS];
extern uint8_t handshake_session_count;
extern bool handshake_capture_enabled;
extern uint32_t handshake_capture_timeout;

// 函数声明
void init_handshake_capture();
void enable_handshake_capture();
void disable_handshake_capture();
bool is_handshake_capture_enabled();

// 握手包处理函数
bool process_eapol_packet(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac);
HandshakeType identify_handshake_type(const uint8_t* eapol_data, size_t length);
bool extract_handshake_data(const uint8_t* eapol_data, size_t length, HandshakePacket* handshake);
HandshakeSession* find_or_create_session(uint8_t* ap_mac, uint8_t* client_mac);
bool update_handshake_session(HandshakeSession* session, const HandshakePacket* packet);
bool is_handshake_complete(const HandshakeSession* session);

// PMKID处理函数
bool extract_pmkid_data(const uint8_t* eapol_data, size_t length, PMKIDPacket* pmkid);
bool update_pmkid_session(HandshakeSession* session, const PMKIDPacket* pmkid);
bool has_pmkid(const HandshakeSession* session);

// 数据导出函数
void export_handshake_data(const HandshakeSession* session);
void export_all_handshakes();
String format_handshake_for_export(const HandshakeSession* session);
void send_handshake_data_via_uart(const HandshakeSession* session);

// PMKID导出函数
void export_pmkid_data(const HandshakeSession* session);
void export_all_pmkids();
String format_pmkid_for_export(const HandshakeSession* session);
void send_pmkid_data_via_uart(const HandshakeSession* session);

// 清理函数
void cleanup_old_sessions();
void clear_all_handshakes();

// 统计函数
uint32_t get_handshake_count();
uint32_t get_complete_handshake_count();
uint32_t get_pmkid_count();

#endif // WIFI_HANDSHAKE_CAPTURE_H
