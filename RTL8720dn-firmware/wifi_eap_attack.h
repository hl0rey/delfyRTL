#ifndef WIFI_EAP_ATTACK_H
#define WIFI_EAP_ATTACK_H

#include <Arduino.h>
#include "wifi_frame_parser.h"
#include "error_handler.h"

// EAP协议常量定义
#define EAP_CODE_REQUEST  1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS  3
#define EAP_CODE_FAILURE  4

// EAP类型定义
#define EAP_TYPE_IDENTITY  1
#define EAP_TYPE_NOTIFICATION 2
#define EAP_TYPE_NAK       3
#define EAP_TYPE_MD5       4
#define EAP_TYPE_OTP       5
#define EAP_TYPE_GTC       6
#define EAP_TYPE_TTLS      21
#define EAP_TYPE_PEAP      25
#define EAP_TYPE_LEAP      17

// EAP数据包最大长度
#define EAP_MAX_PACKET_SIZE 256

// EAP攻击类型枚举
typedef enum {
    EAP_ATTACK_MD5 = 0,
    EAP_ATTACK_LEAP = 1,
    EAP_ATTACK_GTC = 2,
    EAP_ATTACK_TTLS = 3,
    EAP_ATTACK_PEAP = 4,
    EAP_ATTACK_UNKNOWN = 255
} EAPAttackType;

// EAP数据包结构
typedef struct {
    uint8_t code;           // EAP代码 (Request/Response/Success/Failure)
    uint8_t identifier;     // 标识符
    uint16_t length;        // 数据包长度
    uint8_t type;           // EAP类型
    uint8_t data[EAP_MAX_PACKET_SIZE]; // 数据内容
    uint16_t data_length;   // 数据长度
    uint32_t timestamp;     // 时间戳
    bool is_valid;          // 数据是否有效
} EAPPacket;

// EAP攻击会话
typedef struct {
    uint8_t ap_mac[6];           // AP的MAC地址
    uint8_t client_mac[6];       // 客户端的MAC地址
    char ssid[32];               // 网络SSID (固定大小)
    uint8_t channel;             // 信道
    EAPAttackType attack_type;   // 攻击类型
    uint8_t challenge[256];      // 挑战数据
    uint8_t response[256];       // 响应数据
    uint16_t challenge_length;   // 挑战长度
    uint16_t response_length;    // 响应长度
    uint8_t identifier;          // EAP标识符
    uint8_t is_active : 1;       // 攻击是否活跃 (位域)
    uint8_t is_captured : 1;     // 是否已捕获凭据 (位域)
    uint8_t reserved : 6;        // 保留位
    uint32_t start_time;         // 开始时间
    uint32_t last_update;        // 最后更新时间
    char username[64];           // 捕获的用户名 (固定大小)
    char password[64];           // 捕获的密码 (固定大小)
    uint8_t hash_data[64];       // 捕获的哈希数据
    uint16_t hash_length;        // 哈希长度
} EAPAttackSession;

// 常量定义
#define MAX_EAP_SESSIONS 20
#define MAX_EAP_PACKETS_PER_SESSION 50

// 全局变量声明
extern EAPAttackSession eap_attack_sessions[MAX_EAP_SESSIONS];
extern uint8_t eap_session_count;
extern bool eap_attack_enabled;
extern EAPAttackType current_attack_type;
extern uint32_t eap_attack_timeout;

// 函数声明
void init_eap_attack();
void enable_eap_attack(EAPAttackType type);
void disable_eap_attack();
bool is_eap_attack_enabled();
EAPAttackType get_current_attack_type();

// EAP数据包处理函数
bool process_eap_packet(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac);
bool is_eap_packet(const uint8_t* packet, size_t length);
bool parse_eap_packet(const uint8_t* packet, size_t length, EAPPacket* eap_packet);
EAPAttackSession* find_or_create_eap_session(uint8_t* ap_mac, uint8_t* client_mac, EAPAttackType type);
bool update_eap_session(EAPAttackSession* session, const EAPPacket* eap_packet);

// 特定EAP攻击处理函数
bool handle_eap_md5(EAPAttackSession* session, const EAPPacket* eap_packet);
bool handle_eap_leap(EAPAttackSession* session, const EAPPacket* eap_packet);
bool handle_eap_gtc(EAPAttackSession* session, const EAPPacket* eap_packet);
bool handle_eap_ttls(EAPAttackSession* session, const EAPPacket* eap_packet);
bool handle_eap_peap(EAPAttackSession* session, const EAPPacket* eap_packet);

// 凭据提取函数
bool extract_md5_hash(const EAPPacket* eap_packet, uint8_t* hash, uint16_t* hash_length);
bool extract_leap_hash(const EAPPacket* eap_packet, uint8_t* hash, uint16_t* hash_length);
bool extract_gtc_credentials(const EAPPacket* eap_packet, char* username, char* password, size_t max_len);
bool extract_ttls_credentials(const EAPPacket* eap_packet, char* username, char* password, size_t max_len);
bool extract_peap_credentials(const EAPPacket* eap_packet, char* username, char* password, size_t max_len);

// 数据导出函数
void export_eap_data(const EAPAttackSession* session);
void export_all_eap_data();
void format_eap_for_export(const EAPAttackSession* session, char* buffer, size_t buffer_size);
void send_eap_data_via_uart(const EAPAttackSession* session);

// 清理函数
void cleanup_old_eap_sessions();
void emergency_cleanup_eap_sessions();
void clear_all_eap_data();

// 系统监控函数
void monitor_eap_system_health();
void print_eap_system_status();

// 统计函数
uint32_t get_eap_session_count();
uint32_t get_active_eap_sessions();
uint32_t get_captured_eap_sessions();

// 验证函数
bool validate_eap_packet(const EAPPacket* eap_packet);

// 工具函数
const char* eap_type_to_string(EAPAttackType type);
EAPAttackType string_to_eap_type(const char* type_str);
bool is_eap_attack_type_supported(EAPAttackType type);
void generate_eap_challenge(uint8_t* challenge, uint16_t length);

#endif // WIFI_EAP_ATTACK_H
