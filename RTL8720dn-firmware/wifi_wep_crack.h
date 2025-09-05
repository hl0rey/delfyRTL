#ifndef WIFI_WEP_CRACK_H
#define WIFI_WEP_CRACK_H

#include <Arduino.h>
#include "wifi_frame_parser.h"
#include "wep_crack_algorithms.h"

// WEP相关常量定义
#define WEP_IV_LENGTH 3
#define WEP_KEY_LENGTH_64 5   // 64位WEP密钥长度
#define WEP_KEY_LENGTH_128 13 // 128位WEP密钥长度
#define WEP_KEY_LENGTH_152 16 // 152位WEP密钥长度
#define WEP_KEY_LENGTH_256 29 // 256位WEP密钥长度

// WEP数据包类型
#define WEP_DATA_FRAME 0x08
#define WEP_MANAGEMENT_FRAME 0x00
#define WEP_CONTROL_FRAME 0x04

// WEP加密标志
#define WEP_ENCRYPTED_FLAG 0x40

// WEP数据包结构
typedef struct {
    uint8_t ap_mac[6];           // AP的MAC地址
    uint8_t client_mac[6];       // 客户端的MAC地址
    uint8_t iv[3];               // 初始化向量(IV)
    uint8_t key_id;              // 密钥ID (0-3)
    uint8_t encrypted_data[256]; // 加密数据
    uint16_t data_length;        // 数据长度
    uint32_t timestamp;          // 时间戳
    bool is_valid;               // 数据是否有效
} WEPPacket;

// WEP攻击会话
typedef struct {
    uint8_t ap_mac[6];           // 目标AP的MAC地址
    uint8_t client_mac[6];       // 目标客户端的MAC地址
    char ssid[32];               // 网络SSID (固定大小)
    uint8_t channel;             // 信道
    uint8_t key_length;          // 密钥长度 (64, 128, 152, 256)
    WEPPacket packets[MAX_PACKETS_PER_SESSION]; // 收集的数据包 (固定大小)
    uint8_t packet_count;        // 当前包数量
    uint32_t iv_count;           // IV数量
    uint32_t unique_iv_count;    // 唯一IV数量
    uint8_t is_active : 1;       // 攻击是否活跃 (位域)
    uint8_t key_cracked : 1;     // 密钥是否已破解 (位域)
    uint8_t reserved : 6;        // 保留位
    uint32_t start_time;         // 开始时间
    uint32_t last_update;        // 最后更新时间
    uint8_t cracked_key[29];     // 破解的密钥
    uint32_t key_crack_time;     // 密钥破解时间
} WEPAttackSession;

// 常量定义
#define MAX_WEP_SESSIONS 20
#define MAX_PACKETS_PER_SESSION 50

// 全局变量声明
extern WEPAttackSession wep_attack_sessions[MAX_WEP_SESSIONS];
extern uint8_t wep_session_count;
extern bool wep_crack_enabled;
extern uint32_t wep_crack_timeout;
extern uint32_t min_iv_count;
extern WEPCrackStats wep_crack_stats;
extern WEPCrackAlgorithm current_crack_algorithm;

// 函数声明
void init_wep_crack();
void enable_wep_crack();
void disable_wep_crack();
bool is_wep_crack_enabled();

// WEP数据包处理函数
bool process_wep_packet(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac);
bool is_wep_encrypted(const uint8_t* packet, size_t length);
bool extract_wep_data(const uint8_t* packet, size_t length, WEPPacket* wep_packet);
WEPAttackSession* find_or_create_wep_session(uint8_t* ap_mac, uint8_t* client_mac);
bool update_wep_session(WEPAttackSession* session, const WEPPacket* packet);
bool is_wep_session_ready(WEPAttackSession* session);

// WEP密钥破解函数
bool crack_wep_key(WEPAttackSession* session);
bool analyze_wep_weakness(WEPAttackSession* session);
bool brute_force_wep_key(WEPAttackSession* session);
bool statistical_attack(WEPAttackSession* session);

// 数据导出函数
void export_wep_data(const WEPAttackSession* session);
void export_all_wep_data();
void format_wep_for_export(const WEPAttackSession* session, char* buffer, size_t buffer_size);
void send_wep_data_via_uart(const WEPAttackSession* session);

// 清理函数
void cleanup_old_wep_sessions();
void clear_all_wep_data();

// 统计函数
uint32_t get_wep_session_count();
uint32_t get_active_wep_sessions();
uint32_t get_cracked_wep_sessions();

// 工具函数
uint32_t count_unique_ivs(const WEPPacket packets[], uint8_t packet_count);
bool is_weak_iv(const uint8_t* iv);
void generate_wep_key_candidates(uint8_t key_length, uint8_t* candidates[], uint8_t* candidate_count);
bool test_wep_key(const WEPPacket* packet, const uint8_t* key, uint8_t key_length);

// 高级破解算法
bool attempt_advanced_wep_crack(WEPAttackSession* session);
bool attempt_weak_iv_attack(WEPAttackSession* session);
bool attempt_fms_attack(WEPAttackSession* session);
bool attempt_korek_attack(WEPAttackSession* session);
bool attempt_dictionary_attack(WEPAttackSession* session);
bool attempt_combined_attack(WEPAttackSession* session);

// 统计和监控
void update_wep_crack_statistics();
void print_wep_crack_progress(const WEPAttackSession* session);
String get_wep_crack_status();

#endif // WIFI_WEP_CRACK_H
