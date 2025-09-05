#ifndef WEP_CRACK_ALGORITHMS_H
#define WEP_CRACK_ALGORITHMS_H

#include <Arduino.h>

// WEP相关常量定义
#define MAX_WEP_PACKETS 200
#define MAX_WEAK_IVS 100
#define MAX_KEY_CANDIDATES 1000
#define MAX_DICTIONARY_SIZE 1000

// WEP破解算法类型
typedef enum {
    WEP_ALGORITHM_BRUTE_FORCE = 0,
    WEP_ALGORITHM_WEAK_IV,
    WEP_ALGORITHM_FMS,
    WEP_ALGORITHM_KOREK,
    WEP_ALGORITHM_DICTIONARY,
    WEP_ALGORITHM_COMBINED
} WEPCrackAlgorithm;

// WEP密钥长度
#define WEP_KEY_LENGTH_40  5   // 40位WEP密钥
#define WEP_KEY_LENGTH_104 13  // 104位WEP密钥

// WEP破解统计
typedef struct {
    uint32_t total_packets;        // 总数据包数
    uint32_t unique_ivs;           // 唯一IV数
    uint32_t weak_ivs;             // 弱IV数
    uint32_t fms_ivs;              // FMS IV数
    uint32_t korek_ivs;            // KoreK IV数
    uint32_t key_candidates;       // 密钥候选数
    uint32_t tested_keys;          // 已测试密钥数
    uint32_t cracked_keys;         // 已破解密钥数
    uint32_t start_time;           // 开始时间
    uint32_t last_update;          // 最后更新时间
} WEPCrackStats;

// WEP密钥候选
typedef struct {
    uint8_t key[13];               // 密钥数据
    uint8_t length;                // 密钥长度
    uint32_t confidence;           // 置信度
    WEPCrackAlgorithm algorithm;   // 使用的算法
    uint32_t iv_count;             // 支持的IV数量
} WEPKeyCandidate;

// WEP弱IV信息
typedef struct {
    uint8_t iv[3];                 // IV值
    uint8_t key_byte;              // 密钥字节位置
    uint8_t key_value;             // 密钥字节值
    uint32_t confidence;           // 置信度
    bool is_weak;                  // 是否为弱IV
} WEPWeakIV;

// FMS攻击统计
typedef struct {
    uint8_t key_byte;              // 密钥字节位置
    uint32_t count[256];           // 每个可能值的计数
    uint32_t total_ivs;            // 总IV数
    uint8_t most_likely;           // 最可能的值
    uint32_t confidence;           // 置信度
} FMSStats;

// KoreK攻击统计
typedef struct {
    uint8_t key_byte;              // 密钥字节位置
    uint32_t count[256];           // 每个可能值的计数
    uint32_t total_ivs;            // 总IV数
    uint8_t most_likely;           // 最可能的值
    uint32_t confidence;           // 置信度
} KoreKStats;

// 函数声明

// 弱IV攻击
bool is_weak_iv(const uint8_t* iv);
bool extract_key_from_weak_iv(const uint8_t* iv, const uint8_t* encrypted_data, 
                              uint8_t data_length, uint8_t* key_byte, uint8_t* key_value);
void find_weak_ivs(const WEPPacket packets[], uint8_t packet_count, 
                   WEPWeakIV weak_ivs[], uint8_t* weak_iv_count);

// FMS攻击
bool is_fms_iv(const uint8_t* iv);
void fms_attack(const WEPPacket packets[], uint8_t packet_count, 
                FMSStats* stats, uint8_t key_byte);
bool fms_extract_key_byte(const FMSStats* stats, uint8_t* key_byte, uint32_t* confidence);

// KoreK攻击
bool is_korek_iv(const uint8_t* iv);
void korek_attack(const WEPPacket packets[], uint8_t packet_count, 
                  KoreKStats* stats, uint8_t key_byte);
bool korek_extract_key_byte(const KoreKStats* stats, uint8_t* key_byte, uint32_t* confidence);

// 密钥生成和测试
void generate_key_candidates(const WEPWeakIV weak_ivs[], uint8_t weak_iv_count,
                           const FMSStats* fms_stats,
                           const KoreKStats* korek_stats,
                           WEPKeyCandidate candidates[], uint8_t* candidate_count);
bool test_wep_key(const WEPPacket packets[], uint8_t packet_count, 
                  const uint8_t* key, uint8_t key_length);
bool verify_wep_key(const WEPPacket packets[], uint8_t packet_count, 
                    const uint8_t* key, uint8_t key_length);

// 统计和分析
void update_wep_crack_stats(WEPCrackStats* stats, const WEPPacket packets[], uint8_t packet_count);
void analyze_wep_packets(const WEPPacket packets[], uint8_t packet_count, WEPCrackStats* stats);
uint32_t calculate_crack_confidence(const WEPKeyCandidate* candidate);

// 工具函数
void print_wep_crack_stats(const WEPCrackStats* stats);
void print_key_candidate(const WEPKeyCandidate* candidate);
String key_to_string(const uint8_t* key, uint8_t length);
bool compare_keys(const uint8_t* key1, const uint8_t* key2, uint8_t length);

// RC4相关函数
void rc4_init(uint8_t* s, const uint8_t* key, uint8_t key_length);
uint8_t rc4_keystream_byte(uint8_t* s, uint8_t* i, uint8_t* j);
void rc4_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, uint8_t length,
                 const uint8_t* key, uint8_t key_length, const uint8_t* iv);

// 字典攻击  
bool load_wep_dictionary(const char* filename, char dictionary[][64], uint8_t* dict_count);
bool dictionary_attack(const WEPPacket packets[], uint8_t packet_count,
                      const char dictionary[][64], uint8_t dict_count,
                      uint8_t* found_key, uint8_t* key_length);

// 组合攻击
bool combined_wep_attack(const WEPPacket packets[], uint8_t packet_count,
                        const char dictionary[][64], uint8_t dict_count,
                        uint8_t* found_key, uint8_t* key_length,
                        WEPCrackStats* stats);

#endif // WEP_CRACK_ALGORITHMS_H
