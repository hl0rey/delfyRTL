#ifndef WIFI_FRAME_PARSER_H
#define WIFI_FRAME_PARSER_H

#include <Arduino.h>

// 802.11帧类型定义
#define WIFI_FRAME_TYPE_MANAGEMENT 0x00
#define WIFI_FRAME_TYPE_CONTROL    0x01
#define WIFI_FRAME_TYPE_DATA       0x02

// 802.11帧子类型定义
#define WIFI_SUBTYPE_BEACON        0x80
#define WIFI_SUBTYPE_DEAUTH        0xC0
#define WIFI_SUBTYPE_DISASSOC      0xA0
#define WIFI_SUBTYPE_AUTH          0xB0
#define WIFI_SUBTYPE_ASSOC_REQ     0x00
#define WIFI_SUBTYPE_ASSOC_RESP    0x10
#define WIFI_SUBTYPE_DATA          0x00
#define WIFI_SUBTYPE_QOS_DATA      0x08

// 802.11帧控制字段位定义
#define WIFI_FC_TYPE_MASK          0x0C
#define WIFI_FC_SUBTYPE_MASK       0xF0
#define WIFI_FC_TO_DS_MASK         0x01
#define WIFI_FC_FROM_DS_MASK       0x02
#define WIFI_FC_MORE_FRAG_MASK     0x04
#define WIFI_FC_RETRY_MASK         0x08
#define WIFI_FC_PWR_MGT_MASK       0x10
#define WIFI_FC_MORE_DATA_MASK     0x20
#define WIFI_FC_WEP_MASK           0x40
#define WIFI_FC_ORDER_MASK         0x80

// 802.11地址字段位置
#define WIFI_ADDR1_OFFSET          4   // 接收方地址
#define WIFI_ADDR2_OFFSET          10  // 发送方地址
#define WIFI_ADDR3_OFFSET          16  // BSSID地址
#define WIFI_ADDR4_OFFSET          22  // 第四地址（仅用于WDS）

// 802.11帧最小长度
#define WIFI_FRAME_MIN_LENGTH      24

// 802.11帧头部结构
typedef struct {
    uint16_t frame_control;        // 帧控制字段
    uint16_t duration;             // 持续时间
    uint8_t addr1[6];              // 地址1（接收方）
    uint8_t addr2[6];              // 地址2（发送方）
    uint8_t addr3[6];              // 地址3（BSSID）
    uint16_t sequence_control;     // 序列控制
    uint8_t addr4[6];              // 地址4（可选）
} WiFiFrameHeader;

// 802.11数据帧结构
typedef struct {
    WiFiFrameHeader header;
    uint8_t* payload;              // 载荷数据
    size_t payload_length;         // 载荷长度
    uint32_t fcs;                  // 帧校验序列
} WiFiDataFrame;

// 802.11管理帧结构
typedef struct {
    WiFiFrameHeader header;
    uint8_t* payload;              // 载荷数据
    size_t payload_length;         // 载荷长度
    uint32_t fcs;                  // 帧校验序列
} WiFiManagementFrame;

// 802.11控制帧结构
typedef struct {
    WiFiFrameHeader header;
    uint8_t* payload;              // 载荷数据
    size_t payload_length;         // 载荷长度
    uint32_t fcs;                  // 帧校验序列
} WiFiControlFrame;

// 802.11帧解析结果
typedef struct {
    uint8_t frame_type;            // 帧类型
    uint8_t frame_subtype;         // 帧子类型
    bool to_ds;                    // 到DS标志
    bool from_ds;                  // 从DS标志
    bool is_wep_encrypted;         // WEP加密标志
    bool is_qos;                   // QoS标志
    uint8_t addr1[6];              // 地址1
    uint8_t addr2[6];              // 地址2
    uint8_t addr3[6];              // 地址3
    uint8_t addr4[6];              // 地址4
    uint8_t* payload;              // 载荷数据
    size_t payload_length;         // 载荷长度
    bool is_valid;                 // 帧是否有效
} WiFiFrameInfo;

// 函数声明
bool parse_wifi_frame(const uint8_t* packet, size_t length, WiFiFrameInfo* frame_info);
bool is_wifi_data_frame(const uint8_t* packet, size_t length);
bool is_wifi_management_frame(const uint8_t* packet, size_t length);
bool is_wifi_control_frame(const uint8_t* packet, size_t length);
bool is_wep_encrypted_frame(const uint8_t* packet, size_t length);
bool is_eapol_frame(const uint8_t* packet, size_t length);
bool is_eap_frame(const uint8_t* packet, size_t length);
void extract_mac_addresses(const uint8_t* packet, size_t length, uint8_t* src_mac, uint8_t* dst_mac, uint8_t* bssid);
size_t get_wifi_frame_header_length(const uint8_t* packet, size_t length);
bool is_qos_data_frame(const uint8_t* packet, size_t length);

// 工具函数
void print_wifi_frame_info(const WiFiFrameInfo* frame_info);
void print_mac_address(const uint8_t* mac);
String mac_to_string(const uint8_t* mac);

#endif // WIFI_FRAME_PARSER_H
