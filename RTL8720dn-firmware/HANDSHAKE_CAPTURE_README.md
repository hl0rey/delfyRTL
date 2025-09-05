# WiFi握手包捕获功能使用说明

## 功能概述

本功能为delfyRTL项目添加了WPA/WPA2握手包捕获和PMKID捕获能力，可以捕获完整的4次握手过程以及PMKID值，用于后续的密码破解分析。

## 技术原理

### WPA/WPA2握手过程
1. **M1 (Message 1)**: AP → Client - 发送ANonce
2. **M2 (Message 2)**: Client → AP - 发送SNonce和MIC
3. **M3 (Message 3)**: AP → Client - 发送GTK和MIC
4. **M4 (Message 4)**: Client → AP - 发送确认MIC

### 捕获机制
- 监听EAPOL-Key数据包
- 解析802.11帧结构
- 识别握手包类型
- 提取关键数据（Nonce、MIC等）
- 存储完整的握手会话

## 使用方法

### 1. 固件命令

通过UART发送以下命令控制握手包捕获：

#### 启动捕获
```
HANDSHAKE:ON
```

#### 停止捕获
```
HANDSHAKE:OFF
```

#### 查看状态
```
HANDSHAKE:STAT
```
返回格式：
```
HANDSHAKE:STAT|TOTAL:3|COMPLETE:1|PMKID:2|ACTIVE:YES
```

#### 导出数据
```
HANDSHAKE:EXPORT
```

#### 导出PMKID数据
```
HANDSHAKE:PMKID
```

#### 清除数据
```
HANDSHAKE:CLEAR
```

### 2. Flipper Zero界面

在主菜单中选择"Handshake"选项：
- **Start**: 开始/停止握手包捕获
- **Status**: 查看捕获状态
- **Export**: 导出握手包数据
- **PMKID**: 导出PMKID数据

## 数据格式

### 握手包数据格式
```
HANDSHAKE:AP:AA:BB:CC:DD:EE:FF|CLIENT:11:22:33:44:55:66|SSID:TestNetwork|CHANNEL:6|TIME:1234567890
PACKET1:NONCE:1234567890ABCDEF...|MIC:ABCDEF1234567890...
PACKET2:NONCE:1234567890ABCDEF...|MIC:ABCDEF1234567890...
PACKET3:NONCE:1234567890ABCDEF...|MIC:ABCDEF1234567890...
PACKET4:NONCE:1234567890ABCDEF...|MIC:ABCDEF1234567890...
```

### 字段说明
- **AP**: 接入点的MAC地址
- **CLIENT**: 客户端的MAC地址
- **SSID**: 网络名称
- **CHANNEL**: WiFi信道
- **TIME**: 捕获时间戳
- **NONCE**: 32字节的随机数
- **MIC**: 16字节的消息完整性校验码

## 技术实现

### 核心文件
- `wifi_handshake_capture.h` - 头文件定义
- `wifi_handshake_capture.cpp` - 核心实现
- `wifi_cust_tx.h/cpp` - WiFi帧处理扩展
- `RTL8720dn-firmware.ino` - 主固件集成

### 关键函数
- `process_eapol_packet()` - 处理EAPOL数据包
- `identify_handshake_type()` - 识别握手包类型
- `extract_handshake_data()` - 提取握手包数据
- `export_handshake_data()` - 导出握手包数据

### 数据结构
```cpp
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
```

## 使用场景

### 1. 渗透测试
- 捕获目标网络的握手包
- 用于离线密码破解
- 验证网络安全性

### 2. 安全研究
- 分析WPA/WPA2协议实现
- 研究握手包特征
- 开发新的攻击技术

### 3. 网络诊断
- 分析连接问题
- 监控网络活动
- 调试WiFi问题

## 注意事项

### 法律合规
- 仅在授权环境中使用
- 遵守当地法律法规
- 不得用于非法目的

### 技术限制
- 需要目标设备连接网络
- 可能触发去认证攻击
- 内存使用量较大

### 最佳实践
- 在目标设备附近进行捕获
- 使用去认证攻击强制重连
- 定期清理过期数据
- 及时导出重要数据

## 故障排除

### 常见问题
1. **无法捕获握手包**
   - 检查监控模式是否启用
   - 确认目标设备正在连接
   - 验证信道设置

2. **数据不完整**
   - 检查内存使用情况
   - 确认捕获时间足够
   - 验证网络活动

3. **导出失败**
   - 检查UART连接
   - 确认数据格式正确
   - 验证缓冲区大小

### 调试方法
- 启用调试输出
- 检查串口日志
- 验证数据包格式
- 监控内存使用

## 扩展功能

### 未来改进
- 支持WPA3握手包
- 添加数据包过滤
- 优化内存使用
- 增加统计分析

### 自定义开发
- 修改数据格式
- 添加新的导出方式
- 集成第三方工具
- 开发自动化脚本

## 技术支持

如有问题或建议，请参考：
- 项目GitHub仓库
- 技术文档
- 社区论坛
- 开发者文档
