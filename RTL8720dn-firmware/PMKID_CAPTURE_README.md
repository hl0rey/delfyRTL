# PMKID捕获功能使用说明

## 功能概述

PMKID（Pairwise Master Key Identifier）捕获功能是delfyRTL项目的重要扩展，可以捕获WPA3和某些WPA2实现中的PMKID值，用于离线密码破解分析。

## 技术原理

### PMKID机制
PMKID是WPA3-SAE（Simultaneous Authentication of Equals）和某些WPA2实现中使用的快速重连机制：

1. **PMKID生成**：基于PMK（Pairwise Master Key）和AP/客户端MAC地址生成
2. **快速重连**：客户端可以使用PMKID快速重新连接到已知网络
3. **离线破解**：PMKID可以用于离线密码破解，无需完整的4次握手

### PMKID KDE结构
PMKID以Key Data Element (KDE)的形式包含在EAPOL-Key消息中：

```
KDE格式：
- Type: 0xDD (Vendor Specific)
- Length: 0x16 (22字节)
- OUI: 0x00, 0x0F, 0xAC (IEEE 802.11)
- Data Type: 0x0A (PMKID)
- PMKID: 16字节的PMKID值
```

### 捕获机制
- 监听EAPOL-Key数据包
- 解析Key Data字段
- 识别PMKID KDE
- 提取PMKID值
- 存储相关数据（MAC地址、Nonce、MIC等）

## 使用方法

### 1. 固件命令

通过UART发送以下命令控制PMKID捕获：

#### 启动捕获（同时捕获握手包和PMKID）
```
HANDSHAKE:ON
```

#### 查看状态（包含PMKID统计）
```
HANDSHAKE:STAT
```
返回格式：
```
HANDSHAKE:STAT|TOTAL:3|COMPLETE:1|PMKID:2|ACTIVE:YES
```

#### 导出PMKID数据
```
HANDSHAKE:PMKID
```

#### 导出所有数据
```
HANDSHAKE:EXPORT
```

### 2. Flipper Zero界面

在握手包捕获界面中：
- **Start**: 开始/停止捕获（同时捕获握手包和PMKID）
- **Status**: 查看捕获状态（包含PMKID数量）
- **Export**: 导出握手包数据
- **PMKID**: 导出PMKID数据

## 数据格式

### PMKID数据格式
```
PMKID:AP:AA:BB:CC:DD:EE:FF|CLIENT:11:22:33:44:55:66|SSID:TestNetwork|CHANNEL:6|PMKID:1234567890ABCDEF1234567890ABCDEF|TIME:1234567890
PMKID_DETAIL:ANONCE:1234567890ABCDEF...|MIC:ABCDEF1234567890...|KEY_INFO:008A
```

### 字段说明
- **AP**: 接入点的MAC地址
- **CLIENT**: 客户端的MAC地址
- **SSID**: 网络名称
- **CHANNEL**: WiFi信道
- **PMKID**: 16字节的PMKID值（十六进制）
- **TIME**: 捕获时间戳
- **ANONCE**: AP的随机数
- **MIC**: 消息完整性校验码
- **KEY_INFO**: 密钥信息字段

## 技术实现

### 核心文件
- `wifi_handshake_capture.h` - 扩展的头文件定义
- `wifi_handshake_capture.cpp` - PMKID处理实现
- `RTL8720dn-firmware.ino` - 主固件集成

### 关键函数
- `extract_pmkid_data()` - 提取PMKID数据
- `update_pmkid_session()` - 更新PMKID会话
- `export_pmkid_data()` - 导出PMKID数据
- `get_pmkid_count()` - 获取PMKID数量

### 数据结构
```cpp
typedef struct {
    uint8_t ap_mac[6];           // AP的MAC地址
    uint8_t client_mac[6];       // 客户端的MAC地址
    uint8_t pmkid[16];           // PMKID值
    uint8_t anonce[32];          // AP的随机数
    uint8_t snonce[32];          // 客户端的随机数
    uint8_t mic[16];             // 消息完整性校验码
    uint8_t key_data[256];       // 密钥数据
    uint16_t key_data_length;    // 密钥数据长度
    uint16_t key_info;           // 密钥信息
    uint8_t key_replay_counter[8]; // 重放计数器
    uint32_t timestamp;          // 时间戳
    bool is_valid;               // 数据是否有效
} PMKIDPacket;
```

## 使用场景

### 1. WPA3网络攻击
- 捕获WPA3-SAE网络的PMKID
- 用于离线密码破解
- 绕过WPA3的增强安全性

### 2. WPA2快速重连
- 捕获支持PMKID的WPA2网络
- 利用快速重连机制
- 提高攻击效率

### 3. 安全研究
- 分析PMKID实现差异
- 研究快速重连机制
- 开发新的攻击技术

## 优势特点

### 相比传统握手包捕获
1. **更高效**：只需一个数据包即可获得破解所需信息
2. **更隐蔽**：不需要完整的4次握手过程
3. **更快速**：减少捕获时间和网络活动
4. **更广泛**：支持WPA3和现代WPA2实现

### 技术优势
- 自动识别PMKID KDE
- 完整的数据提取和存储
- 标准化的导出格式
- 与现有握手包捕获系统集成

## 注意事项

### 法律合规
- 仅在授权环境中使用
- 遵守当地法律法规
- 不得用于非法目的

### 技术限制
- 需要支持PMKID的网络和设备
- 某些网络可能不支持PMKID
- 需要适当的网络活动

### 最佳实践
- 在目标设备附近进行捕获
- 等待设备连接或重连
- 定期检查捕获状态
- 及时导出重要数据

## 故障排除

### 常见问题
1. **无法捕获PMKID**
   - 检查网络是否支持PMKID
   - 确认设备正在连接
   - 验证监控模式状态

2. **PMKID数据不完整**
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
- 验证PMKID KDE格式
- 监控内存使用

## 与现有功能集成

### 握手包捕获
- PMKID捕获与握手包捕获共享同一系统
- 可以同时捕获两种类型的数据
- 统一的状态查询和导出接口

### 去认证攻击
- 可以结合去认证攻击强制重连
- 增加捕获PMKID的机会
- 提高攻击成功率

## 扩展功能

### 未来改进
- 支持更多PMKID变体
- 添加PMKID验证功能
- 优化内存使用
- 增加统计分析

### 自定义开发
- 修改PMKID数据格式
- 添加新的导出方式
- 集成第三方破解工具
- 开发自动化脚本

## 技术支持

如有问题或建议，请参考：
- 项目GitHub仓库
- 技术文档
- 社区论坛
- 开发者文档

## 相关工具

### 密码破解工具
- **hashcat**: 支持PMKID破解
- **aircrack-ng**: 传统WiFi破解工具
- **John the Ripper**: 通用密码破解工具

### 数据格式转换
- 将PMKID数据转换为hashcat格式
- 支持多种导出格式
- 自动化脚本支持
