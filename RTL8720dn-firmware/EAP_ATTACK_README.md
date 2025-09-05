# EAP攻击功能使用说明

## 功能概述

EAP攻击功能是delfyRTL项目的重要扩展，可以针对WiFi网络中的EAP（Extensible Authentication Protocol）认证协议进行攻击，捕获用户的认证凭据和哈希值。

## 技术原理

### EAP协议概述
EAP是一个可扩展的认证协议，广泛用于WiFi网络的802.1X认证中。它支持多种认证方法，每种方法都有不同的安全特性。

### 支持的EAP攻击类型

#### 1. **EAP-MD5攻击**
- **协议特点**：使用MD5哈希进行认证
- **攻击原理**：捕获EAP-Response/MD5-Challenge中的MD5哈希
- **破解方法**：使用字典攻击或暴力破解MD5哈希
- **安全等级**：低（MD5已被认为不安全）

#### 2. **EAP-LEAP攻击**
- **协议特点**：Cisco专有协议，使用MS-CHAPv1
- **攻击原理**：捕获EAP-Response/LEAP-Challenge中的LEAP哈希
- **破解方法**：使用asleap工具或hashcat破解
- **安全等级**：低（使用弱加密）

#### 3. **EAP-GTC攻击**
- **协议特点**：Generic Token Card，明文传输
- **攻击原理**：直接捕获明文用户名和密码
- **破解方法**：无需破解，直接获取凭据
- **安全等级**：极低（明文传输）

#### 4. **EAP-TTLS攻击**
- **协议特点**：Tunneled Transport Layer Security
- **攻击原理**：捕获TTLS隧道内的认证信息
- **破解方法**：需要解析TTLS内部协议
- **安全等级**：中等

#### 5. **EAP-PEAP攻击**
- **协议特点**：Protected Extensible Authentication Protocol
- **攻击原理**：捕获PEAP隧道内的认证信息
- **破解方法**：需要解析PEAP内部协议
- **安全等级**：中等

## 使用方法

### 1. 固件命令

通过UART发送以下命令控制EAP攻击：

#### 启动EAP-MD5攻击
```
EAP:MD5
```

#### 启动EAP-LEAP攻击
```
EAP:LEAP
```

#### 启动EAP-GTC攻击
```
EAP:GTC
```

#### 启动EAP-TTLS攻击
```
EAP:TTLS
```

#### 启动EAP-PEAP攻击
```
EAP:PEAP
```

#### 停止EAP攻击
```
EAP:OFF
```

#### 查看状态
```
EAP:STAT
```
返回格式：
```
EAP:STAT|TOTAL:2|ACTIVE:1|CAPTURED:1|TYPE:MD5|ACTIVE:YES
```

#### 导出数据
```
EAP:EXPORT
```

#### 清除数据
```
EAP:CLEAR
```

### 2. Flipper Zero界面

在主菜单中选择"EAP Attack"选项：
- **MD5**: 启动EAP-MD5攻击
- **LEAP**: 启动EAP-LEAP攻击
- **GTC**: 启动EAP-GTC攻击
- **Status**: 查看攻击状态

## 数据格式

### EAP数据格式
```
EAP:TYPE:MD5|AP:AA:BB:CC:DD:EE:FF|CLIENT:11:22:33:44:55:66|SSID:TestNetwork|CHANNEL:6|CAPTURED:YES|USERNAME:admin|PASSWORD:password123|HASH:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88|TIME:1234567890
```

### 字段说明
- **TYPE**: 攻击类型（MD5/LEAP/GTC/TTLS/PEAP）
- **AP**: 接入点的MAC地址
- **CLIENT**: 客户端的MAC地址
- **SSID**: 网络名称
- **CHANNEL**: WiFi信道
- **CAPTURED**: 是否已捕获凭据
- **USERNAME**: 捕获的用户名（如果有）
- **PASSWORD**: 捕获的密码（如果有）
- **HASH**: 捕获的哈希值（十六进制）
- **TIME**: 开始时间戳

## 技术实现

### 核心文件
- `wifi_eap_attack.h` - 头文件定义
- `wifi_eap_attack.cpp` - 核心实现
- `wifi_cust_tx.h/cpp` - WiFi帧处理扩展
- `RTL8720dn-firmware.ino` - 主固件集成

### 关键函数
- `process_eap_packet()` - 处理EAP数据包
- `parse_eap_packet()` - 解析EAP数据包
- `handle_eap_md5()` - 处理EAP-MD5攻击
- `handle_eap_leap()` - 处理EAP-LEAP攻击
- `handle_eap_gtc()` - 处理EAP-GTC攻击

### 数据结构
```cpp
typedef struct {
    uint8_t code;           // EAP代码
    uint8_t identifier;     // 标识符
    uint16_t length;        // 数据包长度
    uint8_t type;           // EAP类型
    uint8_t data[256];      // 数据内容
    uint16_t data_length;   // 数据长度
    uint32_t timestamp;     // 时间戳
    bool is_valid;          // 数据是否有效
} EAPPacket;
```

## 攻击流程

### 1. **准备阶段**
1. 启动EAP攻击功能
2. 选择攻击类型（MD5/LEAP/GTC等）
3. 开始监控WiFi数据包

### 2. **攻击执行**
1. 检测EAP数据包
2. 解析EAP协议内容
3. 提取认证信息
4. 保存凭据或哈希值

### 3. **数据提取**
1. 查看捕获的凭据
2. 导出数据用于分析
3. 使用破解工具验证

## 破解工具

### 1. **MD5哈希破解**
```bash
# 使用hashcat
hashcat -m 0 -a 3 md5_hashes.txt ?d?d?d?d?d?d?d?d

# 使用John the Ripper
john --format=raw-md5 md5_hashes.txt
```

### 2. **LEAP哈希破解**
```bash
# 使用asleap工具
asleap -r capture.pcap -w wordlist.txt

# 使用hashcat
hashcat -m 5500 -a 3 leap_hashes.txt ?d?d?d?d?d?d?d?d
```

### 3. **GTC凭据获取**
```bash
# GTC攻击直接获取明文密码
# 无需破解，直接查看捕获的数据
```

## 使用场景

### 1. **渗透测试**
- 测试企业WiFi安全
- 验证EAP认证配置
- 发现认证漏洞

### 2. **安全研究**
- 分析EAP协议安全性
- 研究新的攻击向量
- 开发防护措施

### 3. **教育目的**
- 演示EAP安全漏洞
- 培训网络安全人员
- 提高安全意识

## 防护措施

### 1. **网络管理员**
- 使用强EAP方法（EAP-TLS、EAP-PEAP）
- 禁用弱EAP方法（MD5、LEAP、GTC）
- 使用证书认证
- 监控异常认证尝试

### 2. **用户**
- 避免连接可疑WiFi网络
- 使用VPN保护数据
- 定期更换密码
- 启用双因素认证

## 注意事项

### 法律合规
- 仅在授权环境中使用
- 遵守当地法律法规
- 不得用于非法目的

### 技术限制
- 需要目标网络使用EAP认证
- 需要足够的网络数据流量
- 某些EAP方法难以破解

### 最佳实践
- 在目标网络附近进行攻击
- 使用去认证攻击增加流量
- 定期检查攻击进度
- 及时导出攻击结果

## 故障排除

### 常见问题
1. **无法捕获EAP数据包**
   - 检查网络是否使用EAP认证
   - 确认监控模式是否启用
   - 验证网络活动情况

2. **攻击失败**
   - 检查EAP类型是否支持
   - 确认网络数据流量
   - 尝试不同的攻击方法

3. **导出失败**
   - 检查UART连接
   - 确认数据格式正确
   - 验证缓冲区大小

### 调试方法
- 启用调试输出
- 检查串口日志
- 验证EAP数据包格式
- 监控内存使用

## 与现有功能集成

### 握手包捕获
- EAP攻击与握手包捕获共享WiFi监控系统
- 可以同时进行多种攻击
- 统一的状态查询和导出接口

### 去认证攻击
- 可以结合去认证攻击强制重连
- 增加EAP认证流量
- 提高攻击成功率

## 扩展功能

### 未来改进
- 支持更多EAP类型
- 添加实时破解功能
- 优化内存使用
- 增加攻击统计

### 自定义开发
- 修改攻击算法
- 添加新的EAP类型
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
- **hashcat**: 支持多种哈希类型
- **John the Ripper**: 通用密码破解工具
- **asleap**: 专门用于LEAP攻击

### 数据格式转换
- 将EAP数据转换为标准格式
- 支持多种导出格式
- 自动化脚本支持

## 历史背景

EAP协议最初设计用于PPP连接，后来被扩展到WiFi网络中。虽然EAP提供了灵活的认证框架，但某些实现（如MD5、LEAP）存在严重的安全漏洞，使得EAP攻击成为WiFi安全测试的重要工具。

## 安全建议

对于网络管理员：
1. 立即禁用所有弱EAP方法
2. 使用强EAP方法（EAP-TLS、EAP-PEAP）
3. 实施证书认证
4. 监控网络中的异常活动

对于用户：
1. 避免连接到使用弱EAP方法的网络
2. 使用VPN保护数据传输
3. 定期更新设备固件
4. 启用网络监控功能
