#ifndef ERROR_HANDLER_H
#define ERROR_HANDLER_H

#include <Arduino.h>

// 错误代码定义
#define ERROR_NONE                   0
#define ERROR_INVALID_PARAMETER      1
#define ERROR_MEMORY_ALLOCATION      2
#define ERROR_BUFFER_OVERFLOW        3
#define ERROR_TIMEOUT                4
#define ERROR_INVALID_DATA           5
#define ERROR_RESOURCE_EXHAUSTED     6
#define ERROR_OPERATION_FAILED       7
#define ERROR_SYSTEM_OVERLOAD        8

// 系统限制定义
#define MAX_PACKET_SIZE              2048
#define MAX_SESSIONS                 50
#define MAX_MEMORY_USAGE             8192  // 8KB
#define ERROR_THRESHOLD              100
#define TIMEOUT_DEFAULT              30000 // 30秒

// 错误处理结果
typedef struct {
    bool success;
    uint8_t error_code;
    String error_message;
    uint32_t timestamp;
} ErrorResult;

// 系统状态
typedef struct {
    uint32_t memory_usage;
    uint32_t active_sessions;
    uint32_t error_count;
    uint32_t last_cleanup;
    bool system_overloaded;
} SystemStatus;

// 超时管理器
class TimeoutManager {
private:
    struct TimeoutEntry {
        uint32_t id;
        uint32_t timeout_ms;
        uint32_t start_time;
        bool active;
    };
    
    TimeoutEntry timeouts[10];
    uint8_t timeout_count;
    
public:
    TimeoutManager();
    bool set_timeout(uint32_t id, uint32_t timeout_ms);
    bool is_timeout(uint32_t id);
    void clear_timeout(uint32_t id);
    void cleanup_expired();
};

// 资源管理器
class ResourceManager {
private:
    uint32_t current_memory_usage;
    uint32_t max_memory_usage;
    uint32_t session_count;
    
public:
    ResourceManager();
    bool allocate_memory(uint32_t size);
    void deallocate_memory(uint32_t size);
    bool can_allocate(uint32_t size);
    uint32_t get_memory_usage();
    uint32_t get_available_memory();
    void cleanup_resources();
};

// 错误处理器
class ErrorHandler {
private:
    uint32_t error_count;
    uint32_t last_error_time;
    SystemStatus system_status;
    TimeoutManager timeout_manager;
    ResourceManager resource_manager;
    
public:
    ErrorHandler();
    
    // 错误处理
    ErrorResult handle_error(uint8_t error_code, const String& message);
    void log_error(uint8_t error_code, const String& message);
    void reset_error_count();
    
    // 系统监控
    void update_system_status();
    bool is_system_healthy();
    void cleanup_if_needed();
    
    // 资源管理
    bool check_resources(uint32_t required_memory);
    void cleanup_old_resources();
    
    // 超时管理
    bool set_operation_timeout(uint32_t id, uint32_t timeout_ms);
    bool check_operation_timeout(uint32_t id);
    void clear_operation_timeout(uint32_t id);
    
    // 状态查询
    SystemStatus get_system_status();
    uint32_t get_error_count();
    String get_error_summary();
};

// 全局错误处理器实例
extern ErrorHandler error_handler;

// 便捷宏定义
#define CHECK_PARAM(condition, error_code, message) \
    do { \
        if (!(condition)) { \
            error_handler.log_error(error_code, message); \
            return false; \
        } \
    } while(0)

#define CHECK_MEMORY(size) \
    do { \
        if (!error_handler.check_resources(size)) { \
            error_handler.log_error(ERROR_RESOURCE_EXHAUSTED, "Insufficient memory"); \
            return false; \
        } \
    } while(0)

#define CHECK_TIMEOUT(id) \
    do { \
        if (error_handler.check_operation_timeout(id)) { \
            error_handler.log_error(ERROR_TIMEOUT, "Operation timeout"); \
            return false; \
        } \
    } while(0)

#define SAFE_DELETE(ptr) \
    do { \
        if (ptr) { \
            delete ptr; \
            ptr = nullptr; \
        } \
    } while(0)

// 工具函数
bool validate_packet(const uint8_t* packet, size_t length);
bool validate_mac_address(const uint8_t* mac);
bool validate_session_data(const void* data, size_t size);
String error_code_to_string(uint8_t error_code);
void print_system_status();

// 内存监控函数
void check_memory_usage();
void print_memory_status();
uint32_t get_free_heap();
uint32_t get_total_heap();
bool is_memory_critical();

#endif // ERROR_HANDLER_H
