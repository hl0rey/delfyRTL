#include "error_handler.h"
#include "debug.h"

// 全局错误处理器实例
ErrorHandler error_handler;

// TimeoutManager实现
TimeoutManager::TimeoutManager() : timeout_count(0) {
    memset(timeouts, 0, sizeof(timeouts));
}

bool TimeoutManager::set_timeout(uint32_t id, uint32_t timeout_ms) {
    if (timeout_count >= 10) {
        return false; // 超时条目已满
    }
    
    for (uint8_t i = 0; i < timeout_count; i++) {
        if (timeouts[i].id == id) {
            timeouts[i].timeout_ms = timeout_ms;
            timeouts[i].start_time = millis();
            timeouts[i].active = true;
            return true;
        }
    }
    
    // 添加新的超时条目
    timeouts[timeout_count].id = id;
    timeouts[timeout_count].timeout_ms = timeout_ms;
    timeouts[timeout_count].start_time = millis();
    timeouts[timeout_count].active = true;
    timeout_count++;
    
    return true;
}

bool TimeoutManager::is_timeout(uint32_t id) {
    for (uint8_t i = 0; i < timeout_count; i++) {
        if (timeouts[i].id == id && timeouts[i].active) {
            if (millis() - timeouts[i].start_time > timeouts[i].timeout_ms) {
                timeouts[i].active = false;
                return true;
            }
        }
    }
    return false;
}

void TimeoutManager::clear_timeout(uint32_t id) {
    for (uint8_t i = 0; i < timeout_count; i++) {
        if (timeouts[i].id == id) {
            timeouts[i].active = false;
            break;
        }
    }
}

void TimeoutManager::cleanup_expired() {
    for (uint8_t i = 0; i < timeout_count; i++) {
        if (timeouts[i].active && 
            millis() - timeouts[i].start_time > timeouts[i].timeout_ms) {
            timeouts[i].active = false;
        }
    }
}

// ResourceManager实现
ResourceManager::ResourceManager() : current_memory_usage(0), max_memory_usage(MAX_MEMORY_USAGE), session_count(0) {
}

bool ResourceManager::allocate_memory(uint32_t size) {
    if (current_memory_usage + size > max_memory_usage) {
        return false;
    }
    current_memory_usage += size;
    return true;
}

void ResourceManager::deallocate_memory(uint32_t size) {
    if (current_memory_usage >= size) {
        current_memory_usage -= size;
    }
}

bool ResourceManager::can_allocate(uint32_t size) {
    return (current_memory_usage + size) <= max_memory_usage;
}

uint32_t ResourceManager::get_memory_usage() {
    return current_memory_usage;
}

uint32_t ResourceManager::get_available_memory() {
    return max_memory_usage - current_memory_usage;
}

void ResourceManager::cleanup_resources() {
    // 清理资源，释放内存
    current_memory_usage = 0;
    session_count = 0;
}

// ErrorHandler实现
ErrorHandler::ErrorHandler() : error_count(0), last_error_time(0) {
    memset(&system_status, 0, sizeof(system_status));
    system_status.last_cleanup = millis();
}

ErrorResult ErrorHandler::handle_error(uint8_t error_code, const String& message) {
    ErrorResult result;
    result.success = false;
    result.error_code = error_code;
    result.error_message = message;
    result.timestamp = millis();
    
    log_error(error_code, message);
    return result;
}

void ErrorHandler::log_error(uint8_t error_code, const String& message) {
    error_count++;
    last_error_time = millis();
    
    DEBUG_SER_PRINT("ERROR[%d]: %s (Code: %d)\n", error_count, message.c_str(), error_code);
    
    // 如果错误过多，触发系统清理
    if (error_count > ERROR_THRESHOLD) {
        DEBUG_SER_PRINT("Too many errors, triggering cleanup\n");
        cleanup_resources();
        reset_error_count();
    }
}

void ErrorHandler::reset_error_count() {
    error_count = 0;
    last_error_time = 0;
}

void ErrorHandler::update_system_status() {
    system_status.memory_usage = resource_manager.get_memory_usage();
    system_status.error_count = error_count;
    system_status.last_cleanup = millis();
    
    // 检查系统是否过载
    system_status.system_overloaded = (system_status.memory_usage > (MAX_MEMORY_USAGE * 0.8)) ||
                                     (error_count > (ERROR_THRESHOLD * 0.8));
}

bool ErrorHandler::is_system_healthy() {
    update_system_status();
    return !system_status.system_overloaded && error_count < ERROR_THRESHOLD;
}

void ErrorHandler::cleanup_if_needed() {
    if (millis() - system_status.last_cleanup > 60000) { // 每分钟清理一次
        cleanup_old_resources();
        system_status.last_cleanup = millis();
    }
}

bool ErrorHandler::check_resources(uint32_t required_memory) {
    return resource_manager.can_allocate(required_memory);
}

void ErrorHandler::cleanup_old_resources() {
    resource_manager.cleanup_resources();
    timeout_manager.cleanup_expired();
    
    DEBUG_SER_PRINT("System cleanup completed\n");
}

bool ErrorHandler::set_operation_timeout(uint32_t id, uint32_t timeout_ms) {
    return timeout_manager.set_timeout(id, timeout_ms);
}

bool ErrorHandler::check_operation_timeout(uint32_t id) {
    return timeout_manager.is_timeout(id);
}

void ErrorHandler::clear_operation_timeout(uint32_t id) {
    timeout_manager.clear_timeout(id);
}

SystemStatus ErrorHandler::get_system_status() {
    update_system_status();
    return system_status;
}

uint32_t ErrorHandler::get_error_count() {
    return error_count;
}

String ErrorHandler::get_error_summary() {
    String summary = "System Status:\n";
    summary += "Memory Usage: " + String(system_status.memory_usage) + " bytes\n";
    summary += "Error Count: " + String(error_count) + "\n";
    summary += "System Healthy: " + String(is_system_healthy() ? "Yes" : "No") + "\n";
    return summary;
}

// 工具函数实现
bool validate_packet(const uint8_t* packet, size_t length) {
    if (!packet) {
        error_handler.log_error(ERROR_INVALID_PARAMETER, "Packet is null");
        return false;
    }
    
    if (length == 0) {
        error_handler.log_error(ERROR_INVALID_PARAMETER, "Packet length is zero");
        return false;
    }
    
    if (length > MAX_PACKET_SIZE) {
        error_handler.log_error(ERROR_BUFFER_OVERFLOW, "Packet too large: " + String(length));
        return false;
    }
    
    return true;
}

bool validate_mac_address(const uint8_t* mac) {
    if (!mac) {
        error_handler.log_error(ERROR_INVALID_PARAMETER, "MAC address is null");
        return false;
    }
    
    // 检查MAC地址是否全零或全一（通常无效）
    bool all_zero = true;
    bool all_one = true;
    
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) all_zero = false;
        if (mac[i] != 0xFF) all_one = false;
    }
    
    if (all_zero || all_one) {
        error_handler.log_error(ERROR_INVALID_DATA, "Invalid MAC address");
        return false;
    }
    
    return true;
}

bool validate_session_data(const void* data, size_t size) {
    if (!data) {
        error_handler.log_error(ERROR_INVALID_PARAMETER, "Session data is null");
        return false;
    }
    
    if (size == 0) {
        error_handler.log_error(ERROR_INVALID_PARAMETER, "Session data size is zero");
        return false;
    }
    
    if (size > 1024) { // 会话数据不应超过1KB
        error_handler.log_error(ERROR_BUFFER_OVERFLOW, "Session data too large: " + String(size));
        return false;
    }
    
    return true;
}

String error_code_to_string(uint8_t error_code) {
    switch (error_code) {
        case ERROR_NONE: return "No Error";
        case ERROR_INVALID_PARAMETER: return "Invalid Parameter";
        case ERROR_MEMORY_ALLOCATION: return "Memory Allocation Failed";
        case ERROR_BUFFER_OVERFLOW: return "Buffer Overflow";
        case ERROR_TIMEOUT: return "Operation Timeout";
        case ERROR_INVALID_DATA: return "Invalid Data";
        case ERROR_RESOURCE_EXHAUSTED: return "Resource Exhausted";
        case ERROR_OPERATION_FAILED: return "Operation Failed";
        case ERROR_SYSTEM_OVERLOAD: return "System Overload";
        default: return "Unknown Error";
    }
}

void print_system_status() {
    SystemStatus status = error_handler.get_system_status();
    
    DEBUG_SER_PRINT("=== System Status ===\n");
    DEBUG_SER_PRINT("Memory Usage: %d bytes\n", status.memory_usage);
    DEBUG_SER_PRINT("Active Sessions: %d\n", status.active_sessions);
    DEBUG_SER_PRINT("Error Count: %d\n", status.error_count);
    DEBUG_SER_PRINT("System Overloaded: %s\n", status.system_overloaded ? "Yes" : "No");
    DEBUG_SER_PRINT("System Healthy: %s\n", error_handler.is_system_healthy() ? "Yes" : "No");
    DEBUG_SER_PRINT("===================\n");
}

// 内存监控函数实现
void check_memory_usage() {
    uint32_t free_heap = get_free_heap();
    uint32_t total_heap = get_total_heap();
    uint32_t used_heap = total_heap - free_heap;
    
    // 更新系统状态中的内存使用
    error_handler.update_system_status();
    
    // 检查内存是否严重不足
    if (is_memory_critical()) {
        DEBUG_SER_PRINT("WARNING: Critical memory usage detected!\n");
        print_memory_status();
        
        // 触发紧急清理
        error_handler.cleanup_old_resources();
    }
}

void print_memory_status() {
    uint32_t free_heap = get_free_heap();
    uint32_t total_heap = get_total_heap();
    uint32_t used_heap = total_heap - free_heap;
    float usage_percent = (float)used_heap / total_heap * 100.0f;
    
    DEBUG_SER_PRINT("=== Memory Status ===\n");
    DEBUG_SER_PRINT("Total Heap: %u bytes\n", total_heap);
    DEBUG_SER_PRINT("Used Heap: %u bytes\n", used_heap);
    DEBUG_SER_PRINT("Free Heap: %u bytes\n", free_heap);
    DEBUG_SER_PRINT("Usage: %.1f%%\n", usage_percent);
    DEBUG_SER_PRINT("Status: %s\n", is_memory_critical() ? "CRITICAL" : "OK");
    DEBUG_SER_PRINT("====================\n");
}

uint32_t get_free_heap() {
    // RTL8720DN平台使用FreeRTOS内存API
    #if defined(ARDUINO_AMEBA)
    // RTL8720DN使用FreeRTOS
    return xPortGetFreeHeapSize();
    #elif defined(ESP32)
    return ESP.getFreeHeap();
    #elif defined(ESP8266)
    return ESP.getFreeHeap();
    #else
    // 对于其他平台，返回一个估计值
    return 32000; // 32KB估计
    #endif
}

uint32_t get_total_heap() {
    // RTL8720DN平台的堆内存信息
    #if defined(ARDUINO_AMEBA)
    // RTL8720DN通常有512KB RAM，但不是所有都用作堆
    // 预留256KB给堆使用
    return 262144; // 256KB
    #elif defined(ESP32)
    return ESP.getHeapSize();
    #elif defined(ESP8266)
    return ESP.getHeapSize();
    #else
    // 对于其他平台，返回一个估计值
    return 64000; // 64KB估计
    #endif
}

bool is_memory_critical() {
    uint32_t free_heap = get_free_heap();
    uint32_t total_heap = get_total_heap();
    
    // 如果可用内存少于总内存的10%，认为严重不足
    return (free_heap < total_heap * 0.1);
}
