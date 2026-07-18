#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

const char* WIFI_SSID = "2";
const char* WIFI_PASS = "apekattensatilgutten";
const char* FIPS_HOST = "192.168.13.221";
const int FIPS_PORT = 2121;
const int LOCAL_PORT = 31338; // ESP8266 listen port (matches microfips AGENTS convention)

WiFiUDP udp;
WiFiClient tcp;
bool wifiOK = false;
bool udpOK = false;

#define BUF_SIZE 2048
uint8_t buf[BUF_SIZE];

void connectWiFi() {
  Serial.printf("\n[WIFI] Connecting to '%s'...", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(500);
    Serial.print(".");
    tries++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf(" OK IP=%s RSSI=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
    wifiOK = true;
  } else {
    Serial.printf(" FAIL (%d)\n", WiFi.status());
    wifiOK = false;
  }
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n=============================");
  Serial.println("ESP8266 WiFi-UDP-Serial Bridge");
  Serial.println("FIPS relay: Serial <-> WiFi UDP");
  Serial.println("=============================");
  Serial.printf("Chip: ESP8266 ID=0x%08X Flash=%dKB Heap=%d CPU=%dMHz\n",
    ESP.getChipId(), ESP.getFlashChipRealSize()/1024, ESP.getFreeHeap(), ESP.getCpuFreqMHz());
  
  connectWiFi();
  
  if (wifiOK) {
    udp.begin(LOCAL_PORT);
    udpOK = true;
    Serial.printf("[BRIDGE] UDP listening on port %d -> FIPS %s:%d\n",
      LOCAL_PORT, FIPS_HOST, FIPS_PORT);
    Serial.println("[BRIDGE] Ready. Send FIPS frames via serial (2-byte BE length prefix + payload)");
    Serial.println("[BRIDGE] Or send raw UDP from host to this ESP8266 on port 31338");
  }
}

unsigned long lastHeartbeat = 0;

void loop() {
  // 1. Serial -> UDP (relay host data to FIPS)
  if (udpOK && Serial.available() >= 2) {
    int hi = Serial.read();
    int lo = Serial.read();
    uint16_t frameLen = (hi << 8) | lo;
    
    if (frameLen > 0 && frameLen <= BUF_SIZE) {
      int read = 0;
      unsigned long timeout = millis() + 1000;
      while (read < frameLen && millis() < timeout) {
        if (Serial.available()) {
          buf[read++] = Serial.read();
        } else {
          delay(1);
        }
      }
      
      if (read == frameLen) {
        udp.beginPacket(FIPS_HOST, FIPS_PORT);
        udp.write(buf, frameLen);
        int result = udp.endPacket();
        Serial.printf("[>>] UDP %d bytes -> FIPS (%s)\n", frameLen, result ? "OK" : "FAIL");
      }
    }
  }
  
  // 2. UDP -> Serial (relay FIPS responses to host)
  if (udpOK) {
    int len = udp.parsePacket();
    if (len > 0 && len <= BUF_SIZE) {
      int read = udp.read(buf, len);
      
      // Write back to serial with 2-byte BE length prefix
      Serial.write((read >> 8) & 0xFF);
      Serial.write(read & 0xFF);
      Serial.write(buf, read);
      Serial.printf("[<<] Serial %d bytes <- FIPS\n", read);
    }
  }
  
  // 3. Heartbeat every 30s
  if (udpOK && millis() - lastHeartbeat > 30000) {
    lastHeartbeat = millis();
    Serial.printf("[HB] heap=%d rssi=%d ip=%s uptime=%lus\n",
      ESP.getFreeHeap(), WiFi.RSSI(),
      WiFi.localIP().toString().c_str(), millis()/1000);
  }
  
  // 4. WiFi reconnect
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WIFI] Disconnected! Reconnecting...");
    connectWiFi();
    if (wifiOK) {
      udp.begin(LOCAL_PORT);
    }
  }
  
  yield();
}
