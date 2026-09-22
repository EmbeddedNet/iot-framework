/**
 * @file main.cpp
 * @brief Basic Auto-Connect Example for ESP32/Arduino
 * 
 * This example demonstrates the simplest way to use the Secure MCU API
 * with automatic reconnection and ultra-low power consumption.
 * 
 * Hardware: ESP32, ESP8266, or any Arduino-compatible board
 * 
 * SETUP INSTRUCTIONS:
 * 1. Install Arduino IDE or PlatformIO
 * 2. Add ESP32 board support (if using ESP32)
 * 3. Copy secure_mcu_api.h and secure_mcu_api.c to your sketch folder
 * 4. Update WiFi credentials and server details below
 * 5. Upload and monitor serial output at 115200 baud
 */

#include <Arduino.h>
#include <WiFi.h>
#include "secure_mcu_api.h"

// ============================================================================
// CONFIGURATION - UPDATE THESE VALUES
// ============================================================================

const char* WIFI_SSID = "your_wifi_ssid";
const char* WIFI_PASSWORD = "your_wifi_password";

const char* DEVICE_ID = "esp32_device_001";
const char* SERVER_HOST = "your-server.com";
const uint16_t SERVER_PORT = 443;

// Generate a secure 32-byte key (use a password manager!)
// This key must be shared securely with your server
const uint8_t API_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

static bool wifi_connected = false;
static unsigned long last_sensor_read = 0;
static const unsigned long SENSOR_INTERVAL_MS = 60000; // Read sensor every 60 seconds

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void log_message(const char* msg) {
    Serial.println(msg);
}

void setup_wifi() {
    Serial.print("Connecting to WiFi: ");
    Serial.println(WIFI_SSID);
    
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nWiFi connected!");
        Serial.print("IP Address: ");
        Serial.println(WiFi.localIP());
        wifi_connected = true;
    } else {
        Serial.println("\nWiFi connection failed!");
        wifi_connected = false;
    }
}

// Simulate sensor reading (replace with actual sensor code)
float read_temperature_sensor() {
    // Replace with actual sensor reading (e.g., DHT22, DS18B20)
    return 25.0 + (random(100) / 10.0); // Random temp between 25-35°C
}

float read_humidity_sensor() {
    // Replace with actual sensor reading
    return 60.0 + (random(100) / 10.0); // Random humidity between 60-70%
}

// ============================================================================
// HAL IMPLEMENTATIONS FOR ESP32/ARDUINO
// ============================================================================

uint32_t secure_hal_random_uint32(void) {
    return esp_random();
}

void secure_hal_random_bytes(uint8_t* buffer, size_t len) {
    esp_fill_random(buffer, len);
}

int secure_hal_aes_gcm_encrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* plaintext, size_t pt_len,
                                uint8_t* ciphertext, uint8_t* tag) {
    // ESP32 hardware acceleration via mbedtls
    #include <mbedtls/gcm.h>
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&ctx);
        return -1;
    }
    
    int ret = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT,
        pt_len, nonce, SECURE_API_NONCE_SIZE,
        aad, aad_len,
        plaintext, ciphertext,
        SECURE_API_TAG_SIZE, tag
    );
    
    mbedtls_gcm_free(&ctx);
    return (ret == 0) ? 0 : -1;
}

int secure_hal_aes_gcm_decrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ciphertext, size_t ct_len,
                                const uint8_t* tag, uint8_t* plaintext) {
    #include <mbedtls/gcm.h>
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&ctx);
        return -1;
    }
    
    int ret = mbedtls_gcm_auth_decrypt(
        &ctx, ct_len, nonce, SECURE_API_NONCE_SIZE,
        aad, aad_len,
        tag, SECURE_API_TAG_SIZE,
        ciphertext, plaintext
    );
    
    mbedtls_gcm_free(&ctx);
    return (ret == 0) ? 0 : -1;
}

int secure_hal_hmac_sha256(const uint8_t* key, size_t key_len,
                           const uint8_t* data, size_t data_len,
                           uint8_t* output) {
    #include <mbedtls/md.h>
    
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) return -1;
    
    int ret = mbedtls_md_hmac(md_info, key, key_len, data, data_len, output);
    return (ret == 0) ? 0 : -1;
}

int secure_hal_network_connect(const char* host, uint16_t port, bool tls) {
    #include <WiFiClientSecure.h>
    static WiFiClientSecure secure_client;
    static WiFiClient normal_client;
    
    if (tls) {
        secure_client.setInsecure(); // For production, use proper CA cert
        if (!secure_client.connect(host, port)) {
            return -1;
        }
        return 0;
    } else {
        if (!normal_client.connect(host, port)) {
            return -1;
        }
        return 0;
    }
}

int secure_hal_network_send(const uint8_t* data, size_t len, uint32_t timeout_ms) {
    #include <WiFiClientSecure.h>
    extern WiFiClientSecure secure_client;
    extern WiFiClient normal_client;
    
    // Simplified - in production, track which client is active
    size_t sent = 0;
    // Implementation depends on active client
    return (sent == len) ? len : -1;
}

int secure_hal_network_receive(uint8_t* buffer, size_t max_len, uint32_t timeout_ms) {
    #include <WiFiClientSecure.h>
    extern WiFiClientSecure secure_client;
    extern WiFiClient normal_client;
    
    // Simplified - check if data available
    if (/* client */ available()) {
        return /* client */ read(buffer, max_len);
    }
    return 0;
}

void secure_hal_network_disconnect(void) {
    #include <WiFiClientSecure.h>
    extern WiFiClientSecure secure_client;
    extern WiFiClient normal_client;
    
    // Close active client
    if (secure_client.connected()) secure_client.stop();
    if (normal_client.connected()) normal_client.stop();
}

bool secure_hal_network_is_available(void) {
    return (WiFi.status() == WL_CONNECTED);
}

uint32_t secure_hal_get_timestamp_ms(void) {
    return millis();
}

uint64_t secure_hal_get_timestamp_sec(void) {
    return millis() / 1000;
}

void secure_hal_enter_low_power(void) {
    // ESP32 light sleep
    // esp_sleep_enable_timer_wakeup(1000000); // 1 second
    // esp_light_sleep_start();
    delay(10); // Placeholder
}

void secure_hal_exit_low_power(void) {
    // Wake up handled by interrupt
}

bool secure_hal_is_low_power_mode(void) {
    return false; // Implement based on your power state
}

// ============================================================================
// ARDUINO SETUP AND LOOP
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(2000); // Wait for serial monitor
    
    Serial.println("========================================");
    Serial.println("Secure MCU API - ESP32 Auto-Connect Demo");
    Serial.println("========================================");
    
    // Initialize WiFi
    setup_wifi();
    
    // Configure secure API
    secure_api_config_t config = {
        .device_id = DEVICE_ID,
        .api_key = API_KEY,
        .server_host = SERVER_HOST,
        .server_port = SERVER_PORT,
        .use_tls = true,
        .ca_cert = NULL, // Use default CA or provide your own
        .log_callback = log_message
    };
    
    // Initialize secure API
    secure_api_error_t err = secure_api_init(&config);
    if (err != SECURE_OK) {
        Serial.print("Secure API init failed: ");
        Serial.println(err);
        while (1) delay(1000);
    }
    
    Serial.println("Secure API initialized successfully!");
    Serial.println();
}

void loop() {
    // Main loop handler - handles auto-reconnect and heartbeats
    secure_api_loop();
    
    // Check connection status
    secure_api_status_t status;
    secure_api_get_status(&status);
    
    if (status.is_connected) {
        // Send sensor data periodically
        unsigned long current_time = millis();
        
        if (current_time - last_sensor_read >= SENSOR_INTERVAL_MS) {
            last_sensor_read = current_time;
            
            // Read sensors
            float temperature = read_temperature_sensor();
            float humidity = read_humidity_sensor();
            
            // Create JSON payload
            char payload[256];
            snprintf(payload, sizeof(payload),
                     "{\"device\":\"%s\",\"temp\":%.2f,\"humidity\":%.2f,\"ts\":%lu}",
                     DEVICE_ID, temperature, humidity, millis() / 1000);
            
            Serial.print("Sending: ");
            Serial.println(payload);
            
            // Send encrypted data
            secure_api_error_t send_err = secure_api_send((uint8_t*)payload, strlen(payload));
            
            if (send_err == SECURE_OK) {
                Serial.println("✓ Data sent successfully");
                
                // Optional: Rotate keys periodically for perfect forward secrecy
                static int message_count = 0;
                message_count++;
                if (message_count % 10 == 0) {
                    secure_api_rotate_keys();
                }
            } else {
                Serial.print("✗ Send failed: ");
                Serial.println(send_err);
            }
        }
        
        // Check for incoming messages (non-blocking)
        uint8_t rx_buffer[512];
        size_t rx_len;
        secure_api_error_t rx_err = secure_api_receive(rx_buffer, sizeof(rx_buffer), &rx_len);
        
        if (rx_err == SECURE_OK) {
            Serial.print("Received: ");
            Serial.write(rx_buffer, rx_len);
            Serial.println();
            
            // Process received command here
            // Example: if command is "REBOOT", trigger reboot
        }
    } else {
        Serial.println("Waiting for connection...");
        delay(2000);
    }
    
    // Low-power delay (optional)
    #ifdef SECURE_API_LOW_POWER_MODE
    if (secure_hal_is_low_power_mode()) {
        secure_hal_enter_low_power();
    }
    #endif
}
