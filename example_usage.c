/**
 * @file example_usage.c
 * @brief Complete working example for ESP32/Arduino/STM32
 * 
 * This demonstrates the simple 3-line integration of the Secure MCU API
 */

#include "secure_mcu_api.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * STEP 1: Configure your device credentials
 * Store these in secure element, OTP memory, or encrypted flash
 * ============================================================================ */

static SecureDeviceContext g_device_ctx = {
    .device_id = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    },
    .device_secret = {
        // 32-byte manufacturing secret (unique per device)
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    },
    .aes_key = {
        // 32-byte AES-256 key (pre-shared or derived from secret)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    }
};

/* ============================================================================
 * STEP 2: Implement Hardware Abstraction Layer for your MCU
 * Example implementations for common platforms below
 * ============================================================================ */

// --- Crypto HAL Implementation (Example using mbedTLS or hardware crypto) ---

static SecureAPIStatus my_aes_gcm_encrypt(const uint8_t* key, const uint8_t* iv,
                                           const uint8_t* plaintext, size_t pt_len,
                                           uint8_t* ciphertext, uint8_t* tag) {
    // TODO: Implement using your MCU's crypto hardware or library
    // Examples:
    // - ESP32: esp_aes_gcm_encrypt()
    // - STM32: HAL_CRYP_AESGCM_Encrypt()
    // - Arduino: use AESLib or mbedTLS
    
    #ifdef ARDUINO_ARCH_ESP32
        // ESP32 hardware acceleration example
        // Use esp_aes library with GCM mode
    #endif
    
    // Placeholder - replace with actual implementation
    (void)key; (void)iv; (void)plaintext; (void)pt_len;
    (void)ciphertext; (void)tag;
    
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_aes_gcm_decrypt(const uint8_t* key, const uint8_t* iv,
                                           const uint8_t* ciphertext, size_t ct_len,
                                           const uint8_t* tag, uint8_t* plaintext) {
    // TODO: Implement decryption using your MCU's crypto hardware
    (void)key; (void)iv; (void)ciphertext; (void)ct_len;
    (void)tag; (void)plaintext;
    
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_hmac_sha256(const uint8_t* key, size_t key_len,
                                       const uint8_t* data, size_t data_len,
                                       uint8_t* hmac) {
    // TODO: Implement HMAC-SHA256
    // Examples:
    // - ESP32: esp_hmac_sha256()
    // - mbedTLS: mbedtls_md_hmac()
    (void)key; (void)key_len; (void)data; (void)data_len; (void)hmac;
    
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_random_generate(uint8_t* buffer, size_t length) {
    // TODO: Implement secure random generation
    // Examples:
    // - ESP32: esp_fill_random()
    // - STM32: HAL_RNG_GenerateRandomNumber()
    // - Arduino: randomSeed() + random()
    
    #ifdef ARDUINO_ARCH_ESP32
        esp_fill_random(buffer, length);
        return SECURE_API_SUCCESS;
    #endif
    
    // Fallback (not cryptographically secure - replace!)
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (uint8_t)(i & 0xFF);
    }
    
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_secure_erase(uint8_t* buffer, size_t length) {
    // Securely zero memory (already implemented in API)
    volatile uint8_t* p = (volatile uint8_t*)buffer;
    while (length--) {
        *p++ = 0;
    }
    return SECURE_API_SUCCESS;
}

static const CryptoHAL g_crypto_hal = {
    .aes_gcm_encrypt = my_aes_gcm_encrypt,
    .aes_gcm_decrypt = my_aes_gcm_decrypt,
    .sha256_hmac = my_hmac_sha256,
    .random_generate = my_random_generate,
    .secure_erase = my_secure_erase
};

// --- Network HAL Implementation (Example for WiFi/Ethernet) ---

static SecureAPIStatus my_network_connect(const char* host, uint16_t port, 
                                           uint32_t timeout_ms) {
    // TODO: Implement network connection
    // Examples:
    // - ESP32 WiFi: WiFi.begin(), WiFi.waitForConnectResult()
    // - Ethernet: Ethernet.begin()
    // - GSM: modem.connect()
    
    #ifdef ARDUINO_ARCH_ESP32
        // WiFi.begin("SSID", "PASSWORD");
        // if (WiFi.waitForConnectResult(timeout_ms) != WL_CONNECTED) {
        //     return SECURE_API_ERROR_NETWORK;
        // }
    #endif
    
    (void)host; (void)port; (void)timeout_ms;
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_network_disconnect(void) {
    // TODO: Disconnect network
    #ifdef ARDUINO_ARCH_ESP32
        // WiFi.disconnect();
    #endif
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_network_send(const uint8_t* data, size_t length,
                                        uint32_t timeout_ms) {
    // TODO: Send data over network (TLS/SSL recommended)
    // Examples:
    // - ESP32: WiFiClientSecure.write()
    // - Ethernet: client.write()
    
    (void)data; (void)length; (void)timeout_ms;
    return SECURE_API_SUCCESS;
}

static SecureAPIStatus my_network_receive(uint8_t* buffer, size_t max_length,
                                           size_t* received_length, 
                                           uint32_t timeout_ms) {
    // TODO: Receive data from network
    // Examples:
    // - ESP32: WiFiClientSecure.read()
    // - Ethernet: client.read()
    
    (void)buffer; (void)max_length; (void)received_length; (void)timeout_ms;
    *received_length = 0;
    return SECURE_API_SUCCESS;
}

static bool my_network_is_connected(void) {
    // TODO: Check network connection status
    #ifdef ARDUINO_ARCH_ESP32
        // return (WiFi.status() == WL_CONNECTED);
    #endif
    return true;
}

static bool my_network_available(void) {
    // TODO: Check if network is available
    return true;
}

static const NetworkHAL g_network_hal = {
    .connect = my_network_connect,
    .disconnect = my_network_disconnect,
    .send = my_network_send,
    .receive = my_network_receive,
    .is_connected = my_network_is_connected,
    .network_available = my_network_available
};

// --- Power HAL Implementation ---

static uint32_t g_tick_start = 0;

static void my_enter_low_power(void) {
    // TODO: Enter MCU sleep mode
    // Examples:
    // - ESP32: esp_deep_sleep_start()
    // - STM32: HAL_PWR_EnterSTOPMode()
    // - AVR: set_sleep_mode(SLEEP_MODE_PWR_DOWN); sleep_mode();
    
    #ifdef ARDUINO_ARCH_ESP32
        // esp_deep_sleep(5000);  // Sleep for 5 seconds
    #endif
}

static void my_exit_low_power(void) {
    // TODO: Wake from sleep (usually automatic on interrupt)
}

static uint32_t my_get_tick_ms(void) {
    // TODO: Get current time in milliseconds
    #ifdef ARDUINO
        return millis();
    #else
        // Implement using hardware timer
        return 0;
    #endif
}

static void my_delay_ms(uint32_t ms) {
    #ifdef ARDUINO
        delay(ms);
    #else
        // Implement busy wait or RTOS delay
        (void)ms;
    #endif
}

static const PowerHAL g_power_hal = {
    .enter_low_power = my_enter_low_power,
    .exit_low_power = my_exit_low_power,
    .get_tick_ms = my_get_tick_ms,
    .delay_ms = my_delay_ms
};

/* ============================================================================
 * STEP 3: Initialize in setup()
 * ============================================================================ */

void setup() {
    // Initialize serial for debugging
    #ifdef ARDUINO
        Serial.begin(115200);
        while (!Serial) { delay(10); }
        Serial.println("Secure MCU API Starting...");
    #endif
    
    // ONE-LINE INITIALIZATION
    SecureAPIStatus status = secure_api_init(&g_device_ctx, &g_crypto_hal, 
                                              &g_network_hal, &g_power_hal);
    
    if (status != SECURE_API_SUCCESS) {
        #ifdef ARDUINO
            Serial.printf("Initialization failed: %s\n", 
                         secure_api_get_error_string(status));
        #endif
        while (1) {
            my_delay_ms(1000);
        }
    }
    
    #ifdef ARDUINO
        Serial.println("Secure API initialized successfully!");
    #endif
}

/* ============================================================================
 * STEP 4: Main loop with auto-connect and low-power support
 * ============================================================================ */

void loop() {
    // Call secure_api_loop() regularly - handles everything!
    secure_api_loop();
    
    // Check if ready to send data
    if (SECURE_API_IS_READY()) {
        // Connection established and authenticated
        
        // Option 1: Send sensor data with macro
        float temperature = 23.5;
        float humidity = 65.2;
        
        SECURE_API_SEND_SENSOR("temperature", temperature);
        SECURE_API_SEND_SENSOR("humidity", humidity);
        
        // Option 2: Send custom JSON
        SECURE_API_SEND_JSON("{\"event\":\"status\",\"battery\":95,\"signal\":-67}");
        
        // Option 3: Send binary data
        uint8_t sensor_data[16];
        // ... fill sensor_data ...
        secure_api_send(sensor_data, sizeof(sensor_data));
        
        // Receive commands from server (non-blocking)
        uint8_t rx_buffer[256];
        size_t rx_length;
        SecureAPIStatus rx_status = secure_api_receive(rx_buffer, sizeof(rx_buffer),
                                                        &rx_length, 0);  // 0 = non-blocking
        if (rx_status == SECURE_API_SUCCESS && rx_length > 0) {
            // Process received command
            #ifdef ARDUINO
                Serial.printf("Received %zu bytes\n", rx_length);
            #endif
        }
        
        // Optional: Rotate keys periodically for Perfect Forward Secrecy
        static uint32_t last_key_rotation = 0;
        uint32_t now = my_get_tick_ms();
        if (now - last_key_rotation > 3600000) {  // Every hour
            if (secure_api_rotate_keys() == SECURE_API_SUCCESS) {
                #ifdef ARDUINO
                    Serial.println("Keys rotated successfully");
                #endif
                last_key_rotation = now;
            }
        }
        
    } else {
        // Not connected - API will auto-reconnect with exponential backoff
        // Device can enter low-power mode during reconnection attempts
        
        ConnectionState state = secure_api_get_state();
        switch (state) {
            case CONNECTION_STATE_DISCONNECTED:
                #ifdef ARDUINO
                    Serial.println("Disconnected");
                #endif
                break;
            case CONNECTION_STATE_CONNECTING:
                #ifdef ARDUINO
                    Serial.println("Connecting...");
                #endif
                break;
            case CONNECTION_STATE_AUTHENTICATING:
                #ifdef ARDUINO
                    Serial.println("Authenticating...");
                #endif
                break;
            case CONNECTION_STATE_RECONNECTING:
                #ifdef ARDUINO
                    Serial.println("Reconnecting (backing off)...");
                #endif
                break;
            default:
                break;
        }
    }
    
    // Small delay to prevent busy-looping
    my_delay_ms(100);
}

/* ============================================================================
 * ALTERNATIVE: Ultra-simple usage (minimum code)
 * ============================================================================ */

#if 0  // Uncomment for minimal example

void setup_minimal() {
    Serial.begin(115200);
    
    // Single line to initialize
    secure_api_init(&g_device_ctx, &g_crypto_hal, &g_network_hal, &g_power_hal);
}

void loop_minimal() {
    // Single line to handle everything
    secure_api_loop();
    
    // Single line to send data when ready
    if (SECURE_API_IS_READY()) {
        SECURE_API_SEND_SENSOR("temp", 25.0);
    }
}

#endif

/* ============================================================================
 * Platform-specific notes:
 * 
 * ESP32:
 * - Use esp_aes library for hardware-accelerated AES-GCM
 * - Use esp_hmac for hardware HMAC
 * - Use esp_fill_random() for TRNG
 * - Use WiFiClientSecure for TLS connections
 * 
 * STM32:
 * - Use HAL_CRYP for hardware crypto
 * - Use HAL_RNG for random numbers
 * - Use lwIP + mbedTLS for networking
 * 
 * Arduino AVR:
 * - Use AESLib for software AES (slower)
 * - Use mbedTLS or sha256 library
 * - Use Ethernet library or GSM shield
 * 
 * Nordic nRF52:
 * - Use nrf_crypto for hardware acceleration
 * - Use BLE or LTE libraries for connectivity
 * 
 * ============================================================================ */
