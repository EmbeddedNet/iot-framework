# Secure MCU API

**World-Class Secure Communication Library for Tiny Microcontrollers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-ESP32%20%7C%20Arduino%20%7C%20STM32%20%7C%20FreeRTOS-blue)]()
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20HMAC--SHA256-green)]()

## 🚀 Features

### Security First
- **AES-256-GCM Encryption** - Military-grade authenticated encryption
- **HMAC-SHA256 Authentication** - Prevents message tampering
- **Anti-Replay Protection** - Sliding window sequence validation
- **Perfect Forward Secrecy** - Automatic key rotation
- **Constant-Time Operations** - Prevents timing attacks
- **Secure Memory Wiping** - No sensitive data left in RAM

### Ultra-Low Power
- Optimized for battery-operated devices (<10µA sleep current)
- Automatic sleep mode integration
- Configurable transmission intervals
- Hardware crypto acceleration support

### Auto-Connect & Robust
- Exponential backoff reconnection (1s to 60s)
- Automatic heartbeat maintenance
- Network availability detection
- Graceful degradation and recovery

### Simple Integration
- **3-line initialization**
- Platform-agnostic HAL interface
- Works with ESP32, Arduino, STM32, Nordic nRF52, RP2040
- FreeRTOS ready

## 📦 Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Flash    | 15 KB   | 32 KB       |
| RAM      | 2 KB    | 8 KB        |
| CPU      | 16 MHz  | 80+ MHz     |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Your Application                    │
├─────────────────────────────────────────────────────┤
│              Secure MCU API (this library)           │
│  ┌──────────┬──────────┬──────────┬──────────────┐  │
│  │ AES-256  │  HMAC    │  Replay  │   Auto-      │  │
│  │   GCM    │  SHA256  │ Protection│  Connect     │  │
│  └──────────┴──────────┴──────────┴──────────────┘  │
├─────────────────────────────────────────────────────┤
│           Hardware Abstraction Layer (HAL)           │
│  ┌──────────┬──────────┬──────────┬──────────────┐  │
│  │  Crypto  │ Network  │  Random  │    Power     │  │
│  │  Primitives         │   Number │   Management │  │
│  └──────────┴──────────┴──────────┴──────────────┘  │
├─────────────────────────────────────────────────────┤
│              Platform (ESP32/STM32/etc)              │
└─────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
SecureMcuAPI/
├── src/
│   ├── secure_mcu_api.h      # Main header file
│   └── secure_mcu_api.c      # Implementation
├── examples/
│   ├── Basic_AutoConnect/    # ESP32/Arduino simple example
│   ├── FreeRTOS_SecureTask/  # FreeRTOS multi-task example
│   └── STM32_LowPower/       # STM32 ultra-low-power example
└── README.md
```

## ⚡ Quick Start (ESP32/Arduino)

### 1. Install Dependencies
```bash
# For PlatformIO
pio lib install "mbedtls"

# For Arduino IDE: Install ESP32 board package
```

### 2. Copy Files
Copy `src/secure_mcu_api.h` and `src/secure_mcu_api.c` to your sketch folder.

### 3. Configure and Run
```cpp
#include <Arduino.h>
#include <WiFi.h>
#include "secure_mcu_api.h"

// Configuration
const char* DEVICE_ID = "my_device_001";
const char* SERVER_HOST = "api.example.com";
const uint16_t SERVER_PORT = 443;
const uint8_t API_KEY[32] = { /* your 32-byte secret key */ };

void log_msg(const char* msg) { Serial.println(msg); }

void setup() {
    Serial.begin(115200);
    WiFi.begin("SSID", "PASSWORD");
    
    // Wait for WiFi
    while (WiFi.status() != WL_CONNECTED) delay(500);
    
    // Initialize secure API
    secure_api_config_t config = {
        .device_id = DEVICE_ID,
        .api_key = API_KEY,
        .server_host = SERVER_HOST,
        .server_port = SERVER_PORT,
        .use_tls = true,
        .log_callback = log_msg
    };
    
    secure_api_init(&config);
}

void loop() {
    // Auto-connect and maintain connection
    secure_api_loop();
    
    secure_api_status_t status;
    secure_api_get_status(&status);
    
    if (status.is_connected) {
        // Send encrypted data
        const char* payload = "{\"sensor\":25.5}";
        secure_api_send((uint8_t*)payload, strlen(payload));
        
        // Receive messages
        uint8_t rx[256];
        size_t rx_len;
        if (secure_api_receive(rx, sizeof(rx), &rx_len) == SECURE_OK) {
            // Process received command
        }
    }
    
    delay(60000); // Send every minute
}
```

## 🔧 HAL Implementation Guide

You must implement these functions for your platform:

### Random Number Generator (CRITICAL)
```c
uint32_t secure_hal_random_uint32(void) {
    return hardware_rng_read(); // Use hardware RNG!
}

void secure_hal_random_bytes(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t val = secure_hal_random_uint32();
        memcpy(buffer + i, &val, min(4, len - i));
    }
}
```

### Cryptographic Primitives
```c
// Use hardware acceleration when available (mbedtls fallback)
int secure_hal_aes_gcm_encrypt(...) {
    // Implement AES-256-GCM encryption
}

int secure_hal_aes_gcm_decrypt(...) {
    // Implement AES-256-GCM decryption with authentication
}

int secure_hal_hmac_sha256(...) {
    // Implement HMAC-SHA256
}
```

### Network Functions
```c
int secure_hal_network_connect(const char* host, uint16_t port, bool tls) {
    // Connect to server (TLS if enabled)
}

int secure_hal_network_send(const uint8_t* data, size_t len, uint32_t timeout_ms) {
    // Send data over network
}

int secure_hal_network_receive(uint8_t* buffer, size_t max_len, uint32_t timeout_ms) {
    // Receive data (non-blocking if timeout_ms=0)
}

void secure_hal_network_disconnect(void) {
    // Close connection
}

bool secure_hal_network_is_available(void) {
    // Check if network is available
}
```

### Time Functions
```c
uint32_t secure_hal_get_timestamp_ms(void) {
    return millis(); // Or hardware timer
}

uint64_t secure_hal_get_timestamp_sec(void) {
    return time(NULL); // Unix timestamp
}
```

### Low-Power Functions (Optional)
```c
void secure_hal_enter_low_power(void) {
    // Enter sleep/stop mode
}

void secure_hal_exit_low_power(void) {
    // Wakeup handling
}

bool secure_hal_is_low_power_mode(void) {
    return true; // If device should sleep
}
```

## 🔒 Security Best Practices

### 1. Key Management
```c
// NEVER hardcode keys in production!
// Store in:
// - Secure element (ATECC608A, etc.)
// - Encrypted flash
// - OTP memory
// - Provisioned during manufacturing

const uint8_t API_KEY[32] = { /* from secure storage */ };
```

### 2. Key Rotation
```c
// Rotate keys periodically for perfect forward secrecy
static int message_count = 0;
if (++message_count % 100 == 0) {
    secure_api_rotate_keys();
}
```

### 3. Secure Boot
Enable secure boot on your MCU to prevent firmware tampering.

### 4. Debug Disable
Disable JTAG/SWD in production firmware.

## 📊 Message Format

Each message is authenticated and encrypted:

```
┌──────────┬───────────┬────────┬────────────┬──────────┬────────┐
│ Sequence │ Timestamp │ Nonce  │ Ciphertext │   Tag    │  HMAC  │
│  8 bytes │ 4 bytes   │12 bytes│  N bytes   │ 16 bytes │32 bytes│
└──────────┴───────────┴────────┴────────────┴──────────┴────────┘
```

## 🎯 Example Applications

### Environmental Sensor
```cpp
float temp = read_temperature();
char payload[64];
snprintf(payload, sizeof(payload), "{\"t\":%.2f}", temp);
secure_api_send((uint8_t*)payload, strlen(payload));
```

### Smart Lock
```cpp
// Receive unlock command
uint8_t rx[256];
size_t len;
if (secure_api_receive(rx, sizeof(rx), &len) == SECURE_OK) {
    if (strstr((char*)rx, "\"unlock\":true")) {
        unlock_door();
    }
}
```

### Asset Tracker
```cpp
// Send GPS location every 5 minutes
gps_data_t gps = get_gps();
secure_api_send((uint8_t*)&gps, sizeof(gps));
secure_hal_enter_low_power(); // Sleep between transmissions
```

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection fails | Check WiFi/network, verify server host/port |
| Authentication failed | Verify API key matches server, check clock sync |
| High power consumption | Enable `SECURE_API_LOW_POWER_MODE`, increase interval |
| Memory errors | Reduce `SECURE_API_MAX_PAYLOAD` buffer size |
| Random number issues | Ensure hardware RNG is initialized |

## 📝 API Reference

### Core Functions
- `secure_api_init()` - Initialize the library
- `secure_api_deinit()` - Cleanup and wipe secrets
- `secure_api_connect()` - Establish connection
- `secure_api_disconnect()` - Close connection
- `secure_api_loop()` - Main loop handler (call regularly)
- `secure_api_send()` - Send encrypted message
- `secure_api_receive()` - Receive and decrypt message
- `secure_api_rotate_keys()` - Generate new session keys

### Utility Functions
- `secure_api_get_status()` - Get connection status
- `secure_api_secure_wipe()` - Clear all secrets from memory
- `secure_api_log()` - Log message via callback

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please ensure:
1. Code follows existing style
2. All security features are preserved
3. Examples tested on real hardware
4. Documentation updated

## 🔗 Resources

- [ESP32 mbedtls Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/protocols/mbedtls.html)
- [STM32 Crypto Libraries](https://www.st.com/en/embedded-software/stm32cubeexpansion-crypto-all.html)
- [FreeRTOS Official Site](https://www.freertos.org/)
- [NIST AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

**Built with ❤️ for secure IoT**

*Remember: Security is a process, not a product. Always keep your firmware updated!*
