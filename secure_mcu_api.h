/**
 * @file secure_mcu_api.h
 * @brief World-Class Secure API for Tiny Microcontrollers
 * 
 * Features:
 * - Auto-connect with exponential backoff
 * - AES-256-GCM encryption (authenticated encryption)
 * - HMAC-SHA256 message authentication
 * - Perfect Forward Secrecy support
 * - Ultra-low power optimization
 * - Robust reconnection logic
 * - Simple 3-line integration
 * - Anti-replay protection
 * - Secure bootstrapping
 * 
 * Security Level: Production/Military Grade
 * Power Optimization: Sleep-mode aware
 */

#ifndef SECURE_MCU_API_H
#define SECURE_MCU_API_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION - Tune these for your specific MCU
 * ============================================================================ */

#ifndef SECURE_API_CONFIG_H
#define SECURE_API_CONFIG_H

// Device Identity (set unique per device in production)
#define DEVICE_ID_LENGTH        16
#define DEVICE_SECRET_LENGTH    32

// Cryptography Configuration
#define AES_KEY_LENGTH          32          // 256-bit
#define AES_IV_LENGTH           12          // 96-bit recommended for GCM
#define AES_TAG_LENGTH          16          // 128-bit authentication tag
#define HMAC_LENGTH             32          // SHA-256 output

// Buffer Sizes (optimize for your MCU's RAM)
#define MAX_PAYLOAD_SIZE        256
#define ENCRYPTED_BUFFER_SIZE   (MAX_PAYLOAD_SIZE + AES_TAG_LENGTH + AES_IV_LENGTH)
#define HTTP_HEADER_SIZE        512

// Connection Parameters
#define MAX_RECONNECT_ATTEMPTS  10
#define BASE_RECONNECT_DELAY_MS 1000
#define MAX_RECONNECT_DELAY_MS  60000
#define CONNECTION_TIMEOUT_MS   10000
#define HEARTBEAT_INTERVAL_MS   30000

// Power Management
#define ENABLE_LOW_POWER_MODE   1
#define SLEEP_BETWEEN_RETRY_MS  5000

// Security Features
#define ENABLE_ANTI_REPLAY      1
#define REPLAY_WINDOW_SIZE      100
#define ENABLE_PERFECT_FORWARD_SECRECY 1

#endif /* SECURE_API_CONFIG_H */

/* ============================================================================
 * TYPE DEFINITIONS
 * ============================================================================ */

typedef enum {
    SECURE_API_SUCCESS = 0,
    SECURE_API_ERROR_INIT,
    SECURE_API_ERROR_CRYPTO,
    SECURE_API_ERROR_NETWORK,
    SECURE_API_ERROR_AUTH,
    SECURE_API_ERROR_TIMEOUT,
    SECURE_API_ERROR_MEMORY,
    SECURE_API_ERROR_INVALID_PARAM,
    SECURE_API_ERROR_REPLAY_ATTACK,
    SECURE_API_ERROR_CONNECTION_LOST,
    SECURE_API_ERROR_MAX_RETRIES
} SecureAPIStatus;

typedef enum {
    CONNECTION_STATE_DISCONNECTED,
    CONNECTION_STATE_CONNECTING,
    CONNECTION_STATE_CONNECTED,
    CONNECTION_STATE_AUTHENTICATING,
    CONNECTION_STATE_AUTHENTICATED,
    CONNECTION_STATE_RECONNECTING
} ConnectionState;

typedef struct {
    uint8_t device_id[DEVICE_ID_LENGTH];
    uint8_t device_secret[DEVICE_SECRET_LENGTH];
    uint8_t aes_key[AES_KEY_LENGTH];
    uint32_t sequence_number;
    uint64_t last_timestamp;
} SecureDeviceContext;

typedef struct {
    ConnectionState state;
    uint32_t reconnect_attempts;
    uint32_t next_reconnect_time_ms;
    uint64_t last_heartbeat;
    uint32_t replay_window[REPLAY_WINDOW_SIZE / 32];
    bool network_available;
} SecureConnectionState;

/* ============================================================================
 * HARDWARE ABSTRACTION LAYER - Implement these for your MCU
 * ============================================================================ */

// Crypto Hardware Acceleration (if available)
typedef struct {
    SecureAPIStatus (*aes_gcm_encrypt)(const uint8_t* key, const uint8_t* iv,
                                        const uint8_t* plaintext, size_t pt_len,
                                        uint8_t* ciphertext, uint8_t* tag);
    SecureAPIStatus (*aes_gcm_decrypt)(const uint8_t* key, const uint8_t* iv,
                                        const uint8_t* ciphertext, size_t ct_len,
                                        const uint8_t* tag, uint8_t* plaintext);
    SecureAPIStatus (*sha256_hmac)(const uint8_t* key, size_t key_len,
                                    const uint8_t* data, size_t data_len,
                                    uint8_t* hmac);
    SecureAPIStatus (*random_generate)(uint8_t* buffer, size_t length);
    SecureAPIStatus (*secure_erase)(uint8_t* buffer, size_t length);
} CryptoHAL;

// Network Hardware Abstraction
typedef struct {
    SecureAPIStatus (*connect)(const char* host, uint16_t port, uint32_t timeout_ms);
    SecureAPIStatus (*disconnect)(void);
    SecureAPIStatus (*send)(const uint8_t* data, size_t length, uint32_t timeout_ms);
    SecureAPIStatus (*receive)(uint8_t* buffer, size_t max_length, 
                               size_t* received_length, uint32_t timeout_ms);
    bool (*is_connected)(void);
    bool (*network_available)(void);
} NetworkHAL;

// Power Management HAL
typedef struct {
    void (*enter_low_power)(void);
    void (*exit_low_power)(void);
    uint32_t (*get_tick_ms)(void);
    void (*delay_ms)(uint32_t ms);
} PowerHAL;

/* ============================================================================
 * CORE API FUNCTIONS - Simple 3-Line Integration
 * ============================================================================ */

/**
 * @brief Initialize the secure API (call once at startup)
 * @param ctx Device context with credentials
 * @param crypto_hal Crypto hardware abstraction
 * @param network_hal Network hardware abstraction  
 * @param power_hal Power management HAL
 * @return SECURE_API_SUCCESS on success
 * 
 * Example:
 *   SecureDeviceContext ctx = {0};
 *   secure_api_init(&ctx, &crypto_hal, &network_hal, &power_hal);
 */
SecureAPIStatus secure_api_init(SecureDeviceContext* ctx,
                                const CryptoHAL* crypto_hal,
                                const NetworkHAL* network_hal,
                                const PowerHAL* power_hal);

/**
 * @brief Auto-connect with exponential backoff (call in main loop)
 * @return SECURE_API_SUCCESS when connected
 * 
 * Example:
 *   if (secure_api_auto_connect() == SECURE_API_SUCCESS) {
 *       // Ready to send data
 *   }
 */
SecureAPIStatus secure_api_auto_connect(void);

/**
 * @brief Send encrypted and authenticated data
 * @param payload Data to send
 * @param length Length of data
 * @return SECURE_API_SUCCESS on success
 * 
 * Example:
 *   secure_api_send(sensor_data, sizeof(sensor_data));
 */
SecureAPIStatus secure_api_send(const uint8_t* payload, size_t length);

/**
 * @brief Receive and decrypt data
 * @param buffer Output buffer
 * @param max_length Maximum buffer size
 * @param received_length Actual received length
 * @param timeout_ms Timeout in milliseconds
 * @return SECURE_API_SUCCESS on success
 */
SecureAPIStatus secure_api_receive(uint8_t* buffer, size_t max_length,
                                   size_t* received_length, uint32_t timeout_ms);

/**
 * @brief Check connection status
 * @return true if connected and authenticated
 */
bool secure_api_is_connected(void);

/**
 * @brief Gracefully disconnect
 */
void secure_api_disconnect(void);

/**
 * @brief Main loop handler (call regularly)
 * Handles reconnection, heartbeats, and power management
 */
void secure_api_loop(void);

/* ============================================================================
 * ADVANCED SECURITY FUNCTIONS
 * ============================================================================ */

/**
 * @brief Generate new session keys (Perfect Forward Secrecy)
 */
SecureAPIStatus secure_api_rotate_keys(void);

/**
 * @brief Securely wipe sensitive data from memory
 */
void secure_api_secure_wipe(void* ptr, size_t size);

/**
 * @brief Validate message authenticity and prevent replay attacks
 */
bool secure_api_validate_message(const uint8_t* message, size_t length,
                                 uint64_t timestamp, uint32_t sequence);

/**
 * @brief Get current connection state
 */
ConnectionState secure_api_get_state(void);

/**
 * @brief Get detailed error information
 */
const char* secure_api_get_error_string(SecureAPIStatus status);

/* ============================================================================
 * UTILITY MACROS FOR SIMPLE INTEGRATION
 * ============================================================================ */

#define SECURE_API_SEND_JSON(json_str) \
    secure_api_send((const uint8_t*)(json_str), strlen(json_str))

#define SECURE_API_SEND_SENSOR(type, value) do { \
    char buf[64]; \
    snprintf(buf, sizeof(buf), "{\"type\":\"%s\",\"value\":%f}", type, value); \
    secure_api_send((const uint8_t*)buf, strlen(buf)); \
} while(0)

#define SECURE_API_IS_READY() (secure_api_is_connected())

/* ============================================================================
 * EXAMPLE USAGE (Copy-Paste Template)
 * ============================================================================ */

#if 0  // Comment out to hide from compilation

// STEP 1: Define your credentials (store in secure element/OTP memory)
static SecureDeviceContext g_device_ctx = {
    .device_id = {0x01, 0x02, ...},  // Unique per device
    .device_secret = {...},           // Manufacturing secret
    .aes_key = {...}                  // Pre-shared or derived
};

// STEP 2: Implement HAL functions for your MCU
static CryptoHAL g_crypto_hal = {
    .aes_gcm_encrypt = my_aes_encrypt,
    .aes_gcm_decrypt = my_aes_decrypt,
    .sha256_hmac = my_hmac_sha256,
    .random_generate = my_random,
    .secure_erase = my_secure_erase
};

static NetworkHAL g_network_hal = {
    .connect = my_wifi_connect,
    .disconnect = my_wifi_disconnect,
    .send = my_wifi_send,
    .receive = my_wifi_receive,
    .is_connected = my_wifi_is_connected,
    .network_available = my_wifi_available
};

static PowerHAL g_power_hal = {
    .enter_low_power = my_enter_sleep,
    .exit_low_power = my_exit_sleep,
    .get_tick_ms = my_get_ticks,
    .delay_ms = my_delay_ms
};

// STEP 3: Initialize in setup()
void setup() {
    secure_api_init(&g_device_ctx, &g_crypto_hal, &g_network_hal, &g_power_hal);
}

// STEP 4: Call in main loop
void loop() {
    secure_api_loop();  // Handles auto-connect, heartbeats, power
    
    if (SECURE_API_IS_READY()) {
        // Send sensor data
        SECURE_API_SEND_SENSOR("temperature", 23.5);
        
        // Or send custom JSON
        SECURE_API_SEND_JSON("{\"event\":\"alert\",\"priority\":1}");
    }
    
    // Low-power sleep if needed
    if (!secure_api_is_connected()) {
        g_power_hal.enter_low_power();
    }
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* SECURE_MCU_API_H */
