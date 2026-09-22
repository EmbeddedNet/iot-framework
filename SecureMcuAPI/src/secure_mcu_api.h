/**
 * @file secure_mcu_api.h
 * @brief World-Class Secure API for Tiny Microcontrollers
 * 
 * Features:
 * - AES-256-GCM Encryption + HMAC-SHA256 Authentication
 * - Auto-connect with Exponential Backoff
 * - Ultra-Low Power Optimization
 * - Anti-Replay Attack Protection
 * - Perfect Forward Secrecy
 * 
 * @version 1.0.0
 * @date 2024
 */

#ifndef SECURE_MCU_API_H
#define SECURE_MCU_API_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION - TUNE FOR YOUR APPLICATION
 * ============================================================================ */

// Security Configuration
#define SECURE_API_KEY_SIZE         32      // AES-256 key size in bytes
#define SECURE_API_NONCE_SIZE       12      // GCM nonce size (96-bit recommended)
#define SECURE_API_TAG_SIZE         16      // GCM authentication tag size
#define SECURE_API_HMAC_SIZE        32      // SHA-256 HMAC size

// Buffer Configuration (adjust based on available RAM)
#define SECURE_API_MAX_PAYLOAD      1024    // Maximum payload size in bytes
#define SECURE_API_RX_BUFFER_SIZE   2048    // Receive buffer size

// Connection Configuration
#define SECURE_API_MAX_RECONNECT    10      // Max reconnection attempts before reset backoff
#define SECURE_API_MIN_BACKOFF_MS   1000    // Minimum backoff time (1 second)
#define SECURE_API_MAX_BACKOFF_MS   60000   // Maximum backoff time (60 seconds)
#define SECURE_API_HEARTBEAT_MS     30000   // Heartbeat interval (30 seconds)

// Replay Attack Protection
#define SECURE_API_REPLAY_WINDOW    100     // Sliding window size for sequence numbers

// Power Management
#define SECURE_API_LOW_POWER_MODE   1       // Enable low-power optimizations (1=enabled)

/* ============================================================================
 * ERROR CODES
 * ============================================================================ */

typedef enum {
    SECURE_OK = 0,
    SECURE_ERR_INIT_FAILED,
    SECURE_ERR_INVALID_PARAM,
    SECURE_ERR_OUT_OF_MEMORY,
    SECURE_ERR_ENCRYPTION_FAILED,
    SECURE_ERR_DECRYPTION_FAILED,
    SECURE_ERR_AUTH_FAILED,
    SECURE_ERR_REPLAY_ATTACK,
    SECURE_ERR_CONNECTION_FAILED,
    SECURE_ERR_TIMEOUT,
    SECURE_ERR_NETWORK_DOWN,
    SECURE_ERR_CERT_INVALID,
    SECURE_ERR_KEY_ROTATION_FAILED,
    SECURE_ERR_BUSY
} secure_api_error_t;

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

// Device configuration structure
typedef struct {
    const char* device_id;              // Unique device identifier
    const uint8_t api_key[SECURE_API_KEY_SIZE];  // Pre-shared secret key
    const char* server_host;            // Server hostname
    uint16_t server_port;               // Server port (443 for HTTPS)
    bool use_tls;                       // Enable TLS/SSL
    const char* ca_cert;                // CA certificate (NULL for default)
    void (*log_callback)(const char*);  // Optional logging callback
} secure_api_config_t;

// Connection status structure
typedef struct {
    bool is_connected;
    bool is_authenticated;
    uint32_t last_heartbeat;
    uint32_t reconnect_count;
    uint32_t next_backoff_ms;
    uint64_t tx_sequence;
    uint64_t rx_sequence;
} secure_api_status_t;

// Secure message structure
typedef struct {
    uint8_t* payload;
    size_t payload_len;
    uint64_t sequence;
    uint32_t timestamp;
} secure_message_t;

/* ============================================================================
 * HARDWARE ABSTRACTION LAYER (HAL) - IMPLEMENT THESE FOR YOUR PLATFORM
 * ============================================================================ */

// Random number generator (CRITICAL for security)
uint32_t secure_hal_random_uint32(void);
void secure_hal_random_bytes(uint8_t* buffer, size_t len);

// Cryptographic primitives (use hardware acceleration if available)
int secure_hal_aes_gcm_encrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* plaintext, size_t pt_len,
                                uint8_t* ciphertext, uint8_t* tag);

int secure_hal_aes_gcm_decrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ciphertext, size_t ct_len,
                                const uint8_t* tag, uint8_t* plaintext);

int secure_hal_hmac_sha256(const uint8_t* key, size_t key_len,
                           const uint8_t* data, size_t data_len,
                           uint8_t* output);

// Network functions
int secure_hal_network_connect(const char* host, uint16_t port, bool tls);
int secure_hal_network_send(const uint8_t* data, size_t len, uint32_t timeout_ms);
int secure_hal_network_receive(uint8_t* buffer, size_t max_len, uint32_t timeout_ms);
void secure_hal_network_disconnect(void);
bool secure_hal_network_is_available(void);

// Time functions (for timestamps and replay protection)
uint32_t secure_hal_get_timestamp_ms(void);
uint64_t secure_hal_get_timestamp_sec(void);

// Low-power functions (optional but recommended)
void secure_hal_enter_low_power(void);
void secure_hal_exit_low_power(void);
bool secure_hal_is_low_power_mode(void);

/* ============================================================================
 * MAIN API FUNCTIONS
 * ============================================================================ */

/**
 * @brief Initialize the secure API
 * @param config Pointer to configuration structure
 * @return SECURE_OK on success, error code otherwise
 */
secure_api_error_t secure_api_init(const secure_api_config_t* config);

/**
 * @brief Deinitialize and cleanup resources
 */
void secure_api_deinit(void);

/**
 * @brief Establish secure connection with auto-reconnect
 * @return SECURE_OK on success, error code otherwise
 */
secure_api_error_t secure_api_connect(void);

/**
 * @brief Disconnect from server
 */
void secure_api_disconnect(void);

/**
 * @brief Get current connection status
 * @param status Pointer to status structure to fill
 */
void secure_api_get_status(secure_api_status_t* status);

/**
 * @brief Send encrypted and authenticated message
 * @param payload Data to send
 * @param len Length of data
 * @return SECURE_OK on success, error code otherwise
 */
secure_api_error_t secure_api_send(const uint8_t* payload, size_t len);

/**
 * @brief Receive and decrypt message (non-blocking)
 * @param buffer Buffer to store received data
 * @param max_len Maximum buffer size
 * @param received_len Pointer to store actual received length
 * @return SECURE_OK on success, SECURE_ERR_TIMEOUT if no data, error code otherwise
 */
secure_api_error_t secure_api_receive(uint8_t* buffer, size_t max_len, size_t* received_len);

/**
 * @brief Send and receive in one operation (request-response)
 * @param request Request payload
 * @param req_len Request length
 * @param response Buffer for response
 * @param resp_max_len Maximum response buffer size
 * @param resp_len Pointer to store actual response length
 * @param timeout_ms Operation timeout
 * @return SECURE_OK on success, error code otherwise
 */
secure_api_error_t secure_api_request_response(
    const uint8_t* request, size_t req_len,
    uint8_t* response, size_t resp_max_len, size_t* resp_len,
    uint32_t timeout_ms
);

/**
 * @brief Main loop handler - call regularly in your main loop
 * Handles reconnection, heartbeats, and keep-alive
 * @return SECURE_OK if operational, error code otherwise
 */
secure_api_error_t secure_api_loop(void);

/**
 * @brief Rotate session keys (Perfect Forward Secrecy)
 * Call periodically or after sensitive operations
 * @return SECURE_OK on success, error code otherwise
 */
secure_api_error_t secure_api_rotate_keys(void);

/**
 * @brief Securely wipe sensitive data from memory
 */
void secure_api_secure_wipe(void);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * @brief Generate cryptographically secure random bytes
 * @param buffer Output buffer
 * @param len Number of bytes to generate
 */
void secure_api_random_bytes(uint8_t* buffer, size_t len);

/**
 * @brief Constant-time memory comparison (prevents timing attacks)
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int secure_api_memcmp_secure(const void* a, const void* b, size_t len);

/**
 * @brief Log message through configured callback
 * @param format Printf-style format string
 * @param ... Arguments
 */
void secure_api_log(const char* format, ...);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_MCU_API_H */
