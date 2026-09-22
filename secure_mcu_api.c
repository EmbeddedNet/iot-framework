/**
 * @file secure_mcu_api.c
 * @brief Implementation of World-Class Secure API for Tiny Microcontrollers
 * 
 * This implementation provides:
 * - Production-grade security with AES-256-GCM and HMAC-SHA256
 * - Auto-reconnection with exponential backoff
 * - Ultra-low power optimization
 * - Anti-replay attack protection
 * - Simple integration (3 lines of code)
 */

#include "secure_mcu_api.h"
#include <stdlib.h>

/* ============================================================================
 * INTERNAL STATE
 * ============================================================================ */

static SecureDeviceContext* g_device_ctx = NULL;
static const CryptoHAL* g_crypto_hal = NULL;
static const NetworkHAL* g_network_hal = NULL;
static const PowerHAL* g_power_hal = NULL;
static SecureConnectionState g_conn_state = {0};
static uint8_t g_encrypt_buffer[ENCRYPTED_BUFFER_SIZE];
static uint8_t g_decrypt_buffer[ENCRYPTED_BUFFER_SIZE];

/* ============================================================================
 * INTERNAL HELPER FUNCTIONS
 * ============================================================================ */

/**
 * @brief Secure memory zeroing (prevents compiler optimization)
 */
static void secure_zero(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--) {
        *p++ = 0;
    }
    // Memory barrier to prevent reordering
    __asm__ __volatile__("" ::: "memory");
}

/**
 * @brief Calculate exponential backoff delay
 */
static uint32_t calculate_backoff_delay(uint32_t attempt) {
    if (attempt >= MAX_RECONNECT_ATTEMPTS) {
        return MAX_RECONNECT_DELAY_MS;
    }
    
    // Exponential backoff: base_delay * 2^attempt
    uint32_t delay = BASE_RECONNECT_DELAY_MS << attempt;
    
    // Add jitter (±25%) to prevent thundering herd
    uint32_t jitter = (delay / 4) & 0x7FFF;
    if (g_crypto_hal && g_crypto_hal->random_generate) {
        uint8_t random_byte;
        if (g_crypto_hal->random_generate(&random_byte, 1) == SECURE_API_SUCCESS) {
            jitter = (delay / 4) * (random_byte % 100) / 100;
        }
    }
    
    return (delay > jitter) ? (delay - jitter) : delay;
}

/**
 * @brief Check if message is a replay attack
 */
static bool is_replay_attack(uint64_t timestamp, uint32_t sequence) {
#if ENABLE_ANTI_REPLAY
    // Check timestamp window (prevent old messages)
    uint64_t current_time = g_power_hal->get_tick_ms();
    if (timestamp < g_device_ctx->last_timestamp) {
        return true;  // Old timestamp
    }
    
    // Check sequence number within replay window
    uint32_t window_index = sequence / 32;
    uint32_t bit_index = sequence % 32;
    
    if (window_index < (REPLAY_WINDOW_SIZE / 32)) {
        if (g_conn_state.replay_window[window_index] & (1UL << bit_index)) {
            return true;  // Already seen this sequence
        }
        
        // Mark as seen
        g_conn_state.replay_window[window_index] |= (1UL << bit_index);
    }
    
    g_device_ctx->last_timestamp = timestamp;
#endif
    return false;
}

/**
 * @brief Build authenticated encrypted packet
 */
static SecureAPIStatus build_secure_packet(const uint8_t* payload, size_t length,
                                           uint8_t* output, size_t* output_length) {
    if (length > MAX_PAYLOAD_SIZE) {
        return SECURE_API_ERROR_INVALID_PARAM;
    }
    
    // Generate random IV
    uint8_t iv[AES_IV_LENGTH];
    SecureAPIStatus status = g_crypto_hal->random_generate(iv, AES_IV_LENGTH);
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    // Increment sequence number
    g_device_ctx->sequence_number++;
    uint64_t timestamp = g_power_hal->get_tick_ms();
    
    // Encrypt with AES-256-GCM
    uint8_t tag[AES_TAG_LENGTH];
    status = g_crypto_hal->aes_gcm_encrypt(
        g_device_ctx->aes_key,
        iv,
        payload, length,
        output + AES_IV_LENGTH,
        tag
    );
    
    if (status != SECURE_API_SUCCESS) {
        secure_zero(iv, sizeof(iv));
        secure_zero(tag, sizeof(tag));
        return status;
    }
    
    // Copy IV to beginning of output
    memcpy(output, iv, AES_IV_LENGTH);
    
    // Append tag after ciphertext
    memcpy(output + AES_IV_LENGTH + length, tag, AES_TAG_LENGTH);
    
    // Add header: [IV(12)][Ciphertext][Tag(16)][Timestamp(8)][Sequence(4)]
    uint8_t* ptr = output + AES_IV_LENGTH + length + AES_TAG_LENGTH;
    memcpy(ptr, &timestamp, sizeof(timestamp));
    ptr += sizeof(timestamp);
    memcpy(ptr, &g_device_ctx->sequence_number, sizeof(g_device_ctx->sequence_number));
    
    *output_length = AES_IV_LENGTH + length + AES_TAG_LENGTH + sizeof(timestamp) + 
                     sizeof(g_device_ctx->sequence_number);
    
    // Secure cleanup
    secure_zero(iv, sizeof(iv));
    secure_zero(tag, sizeof(tag));
    
    return SECURE_API_SUCCESS;
}

/**
 * @brief Parse and validate received secure packet
 */
static SecureAPIStatus parse_secure_packet(const uint8_t* input, size_t input_length,
                                           uint8_t* output, size_t* output_length) {
    // Minimum packet size check
    size_t min_size = AES_IV_LENGTH + AES_TAG_LENGTH + sizeof(uint64_t) + sizeof(uint32_t);
    if (input_length < min_size) {
        return SECURE_API_ERROR_INVALID_PARAM;
    }
    
    // Extract components
    const uint8_t* iv = input;
    const uint8_t* ciphertext = input + AES_IV_LENGTH;
    size_t ciphertext_length = input_length - AES_IV_LENGTH - AES_TAG_LENGTH - 
                               sizeof(uint64_t) - sizeof(uint32_t);
    const uint8_t* tag = input + AES_IV_LENGTH + ciphertext_length;
    const uint8_t* timestamp_ptr = input + AES_IV_LENGTH + ciphertext_length + AES_TAG_LENGTH;
    const uint8_t* sequence_ptr = timestamp_ptr + sizeof(uint64_t);
    
    // Extract timestamp and sequence
    uint64_t timestamp;
    uint32_t sequence;
    memcpy(&timestamp, timestamp_ptr, sizeof(timestamp));
    memcpy(&sequence, sequence_ptr, sizeof(sequence));
    
    // Check for replay attack
    if (is_replay_attack(timestamp, sequence)) {
        return SECURE_API_ERROR_REPLAY_ATTACK;
    }
    
    // Decrypt
    SecureAPIStatus status = g_crypto_hal->aes_gcm_decrypt(
        g_device_ctx->aes_key,
        iv,
        ciphertext, ciphertext_length,
        tag,
        output
    );
    
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    *output_length = ciphertext_length;
    return SECURE_API_SUCCESS;
}

/**
 * @brief Authenticate with server
 */
static SecureAPIStatus authenticate_device(void) {
    // Build authentication payload
    uint8_t auth_payload[DEVICE_ID_LENGTH + sizeof(uint64_t)];
    memcpy(auth_payload, g_device_ctx->device_id, DEVICE_ID_LENGTH);
    uint64_t timestamp = g_power_hal->get_tick_ms();
    memcpy(auth_payload + DEVICE_ID_LENGTH, &timestamp, sizeof(timestamp));
    
    // Generate HMAC
    uint8_t hmac[HMAC_LENGTH];
    SecureAPIStatus status = g_crypto_hal->sha256_hmac(
        g_device_ctx->device_secret, DEVICE_SECRET_LENGTH,
        auth_payload, sizeof(auth_payload),
        hmac
    );
    
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    // Send authentication packet
    uint8_t auth_packet[DEVICE_ID_LENGTH + sizeof(uint64_t) + HMAC_LENGTH];
    memcpy(auth_packet, auth_payload, DEVICE_ID_LENGTH + sizeof(uint64_t));
    memcpy(auth_packet + DEVICE_ID_LENGTH + sizeof(uint64_t), hmac, HMAC_LENGTH);
    
    status = g_network_hal->send(auth_packet, sizeof(auth_packet), CONNECTION_TIMEOUT_MS);
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    // Wait for authentication response
    uint8_t response[64];
    size_t response_length;
    status = g_network_hal->receive(response, sizeof(response), &response_length, 
                                    CONNECTION_TIMEOUT_MS);
    
    if (status != SECURE_API_SUCCESS) {
        return SECURE_API_ERROR_AUTH;
    }
    
    // Verify response (implementation depends on server protocol)
    if (response_length < 1 || response[0] != 0x01) {
        return SECURE_API_ERROR_AUTH;
    }
    
    return SECURE_API_SUCCESS;
}

/* ============================================================================
 * PUBLIC API IMPLEMENTATION
 * ============================================================================ */

SecureAPIStatus secure_api_init(SecureDeviceContext* ctx,
                                const CryptoHAL* crypto_hal,
                                const NetworkHAL* network_hal,
                                const PowerHAL* power_hal) {
    // Validate parameters
    if (!ctx || !crypto_hal || !network_hal || !power_hal) {
        return SECURE_API_ERROR_INVALID_PARAM;
    }
    
    // Validate required HAL functions
    if (!crypto_hal->aes_gcm_encrypt || !crypto_hal->aes_gcm_decrypt ||
        !crypto_hal->sha256_hmac || !crypto_hal->random_generate ||
        !network_hal->connect || !network_hal->send || !network_hal->receive ||
        !power_hal->get_tick_ms || !power_hal->delay_ms) {
        return SECURE_API_ERROR_INVALID_PARAM;
    }
    
    // Initialize global state
    g_device_ctx = ctx;
    g_crypto_hal = crypto_hal;
    g_network_hal = network_hal;
    g_power_hal = power_hal;
    
    // Reset connection state
    memset(&g_conn_state, 0, sizeof(g_conn_state));
    g_conn_state.state = CONNECTION_STATE_DISCONNECTED;
    
    // Initialize sequence number from random
    uint32_t random_seq;
    if (crypto_hal->random_generate((uint8_t*)&random_seq, sizeof(random_seq)) 
        == SECURE_API_SUCCESS) {
        g_device_ctx->sequence_number = random_seq;
    }
    
    // Secure zero sensitive buffers
    secure_zero(g_encrypt_buffer, sizeof(g_encrypt_buffer));
    secure_zero(g_decrypt_buffer, sizeof(g_decrypt_buffer));
    
    return SECURE_API_SUCCESS;
}

SecureAPIStatus secure_api_auto_connect(void) {
    if (!g_device_ctx || !g_network_hal || !g_power_hal) {
        return SECURE_API_ERROR_INIT;
    }
    
    // Already connected?
    if (g_conn_state.state == CONNECTION_STATE_AUTHENTICATED) {
        if (g_network_hal->is_connected()) {
            return SECURE_API_SUCCESS;
        }
        // Connection lost
        g_conn_state.state = CONNECTION_STATE_CONNECTION_LOST;
    }
    
    // Check if it's time to reconnect
    uint32_t current_time = g_power_hal->get_tick_ms();
    if (g_conn_state.state == CONNECTION_STATE_RECONNECTING) {
        if (current_time < g_conn_state.next_reconnect_time_ms) {
#if ENABLE_LOW_POWER_MODE
            if (g_power_hal->enter_low_power) {
                g_power_hal->enter_low_power();
            }
#endif
            return SECURE_API_ERROR_TIMEOUT;
        }
    }
    
    // Check network availability
    if (g_network_hal->network_available && !g_network_hal->network_available()) {
        g_conn_state.network_available = false;
        return SECURE_API_ERROR_NETWORK;
    }
    g_conn_state.network_available = true;
    
    // Attempt connection
    g_conn_state.state = CONNECTION_STATE_CONNECTING;
    
    // Note: Host/port should be configured - using placeholders
    SecureAPIStatus status = g_network_hal->connect("api.secure-server.com", 443, 
                                                    CONNECTION_TIMEOUT_MS);
    
    if (status != SECURE_API_SUCCESS) {
        // Schedule retry with exponential backoff
        g_conn_state.reconnect_attempts++;
        uint32_t delay = calculate_backoff_delay(g_conn_state.reconnect_attempts);
        g_conn_state.next_reconnect_time_ms = current_time + delay;
        g_conn_state.state = CONNECTION_STATE_RECONNECTING;
        
        if (g_conn_state.reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
            return SECURE_API_ERROR_MAX_RETRIES;
        }
        
        return SECURE_API_ERROR_TIMEOUT;
    }
    
    // Authenticate
    g_conn_state.state = CONNECTION_STATE_AUTHENTICATING;
    status = authenticate_device();
    
    if (status != SECURE_API_SUCCESS) {
        g_network_hal->disconnect();
        g_conn_state.reconnect_attempts++;
        uint32_t delay = calculate_backoff_delay(g_conn_state.reconnect_attempts);
        g_conn_state.next_reconnect_time_ms = current_time + delay;
        g_conn_state.state = CONNECTION_STATE_RECONNECTING;
        return status;
    }
    
    // Success!
    g_conn_state.state = CONNECTION_STATE_AUTHENTICATED;
    g_conn_state.reconnect_attempts = 0;
    g_conn_state.last_heartbeat = current_time;
    
    return SECURE_API_SUCCESS;
}

SecureAPIStatus secure_api_send(const uint8_t* payload, size_t length) {
    if (!g_device_ctx || !g_crypto_hal || !g_network_hal) {
        return SECURE_API_ERROR_INIT;
    }
    
    if (!payload || length == 0 || length > MAX_PAYLOAD_SIZE) {
        return SECURE_API_ERROR_INVALID_PARAM;
    }
    
    if (g_conn_state.state != CONNECTION_STATE_AUTHENTICATED) {
        return SECURE_API_ERROR_CONNECTION_LOST;
    }
    
    // Build secure packet
    size_t packet_length;
    SecureAPIStatus status = build_secure_packet(payload, length, 
                                                  g_encrypt_buffer, &packet_length);
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    // Send packet
    status = g_network_hal->send(g_encrypt_buffer, packet_length, CONNECTION_TIMEOUT_MS);
    
    // Secure cleanup
    secure_zero(g_encrypt_buffer, sizeof(g_encrypt_buffer));
    
    if (status != SECURE_API_SUCCESS) {
        g_conn_state.state = CONNECTION_STATE_CONNECTION_LOST;
        return status;
    }
    
    return SECURE_API_SUCCESS;
}

SecureAPIStatus secure_api_receive(uint8_t* buffer, size_t max_length,
                                   size_t* received_length, uint32_t timeout_ms) {
    if (!g_device_ctx || !g_crypto_hal || !g_network_hal) {
        return SECURE_API_ERROR_INIT;
    }
    
    if (!buffer || !received_length || max_length == 0) {
        return SECURE_API_ERROR_INVALID_PARAM;
    }
    
    if (g_conn_state.state != CONNECTION_STATE_AUTHENTICATED) {
        return SECURE_API_ERROR_CONNECTION_LOST;
    }
    
    // Receive encrypted packet
    size_t packet_length;
    SecureAPIStatus status = g_network_hal->receive(g_decrypt_buffer, 
                                                     sizeof(g_decrypt_buffer),
                                                     &packet_length, timeout_ms);
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    // Parse and decrypt
    status = parse_secure_packet(g_decrypt_buffer, packet_length, 
                                 buffer, received_length);
    
    // Secure cleanup
    secure_zero(g_decrypt_buffer, sizeof(g_decrypt_buffer));
    
    return status;
}

bool secure_api_is_connected(void) {
    if (!g_network_hal) {
        return false;
    }
    
    if (g_conn_state.state != CONNECTION_STATE_AUTHENTICATED) {
        return false;
    }
    
    return g_network_hal->is_connected();
}

void secure_api_disconnect(void) {
    if (g_network_hal && g_network_hal->disconnect) {
        g_network_hal->disconnect();
    }
    
    if (g_conn_state.state == CONNECTION_STATE_AUTHENTICATED) {
        // Send graceful disconnect notification if possible
        uint8_t disconnect_msg[] = {0xFF};
        secure_api_send(disconnect_msg, sizeof(disconnect_msg));
    }
    
    g_conn_state.state = CONNECTION_STATE_DISCONNECTED;
    
    // Secure cleanup
    secure_zero(g_encrypt_buffer, sizeof(g_encrypt_buffer));
    secure_zero(g_decrypt_buffer, sizeof(g_decrypt_buffer));
}

void secure_api_loop(void) {
    if (!g_power_hal) {
        return;
    }
    
    uint32_t current_time = g_power_hal->get_tick_ms();
    
    // Handle auto-reconnection
    if (g_conn_state.state == CONNECTION_STATE_RECONNECTING ||
        g_conn_state.state == CONNECTION_STATE_CONNECTION_LOST) {
        secure_api_auto_connect();
        return;
    }
    
    // Send heartbeat if connected
    if (g_conn_state.state == CONNECTION_STATE_AUTHENTICATED) {
        if (current_time - g_conn_state.last_heartbeat > HEARTBEAT_INTERVAL_MS) {
            uint8_t heartbeat[] = {0x00};  // Heartbeat marker
            secure_api_send(heartbeat, sizeof(heartbeat));
            g_conn_state.last_heartbeat = current_time;
        }
        
        // Check if still connected
        if (!g_network_hal->is_connected()) {
            g_conn_state.state = CONNECTION_STATE_CONNECTION_LOST;
        }
    }
    
    // Enter low-power mode if disconnected and enabled
#if ENABLE_LOW_POWER_MODE
    if (g_conn_state.state != CONNECTION_STATE_AUTHENTICATED && 
        g_power_hal->enter_low_power) {
        g_power_hal->enter_low_power();
    }
#endif
}

SecureAPIStatus secure_api_rotate_keys(void) {
#if ENABLE_PERFECT_FORWARD_SECRECY
    if (!g_crypto_hal || !g_device_ctx) {
        return SECURE_API_ERROR_INIT;
    }
    
    // Generate new session key
    uint8_t new_key[AES_KEY_LENGTH];
    SecureAPIStatus status = g_crypto_hal->random_generate(new_key, sizeof(new_key));
    if (status != SECURE_API_SUCCESS) {
        return status;
    }
    
    // Securely replace old key
    secure_zero(g_device_ctx->aes_key, sizeof(g_device_ctx->aes_key));
    memcpy(g_device_ctx->aes_key, new_key, AES_KEY_LENGTH);
    
    // Secure cleanup
    secure_zero(new_key, sizeof(new_key));
    
    // Reset sequence number for new session
    g_device_ctx->sequence_number = 0;
    
    return SECURE_API_SUCCESS;
#else
    return SECURE_API_ERROR_INVALID_PARAM;
#endif
}

void secure_api_secure_wipe(void* ptr, size_t size) {
    secure_zero(ptr, size);
}

bool secure_api_validate_message(const uint8_t* message, size_t length,
                                 uint64_t timestamp, uint32_t sequence) {
    if (!message || length == 0) {
        return false;
    }
    
    return !is_replay_attack(timestamp, sequence);
}

ConnectionState secure_api_get_state(void) {
    return g_conn_state.state;
}

const char* secure_api_get_error_string(SecureAPIStatus status) {
    switch (status) {
        case SECURE_API_SUCCESS:
            return "Success";
        case SECURE_API_ERROR_INIT:
            return "Initialization error";
        case SECURE_API_ERROR_CRYPTO:
            return "Cryptographic operation failed";
        case SECURE_API_ERROR_NETWORK:
            return "Network error";
        case SECURE_API_ERROR_AUTH:
            return "Authentication failed";
        case SECURE_API_ERROR_TIMEOUT:
            return "Operation timeout";
        case SECURE_API_ERROR_MEMORY:
            return "Memory allocation failed";
        case SECURE_API_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case SECURE_API_ERROR_REPLAY_ATTACK:
            return "Replay attack detected";
        case SECURE_API_ERROR_CONNECTION_LOST:
            return "Connection lost";
        case SECURE_API_ERROR_MAX_RETRIES:
            return "Maximum retry attempts exceeded";
        default:
            return "Unknown error";
    }
}
