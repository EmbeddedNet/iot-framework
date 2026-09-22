/**
 * @file secure_mcu_api.c
 * @brief Implementation of World-Class Secure API for Tiny Microcontrollers
 */

#include "secure_mcu_api.h"
#include <string.h>
#include <stdarg.h>

/* ============================================================================
 * INTERNAL STATE
 * ============================================================================ */

static struct {
    secure_api_config_t config;
    secure_api_status_t status;
    bool initialized;
    uint8_t session_key[SECURE_API_KEY_SIZE];
    uint8_t rx_buffer[SECURE_API_RX_BUFFER_SIZE];
    uint64_t replay_window[SECURE_API_REPLAY_WINDOW / 64 + 1];
    uint32_t last_loop_time;
} g_secure_api = {0};

/* ============================================================================
 * INTERNAL HELPER FUNCTIONS
 * ============================================================================ */

// Secure memory zeroing (prevents compiler optimization)
static void secure_memzero(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Generate new session key from master key and random nonce
static void derive_session_key(uint8_t* output) {
    uint8_t nonce[SECURE_API_NONCE_SIZE];
    secure_hal_random_bytes(nonce, sizeof(nonce));
    
    // HMAC-based key derivation
    secure_hal_hmac_sha256(g_secure_api.config.api_key, SECURE_API_KEY_SIZE,
                           nonce, sizeof(nonce), output);
    
    secure_memzero(nonce, sizeof(nonce));
}

// Check for replay attack using sliding window
static bool check_replay_attack(uint64_t sequence) {
    if (sequence <= g_secure_api.status.rx_sequence) {
        return true; // Old or duplicate sequence
    }
    
    // Update window if sequence is within range
    if (sequence < g_secure_api.status.rx_sequence + SECURE_API_REPLAY_WINDOW) {
        uint64_t diff = sequence - g_secure_api.status.rx_sequence;
        uint64_t index = diff / 64;
        uint64_t bit = diff % 64;
        
        if (index < sizeof(g_secure_api.replay_window) / sizeof(uint64_t)) {
            g_secure_api.replay_window[index] |= (1ULL << bit);
        }
    }
    
    g_secure_api.status.rx_sequence = sequence;
    return false;
}

// Build authenticated message frame
static int build_message_frame(const uint8_t* payload, size_t payload_len,
                               uint8_t* output, size_t max_len, size_t* out_len) {
    // Frame structure: [Sequence:8][Timestamp:4][Nonce:12][Ciphertext:N][Tag:16][HMAC:32]
    size_t required_len = 8 + 4 + SECURE_API_NONCE_SIZE + payload_len + SECURE_API_TAG_SIZE + SECURE_API_HMAC_SIZE;
    
    if (required_len > max_len) {
        return -1;
    }
    
    uint8_t* ptr = output;
    
    // Sequence number (big-endian)
    g_secure_api.status.tx_sequence++;
    for (int i = 7; i >= 0; i--) {
        *ptr++ = (g_secure_api.status.tx_sequence >> (i * 8)) & 0xFF;
    }
    
    // Timestamp
    uint32_t timestamp = (uint32_t)secure_hal_get_timestamp_sec();
    *ptr++ = (timestamp >> 24) & 0xFF;
    *ptr++ = (timestamp >> 16) & 0xFF;
    *ptr++ = (timestamp >> 8) & 0xFF;
    *ptr++ = timestamp & 0xFF;
    
    // Generate fresh nonce
    uint8_t* nonce = ptr;
    secure_hal_random_bytes(nonce, SECURE_API_NONCE_SIZE);
    ptr += SECURE_API_NONCE_SIZE;
    
    // Encrypt payload with AES-GCM
    uint8_t* ciphertext = ptr;
    uint8_t* tag = ciphertext + payload_len;
    
    // AAD includes sequence and timestamp for authentication
    uint8_t aad[12];
    memcpy(aad, output, 12);
    
    int ret = secure_hal_aes_gcm_encrypt(
        g_secure_api.session_key, nonce,
        aad, sizeof(aad),
        payload, payload_len,
        ciphertext, tag
    );
    
    if (ret != 0) {
        return -1;
    }
    ptr += payload_len + SECURE_API_TAG_SIZE;
    
    // Calculate HMAC over entire frame (excluding HMAC itself)
    size_t hmac_data_len = ptr - output;
    int hmac_ret = secure_hal_hmac_sha256(
        g_secure_api.session_key, SECURE_API_KEY_SIZE,
        output, hmac_data_len,
        ptr
    );
    
    if (hmac_ret != 0) {
        return -1;
    }
    ptr += SECURE_API_HMAC_SIZE;
    
    *out_len = ptr - output;
    return 0;
}

// Parse and verify received message frame
static int parse_message_frame(const uint8_t* input, size_t input_len,
                               uint8_t* output, size_t max_len, size_t* out_len) {
    // Minimum frame size check
    size_t min_len = 8 + 4 + SECURE_API_NONCE_SIZE + SECURE_API_TAG_SIZE + SECURE_API_HMAC_SIZE;
    if (input_len < min_len) {
        return -1;
    }
    
    const uint8_t* ptr = input;
    
    // Extract sequence number
    uint64_t sequence = 0;
    for (int i = 0; i < 8; i++) {
        sequence = (sequence << 8) | *ptr++;
    }
    
    // Check for replay attack
    if (check_replay_attack(sequence)) {
        secure_api_log("REPLAY ATTACK DETECTED: seq=%llu", (unsigned long long)sequence);
        return -1;
    }
    
    // Extract timestamp
    uint32_t timestamp = 0;
    for (int i = 0; i < 4; i++) {
        timestamp = (timestamp << 8) | *ptr++;
    }
    
    // Extract nonce
    const uint8_t* nonce = ptr;
    ptr += SECURE_API_NONCE_SIZE;
    
    // Calculate expected ciphertext length
    size_t ciphertext_len = input_len - (ptr - input) - SECURE_API_TAG_SIZE - SECURE_API_HMAC_SIZE;
    const uint8_t* ciphertext = ptr;
    ptr += ciphertext_len;
    
    // Extract tag
    const uint8_t* tag = ptr;
    ptr += SECURE_API_TAG_SIZE;
    
    // Verify HMAC
    const uint8_t* received_hmac = ptr;
    uint8_t calculated_hmac[SECURE_API_HMAC_SIZE];
    
    size_t hmac_data_len = received_hmac - input;
    if (secure_hal_hmac_sha256(g_secure_api.session_key, SECURE_API_KEY_SIZE,
                               input, hmac_data_len, calculated_hmac) != 0) {
        return -1;
    }
    
    if (secure_api_memcmp_secure(received_hmac, calculated_hmac, SECURE_API_HMAC_SIZE) != 0) {
        secure_api_log("HMAC VERIFICATION FAILED");
        return -1;
    }
    
    // Decrypt payload
    uint8_t aad[12];
    memcpy(aad, input, 12);
    
    if (secure_hal_aes_gcm_decrypt(
            g_secure_api.session_key, nonce,
            aad, sizeof(aad),
            ciphertext, ciphertext_len,
            tag, output) != 0) {
        secure_api_log("DECRYPTION FAILED");
        return -1;
    }
    
    *out_len = ciphertext_len;
    return 0;
}

// Exponential backoff calculation
static uint32_t calculate_backoff(void) {
    if (g_secure_api.status.reconnect_count >= SECURE_API_MAX_RECONNECT) {
        g_secure_api.status.reconnect_count = 0;
    }
    
    uint32_t backoff = SECURE_API_MIN_BACKOFF_MS * (1 << g_secure_api.status.reconnect_count);
    
    if (backoff > SECURE_API_MAX_BACKOFF_MS) {
        backoff = SECURE_API_MAX_BACKOFF_MS;
    }
    
    // Add jitter (±25%)
    uint32_t jitter = secure_hal_random_uint32() % (backoff / 2);
    backoff = backoff - (backoff / 4) + jitter;
    
    return backoff;
}

/* ============================================================================
 * PUBLIC API IMPLEMENTATION
 * ============================================================================ */

secure_api_error_t secure_api_init(const secure_api_config_t* config) {
    if (config == NULL || config->device_id == NULL || 
        config->server_host == NULL) {
        return SECURE_ERR_INVALID_PARAM;
    }
    
    // Clear state
    memset(&g_secure_api, 0, sizeof(g_secure_api));
    
    // Copy configuration
    g_secure_api.config = *config;
    
    // Derive initial session key
    derive_session_key(g_secure_api.session_key);
    
    g_secure_api.initialized = true;
    g_secure_api.last_loop_time = secure_hal_get_timestamp_ms();
    
    secure_api_log("Secure API initialized for device: %s", config->device_id);
    
    return SECURE_OK;
}

void secure_api_deinit(void) {
    if (!g_secure_api.initialized) {
        return;
    }
    
    secure_api_disconnect();
    secure_api_secure_wipe();
    
    g_secure_api.initialized = false;
    secure_api_log("Secure API deinitialized");
}

secure_api_error_t secure_api_connect(void) {
    if (!g_secure_api.initialized) {
        return SECURE_ERR_INIT_FAILED;
    }
    
    if (g_secure_api.status.is_connected) {
        return SECURE_OK;
    }
    
    secure_api_log("Connecting to %s:%d...", 
                   g_secure_api.config.server_host, 
                   g_secure_api.config.server_port);
    
    // Check network availability
    if (!secure_hal_network_is_available()) {
        secure_api_log("Network not available");
        return SECURE_ERR_NETWORK_DOWN;
    }
    
    // Establish connection
    int ret = secure_hal_network_connect(
        g_secure_api.config.server_host,
        g_secure_api.config.server_port,
        g_secure_api.config.use_tls
    );
    
    if (ret < 0) {
        secure_api_log("Connection failed: %d", ret);
        g_secure_api.status.reconnect_count++;
        g_secure_api.status.next_backoff_ms = calculate_backoff();
        return SECURE_ERR_CONNECTION_FAILED;
    }
    
    g_secure_api.status.is_connected = true;
    g_secure_api.status.is_authenticated = true;
    g_secure_api.status.reconnect_count = 0;
    g_secure_api.status.next_backoff_ms = SECURE_API_MIN_BACKOFF_MS;
    g_secure_api.status.last_heartbeat = secure_hal_get_timestamp_ms();
    
    secure_api_log("Connected successfully");
    
    return SECURE_OK;
}

void secure_api_disconnect(void) {
    if (!g_secure_api.status.is_connected) {
        return;
    }
    
    secure_hal_network_disconnect();
    g_secure_api.status.is_connected = false;
    g_secure_api.status.is_authenticated = false;
    
    secure_api_log("Disconnected");
}

void secure_api_get_status(secure_api_status_t* status) {
    if (status == NULL) {
        return;
    }
    *status = g_secure_api.status;
}

secure_api_error_t secure_api_send(const uint8_t* payload, size_t len) {
    if (!g_secure_api.initialized || !g_secure_api.status.is_connected) {
        return SECURE_ERR_CONNECTION_FAILED;
    }
    
    if (payload == NULL || len == 0 || len > SECURE_API_MAX_PAYLOAD) {
        return SECURE_ERR_INVALID_PARAM;
    }
    
    // Build authenticated message frame
    uint8_t frame[SECURE_API_RX_BUFFER_SIZE];
    size_t frame_len;
    
    if (build_message_frame(payload, len, frame, sizeof(frame), &frame_len) != 0) {
        return SECURE_ERR_ENCRYPTION_FAILED;
    }
    
    // Send frame
    int ret = secure_hal_network_send(frame, frame_len, 5000);
    
    if (ret < 0) {
        g_secure_api.status.is_connected = false;
        return SECURE_ERR_CONNECTION_FAILED;
    }
    
    return SECURE_OK;
}

secure_api_error_t secure_api_receive(uint8_t* buffer, size_t max_len, size_t* received_len) {
    if (!g_secure_api.initialized || !g_secure_api.status.is_connected) {
        return SECURE_ERR_CONNECTION_FAILED;
    }
    
    if (buffer == NULL || received_len == NULL) {
        return SECURE_ERR_INVALID_PARAM;
    }
    
    // Receive data
    int ret = secure_hal_network_receive(g_secure_api.rx_buffer, 
                                          sizeof(g_secure_api.rx_buffer), 
                                          0); // Non-blocking
    
    if (ret <= 0) {
        return SECURE_ERR_TIMEOUT;
    }
    
    // Parse and verify message
    size_t decrypted_len;
    if (parse_message_frame(g_secure_api.rx_buffer, ret, 
                            buffer, max_len, &decrypted_len) != 0) {
        return SECURE_ERR_AUTH_FAILED;
    }
    
    *received_len = decrypted_len;
    return SECURE_OK;
}

secure_api_error_t secure_api_request_response(
    const uint8_t* request, size_t req_len,
    uint8_t* response, size_t resp_max_len, size_t* resp_len,
    uint32_t timeout_ms) {
    
    if (!g_secure_api.initialized || !g_secure_api.status.is_connected) {
        return SECURE_ERR_CONNECTION_FAILED;
    }
    
    // Send request
    secure_api_error_t err = secure_api_send(request, req_len);
    if (err != SECURE_OK) {
        return err;
    }
    
    // Wait for response with timeout
    uint32_t start_time = secure_hal_get_timestamp_ms();
    
    while ((secure_hal_get_timestamp_ms() - start_time) < timeout_ms) {
        err = secure_api_receive(response, resp_max_len, resp_len);
        
        if (err == SECURE_OK) {
            return SECURE_OK;
        } else if (err != SECURE_ERR_TIMEOUT) {
            return err;
        }
        
        // Small delay to prevent busy-waiting
        #if SECURE_API_LOW_POWER_MODE
        if (secure_hal_is_low_power_mode()) {
            secure_hal_enter_low_power();
        }
        #endif
    }
    
    return SECURE_ERR_TIMEOUT;
}

secure_api_error_t secure_api_loop(void) {
    if (!g_secure_api.initialized) {
        return SECURE_ERR_INIT_FAILED;
    }
    
    uint32_t current_time = secure_hal_get_timestamp_ms();
    
    // Handle auto-reconnect if disconnected
    if (!g_secure_api.status.is_connected) {
        if (current_time - g_secure_api.last_loop_time >= g_secure_api.status.next_backoff_ms) {
            secure_api_log("Attempting reconnection (attempt %lu)...", 
                          (unsigned long)g_secure_api.status.reconnect_count + 1);
            
            secure_api_error_t err = secure_api_connect();
            
            if (err == SECURE_OK) {
                secure_api_log("Reconnection successful");
            } else {
                secure_api_log("Reconnection failed, next attempt in %lu ms", 
                              (unsigned long)g_secure_api.status.next_backoff_ms);
            }
            
            g_secure_api.last_loop_time = current_time;
            return err;
        }
        
        #if SECURE_API_LOW_POWER_MODE
        secure_hal_enter_low_power();
        #endif
        
        return SECURE_ERR_CONNECTION_FAILED;
    }
    
    // Send heartbeat if needed
    if (current_time - g_secure_api.status.last_heartbeat >= SECURE_API_HEARTBEAT_MS) {
        uint8_t heartbeat[] = "{\"type\":\"heartbeat\"}";
        secure_api_send(heartbeat, sizeof(heartbeat) - 1);
        g_secure_api.status.last_heartbeat = current_time;
    }
    
    g_secure_api.last_loop_time = current_time;
    
    return SECURE_OK;
}

secure_api_error_t secure_api_rotate_keys(void) {
    if (!g_secure_api.initialized) {
        return SECURE_ERR_INIT_FAILED;
    }
    
    secure_api_log("Rotating session keys...");
    
    // Derive new session key
    uint8_t new_key[SECURE_API_KEY_SIZE];
    derive_session_key(new_key);
    
    // Securely replace old key
    memcpy(g_secure_api.session_key, new_key, SECURE_API_KEY_SIZE);
    secure_memzero(new_key, sizeof(new_key));
    
    // Reset sequence numbers for new session
    g_secure_api.status.tx_sequence = 0;
    g_secure_api.status.rx_sequence = 0;
    memset(g_secure_api.replay_window, 0, sizeof(g_secure_api.replay_window));
    
    secure_api_log("Session keys rotated successfully");
    
    return SECURE_OK;
}

void secure_api_secure_wipe(void) {
    // Securely clear all sensitive data
    secure_memzero(g_secure_api.session_key, sizeof(g_secure_api.session_key));
    secure_memzero(g_secure_api.rx_buffer, sizeof(g_secure_api.rx_buffer));
    secure_memzero(g_secure_api.replay_window, sizeof(g_secure_api.replay_window));
    
    secure_api_log("Sensitive data wiped from memory");
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

void secure_api_random_bytes(uint8_t* buffer, size_t len) {
    secure_hal_random_bytes(buffer, len);
}

int secure_api_memcmp_secure(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = (const volatile uint8_t*)a;
    const volatile uint8_t* pb = (const volatile uint8_t*)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result;
}

void secure_api_log(const char* format, ...) {
    if (g_secure_api.config.log_callback == NULL) {
        return;
    }
    
    static char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    g_secure_api.config.log_callback(buffer);
}
