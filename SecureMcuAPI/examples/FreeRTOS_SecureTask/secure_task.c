/**
 * @file secure_task.c
 * @brief FreeRTOS Example with Secure MCU API
 * 
 * This example demonstrates how to run the Secure MCU API in a dedicated
 * FreeRTOS task with proper task synchronization and low-power operation.
 * 
 * Hardware: ESP32, STM32, or any FreeRTOS-compatible MCU
 */

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "secure_mcu_api.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define TASK_STACK_SIZE         4096
#define TASK_PRIORITY           5
#define SENSOR_QUEUE_SIZE       10
#define COMMAND_QUEUE_SIZE      10

// Device configuration
static const char* DEVICE_ID = "freertos_device_001";
static const char* SERVER_HOST = "your-server.com";
static const uint16_t SERVER_PORT = 443;

static const uint8_t API_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

typedef struct {
    float temperature;
    float humidity;
    uint32_t timestamp;
} sensor_data_t;

typedef enum {
    CMD_SEND_DATA,
    CMD_ROTATE_KEYS,
    CMD_DISCONNECT,
    CMD_SHUTDOWN
} command_t;

// ============================================================================
// GLOBAL HANDLES
// ============================================================================

static TaskHandle_t xSecureTaskHandle = NULL;
static QueueHandle_t xSensorQueue = NULL;
static QueueHandle_t xCommandQueue = NULL;
static SemaphoreHandle_t xConnectionSemaphore = NULL;

// ============================================================================
// SENSOR TASK - Reads sensors and sends data to secure task
// ============================================================================

void vSensorTask(void* pvParameters) {
    sensor_data_t sensor_data;
    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xPeriod = pdMS_TO_TICKS(60000); // 60 seconds
    
    for (;;) {
        // Read sensors (replace with actual sensor code)
        sensor_data.temperature = 25.0f + (rand() % 100) / 10.0f;
        sensor_data.humidity = 60.0f + (rand() % 100) / 10.0f;
        sensor_data.timestamp = xTaskGetTickCount() / portTICK_PERIOD_MS;
        
        // Send to secure task queue
        if (xQueueSend(xSensorQueue, &sensor_data, pdMS_TO_TICKS(5000)) != pdTRUE) {
            // Queue full, handle error
        }
        
        // Wait for next period
        vTaskDelayUntil(&xLastWakeTime, xPeriod);
    }
}

// ============================================================================
// COMMAND TASK - Handles external commands (e.g., from UART, buttons)
// ============================================================================

void vCommandTask(void* pvParameters) {
    for (;;) {
        // Wait for command (example: button press, UART input)
        // This is a placeholder - implement your command source
        
        // Example: send rotate keys command every 10 minutes
        vTaskDelay(pdMS_TO_TICKS(600000));
        
        command_t cmd = CMD_ROTATE_KEYS;
        xQueueSend(xCommandQueue, &cmd, portMAX_DELAY);
    }
}

// ============================================================================
// SECURE COMMUNICATION TASK - Main secure API handler
// ============================================================================

void vSecureTask(void* pvParameters) {
    secure_api_config_t config = {
        .device_id = DEVICE_ID,
        .api_key = API_KEY,
        .server_host = SERVER_HOST,
        .server_port = SERVER_PORT,
        .use_tls = true,
        .ca_cert = NULL,
        .log_callback = NULL // Implement logging if needed
    };
    
    secure_api_error_t err;
    sensor_data_t sensor_data;
    command_t cmd;
    
    // Initialize secure API
    err = secure_api_init(&config);
    if (err != SECURE_OK) {
        // Handle initialization error
        vTaskDelete(NULL);
        return;
    }
    
    // Signal that initialization is complete
    xSemaphoreGive(xConnectionSemaphore);
    
    for (;;) {
        // Handle auto-reconnect and heartbeats
        err = secure_api_loop();
        
        if (err == SECURE_OK) {
            secure_api_status_t status;
            secure_api_get_status(&status);
            
            if (status.is_connected) {
                // Check for sensor data
                if (xQueueReceive(xSensorQueue, &sensor_data, 0) == pdTRUE) {
                    // Format payload
                    char payload[256];
                    snprintf(payload, sizeof(payload),
                             "{\"device\":\"%s\",\"temp\":%.2f,\"humidity\":%.2f,\"ts\":%lu}",
                             DEVICE_ID, sensor_data.temperature, 
                             sensor_data.humidity, sensor_data.timestamp);
                    
                    // Send encrypted data
                    err = secure_api_send((uint8_t*)payload, strlen(payload));
                    
                    if (err != SECURE_OK) {
                        // Handle send error
                    }
                }
                
                // Check for commands
                if (xQueueReceive(xCommandQueue, &cmd, 0) == pdTRUE) {
                    switch (cmd) {
                        case CMD_ROTATE_KEYS:
                            secure_api_rotate_keys();
                            break;
                            
                        case CMD_DISCONNECT:
                            secure_api_disconnect();
                            break;
                            
                        case CMD_SHUTDOWN:
                            secure_api_deinit();
                            vTaskDelete(NULL);
                            return;
                            
                        default:
                            break;
                    }
                }
                
                // Check for incoming messages
                uint8_t rx_buffer[512];
                size_t rx_len;
                err = secure_api_receive(rx_buffer, sizeof(rx_buffer), &rx_len);
                
                if (err == SECURE_OK) {
                    // Process received command
                    // Example: parse JSON and act on commands
                }
            }
        }
        
        // Enter low-power mode if disconnected
        if (err != SECURE_OK) {
            #if SECURE_API_LOW_POWER_MODE
            secure_hal_enter_low_power();
            #endif
            
            // Delay before retry (handled by secure_api_loop backoff)
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            // Small delay to prevent busy-waiting
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

// ============================================================================
// HAL IMPLEMENTATIONS FOR FREERTOS
// ============================================================================

uint32_t secure_hal_random_uint32(void) {
    // Use hardware RNG if available, otherwise use FreeRTOS pseudo-random
    #ifdef CONFIG_IDF_TARGET_ESP32
    return esp_random();
    #else
    static uint32_t seed = 0;
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return seed;
    #endif
}

void secure_hal_random_bytes(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t val = secure_hal_random_uint32();
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            buffer[i + j] = (val >> (j * 8)) & 0xFF;
        }
    }
}

// Crypto implementations - use platform-specific hardware acceleration
// See Basic_AutoConnect example for ESP32 mbedtls implementation

int secure_hal_aes_gcm_encrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* plaintext, size_t pt_len,
                                uint8_t* ciphertext, uint8_t* tag) {
    // Implement using mbedtls or hardware crypto engine
    // Placeholder - replace with actual implementation
    return 0;
}

int secure_hal_aes_gcm_decrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ciphertext, size_t ct_len,
                                const uint8_t* tag, uint8_t* plaintext) {
    // Implement using mbedtls or hardware crypto engine
    return 0;
}

int secure_hal_hmac_sha256(const uint8_t* key, size_t key_len,
                           const uint8_t* data, size_t data_len,
                           uint8_t* output) {
    // Implement using mbedtls or hardware crypto engine
    return 0;
}

// Network functions - implement based on your network stack
int secure_hal_network_connect(const char* host, uint16_t port, bool tls) {
    // Implement using your network stack (LwIP, cellular, etc.)
    return 0;
}

int secure_hal_network_send(const uint8_t* data, size_t len, uint32_t timeout_ms) {
    // Implement network send
    return len;
}

int secure_hal_network_receive(uint8_t* buffer, size_t max_len, uint32_t timeout_ms) {
    // Implement network receive
    return 0;
}

void secure_hal_network_disconnect(void) {
    // Implement network disconnect
}

bool secure_hal_network_is_available(void) {
    // Check network availability
    return true;
}

uint32_t secure_hal_get_timestamp_ms(void) {
    return xTaskGetTickCount() * portTICK_PERIOD_MS;
}

uint64_t secure_hal_get_timestamp_sec(void) {
    return xTaskGetTickCount() / (1000 / portTICK_PERIOD_MS);
}

void secure_hal_enter_low_power(void) {
    // Enter FreeRTOS tickless idle mode or MCU sleep
    // vPortSleep(); // Platform-specific
}

void secure_hal_exit_low_power(void) {
    // Wake up handled by interrupt
}

bool secure_hal_is_low_power_mode(void) {
    return false;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

void vStartSecureApplication(void) {
    // Create queues
    xSensorQueue = xQueueCreate(SENSOR_QUEUE_SIZE, sizeof(sensor_data_t));
    xCommandQueue = xQueueCreate(COMMAND_QUEUE_SIZE, sizeof(command_t));
    xConnectionSemaphore = xSemaphoreCreateBinary();
    
    if (xSensorQueue == NULL || xCommandQueue == NULL || xConnectionSemaphore == NULL) {
        // Handle allocation failure
        return;
    }
    
    // Create tasks
    xTaskCreate(vSensorTask, "SensorTask", TASK_STACK_SIZE, NULL, 
                TASK_PRIORITY - 1, NULL);
    
    xTaskCreate(vCommandTask, "CommandTask", TASK_STACK_SIZE, NULL,
                TASK_PRIORITY - 1, NULL);
    
    xTaskCreate(vSecureTask, "SecureTask", TASK_STACK_SIZE, NULL,
                TASK_PRIORITY, &xSecureTaskHandle);
    
    // Wait for connection
    if (xSemaphoreTake(xConnectionSemaphore, pdMS_TO_TICKS(10000)) == pdTRUE) {
        // Connection established
    } else {
        // Connection timeout
    }
}

// Example usage in main.c:
// int main(void) {
//     // Initialize hardware, FreeRTOS scheduler
//     vStartSecureApplication();
//     vTaskStartScheduler();
//     return 0;
// }
