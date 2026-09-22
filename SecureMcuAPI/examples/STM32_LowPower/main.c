/**
 * @file main.c
 * @brief STM32 Low-Power Example with Secure MCU API
 * 
 * This example demonstrates ultra-low-power operation on STM32 microcontrollers
 * using the Secure MCU API with hardware crypto acceleration and sleep modes.
 * 
 * Hardware: STM32L4, STM32L0, or any STM32 with low-power capabilities
 * Features:
 * - Hardware AES-GCM acceleration
 * - Stop mode between transmissions
 * - RTC wakeup timer
 * - Minimal power consumption (<10µA in sleep)
 */

#include "stm32l4xx_hal.h"
#include "secure_mcu_api.h"
#include <stdio.h>
#include <string.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#define DEVICE_ID           "stm32_lp_device_001"
#define SERVER_HOST         "your-server.com"
#define SERVER_PORT         443
#define TRANSMIT_INTERVAL_S 300  // Transmit every 5 minutes for max battery life

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

static RTC_HandleTypeDef hrtc;
static UART_HandleTypeDef huart2;
static volatile bool g_wakeup_flag = false;

// Device credentials (store in secure element or encrypted flash in production)
static const uint8_t API_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// ============================================================================
// HARDWARE INITIALIZATION
// ============================================================================

void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_RTC_Init(void);

void HAL_MspInit(void) {
    // Enable clocks
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_RCC_RTC_ENABLE();
    
    // Configure GPIOs for low power
    // Set all unused GPIOs to analog mode to minimize leakage
}

void HAL_MspDeInit(void) {
    // Disable clocks for peripherals not needed in stop mode
    __HAL_RCC_USART2_CLK_DISABLE();
}

// ============================================================================
// LOW-POWER FUNCTIONS
// ============================================================================

void enter_stop_mode(uint32_t wake_time_ms) {
    // Configure RTC wakeup timer
    RTC_TimeTypeDef sTime = {0};
    RTC_DateTypeDef sDate = {0};
    
    // Set wakeup time
    HAL_RTCEx_SetWakeUpTimer(&hrtc, wake_time_ms / 1000, RTC_WAKEUPCLOCK_CK_SPRE_16BITS);
    
    // Enter STOP mode with RTC running
    HAL_PWREx_EnterSTOP2(PWR_STOPENTRY_WFI);
    
    // System wakes up here after RTC interrupt
    // Reconfigure system clock after wakeup
    SystemClock_Config();
    MX_USART2_UART_Init();
}

void configure_low_power_gpio(void) {
    // Configure all GPIOs for minimum leakage
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    
    // Set all pins to analog mode (lowest leakage)
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
    
    GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);
}

// ============================================================================
// SENSOR FUNCTIONS
// ============================================================================

float read_battery_voltage(void) {
    // Read internal VREFINT to calculate VBAT
    // Implementation depends on specific STM32 model
    return 3.3f; // Placeholder
}

int32_t read_temperature(void) {
    // Read internal temperature sensor
    // Returns temperature in millidegrees Celsius
    return 25000; // Placeholder: 25.00°C
}

// ============================================================================
// HAL IMPLEMENTATIONS FOR STM32
// ============================================================================

uint32_t secure_hal_random_uint32(void) {
    uint32_t random = 0;
    HAL_RNG_GenerateRandomNumber(&hrng, &random);
    return random;
}

void secure_hal_random_bytes(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t val;
        HAL_RNG_GenerateRandomNumber(&hrng, &val);
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            buffer[i + j] = (val >> (j * 8)) & 0xFF;
        }
    }
}

int secure_hal_aes_gcm_encrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* plaintext, size_t pt_len,
                                uint8_t* ciphertext, uint8_t* tag) {
    // Use STM32 hardware crypto engine (CRYP peripheral)
    #if defined(STM32L4) || defined(STM32F4)
    CRYP_HandleTypeDef hcryp;
    memset(&hcryp, 0, sizeof(hcryp));
    
    hcryp.Instance = CRYP;
    hcryp.Init.DataType = CRYP_DATATYPE_8BIT;
    hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
    memcpy(hcryp.Init.pKey, key, 32);
    memcpy(hcryp.Init.pInitVect, nonce, 12);
    
    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return -1;
    }
    
    // GCM encryption with authentication tag
    if (HAL_CRYP_AESGCM_Encrypt(&hcryp, (uint8_t*)aad, aad_len,
                                 (uint8_t*)plaintext, pt_len,
                                 ciphertext, 5000) != HAL_OK) {
        HAL_CRYP_DeInit(&hcryp);
        return -1;
    }
    
    // Get authentication tag
    if (HAL_CRYP_AESGCM_Finish(&hcryp, tag, SECURE_API_TAG_SIZE, 5000) != HAL_OK) {
        HAL_CRYP_DeInit(&hcryp);
        return -1;
    }
    
    HAL_CRYP_DeInit(&hcryp);
    return 0;
    #else
    // Fallback to software implementation (mbedtls)
    return -1;
    #endif
}

int secure_hal_aes_gcm_decrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ciphertext, size_t ct_len,
                                const uint8_t* tag, uint8_t* plaintext) {
    #if defined(STM32L4) || defined(STM32F4)
    CRYP_HandleTypeDef hcryp;
    memset(&hcryp, 0, sizeof(hcryp));
    
    hcryp.Instance = CRYP;
    hcryp.Init.DataType = CRYP_DATATYPE_8BIT;
    hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
    memcpy(hcryp.Init.pKey, key, 32);
    memcpy(hcryp.Init.pInitVect, nonce, 12);
    
    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return -1;
    }
    
    int ret = HAL_CRYP_AESGCM_Decrypt(&hcryp, (uint8_t*)aad, aad_len,
                                       (uint8_t*)ciphertext, ct_len,
                                       plaintext, 5000);
    
    // Verify authentication tag
    uint8_t calc_tag[SECURE_API_TAG_SIZE];
    if (ret == HAL_OK) {
        ret = HAL_CRYP_AESGCM_Finish(&hcryp, calc_tag, SECURE_API_TAG_SIZE, 5000);
        if (ret == HAL_OK && memcmp(tag, calc_tag, SECURE_API_TAG_SIZE) != 0) {
            ret = HAL_ERROR;
        }
    }
    
    HAL_CRYP_DeInit(&hcryp);
    return (ret == HAL_OK) ? 0 : -1;
    #else
    return -1;
    #endif
}

int secure_hal_hmac_sha256(const uint8_t* key, size_t key_len,
                           const uint8_t* data, size_t data_len,
                           uint8_t* output) {
    // Use hardware HASH peripheral if available, otherwise mbedtls
    #if defined(STM32L4) && defined(HASH)
    HASH_HandleTypeDef hhash;
    memset(&hhash, 0, sizeof(hhash));
    
    hhash.Instance = HASH;
    hhash.Init.DataType = HASH_DATATYPE_8BIT;
    hhash.Init.KeySize = (key_len <= 16) ? HASH_KEYSIZE_128B :
                         (key_len <= 32) ? HASH_KEYSIZE_256B : HASH_KEYSIZE_512B;
    memcpy(hhash.Init.pKey, key, key_len);
    
    if (HAL_HASH_Init(&hhash) != HAL_OK) {
        return -1;
    }
    
    if (HAL_HASH_HMAC_SHA256_Start(&hhash, (uint8_t*)data, data_len,
                                    output, 5000) != HAL_OK) {
        HAL_HASH_DeInit(&hhash);
        return -1;
    }
    
    HAL_HASH_DeInit(&hhash);
    return 0;
    #else
    // Fallback to mbedtls
    return -1;
    #endif
}

int secure_hal_network_connect(const char* host, uint16_t port, bool tls) {
    // Implement using your network stack (WiFi, Cellular, LoRaWAN, etc.)
    // Example: BG96 cellular module, ESP-AT commands, or LoRaWAN stack
    return 0; // Placeholder
}

int secure_hal_network_send(const uint8_t* data, size_t len, uint32_t timeout_ms) {
    // Send via configured network interface
    return len; // Placeholder
}

int secure_hal_network_receive(uint8_t* buffer, size_t max_len, uint32_t timeout_ms) {
    // Receive from network interface (non-blocking)
    return 0; // Placeholder
}

void secure_hal_network_disconnect(void) {
    // Disconnect network
}

bool secure_hal_network_is_available(void) {
    // Check network registration status
    return true; // Placeholder
}

uint32_t secure_hal_get_timestamp_ms(void) {
    return HAL_GetTick();
}

uint64_t secure_hal_get_timestamp_sec(void) {
    RTC_TimeTypeDef sTime = {0};
    RTC_DateTypeDef sDate = {0};
    
    HAL_RTC_GetTime(&hrtc, &sTime, RTC_FORMAT_BIN);
    HAL_RTC_GetDate(&hrtc, &sDate, RTC_FORMAT_BIN);
    
    // Convert to Unix timestamp (implementation dependent)
    return ((uint64_t)sDate.Year * 365 * 24 * 3600) +
           (sDate.Month * 30 * 24 * 3600) +
           (sDate.Date * 24 * 3600) +
           (sTime.Hours * 3600) +
           (sTime.Minutes * 60) +
           sTime.Seconds;
}

void secure_hal_enter_low_power(void) {
    // Enter STOP2 mode (ultra-low power, ~2µA)
    // Wakeup via RTC alarm or external interrupt
    
    // Disable UART before entering stop mode
    HAL_UART_DeInit(&huart2);
    
    // Enter stop mode with RTC wakeup
    enter_stop_mode(TRANSMIT_INTERVAL_S * 1000);
    
    // Re-enable UART after wakeup
    MX_USART2_UART_Init();
}

void secure_hal_exit_low_power(void) {
    // Called after wakeup from stop mode
    // System clock is reconfigured in enter_stop_mode()
    g_wakeup_flag = true;
}

bool secure_hal_is_low_power_mode(void) {
    return true; // Always use low-power mode in this example
}

// ============================================================================
// LOGGING FUNCTION
// ============================================================================

void secure_api_log_callback(const char* msg) {
    // Log via UART (only when awake)
    HAL_UART_Transmit(&huart2, (uint8_t*)msg, strlen(msg), 100);
    HAL_UART_Transmit(&huart2, (uint8_t*)"\r\n", 2, 100);
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

int main(void) {
    // Initialize HAL
    HAL_Init();
    
    // Configure system clock
    SystemClock_Config();
    
    // Initialize peripherals
    MX_GPIO_Init();
    MX_USART2_UART_Init();
    MX_RTC_Init();
    
    printf("STM32 Low-Power Secure API Demo\r\n");
    printf("=================================\r\n");
    
    // Initialize secure API
    secure_api_config_t config = {
        .device_id = DEVICE_ID,
        .api_key = API_KEY,
        .server_host = SERVER_HOST,
        .server_port = SERVER_PORT,
        .use_tls = true,
        .ca_cert = NULL,
        .log_callback = secure_api_log_callback
    };
    
    if (secure_api_init(&config) != SECURE_OK) {
        printf("Secure API initialization failed!\r\n");
        while (1);
    }
    
    printf("Secure API initialized\r\n");
    
    // Main loop
    while (1) {
        // Handle secure API (auto-reconnect, heartbeats)
        secure_api_error_t err = secure_api_loop();
        
        if (err == SECURE_OK) {
            secure_api_status_t status;
            secure_api_get_status(&status);
            
            if (status.is_connected) {
                // Prepare sensor data
                float battery = read_battery_voltage();
                int32_t temp = read_temperature();
                
                char payload[128];
                snprintf(payload, sizeof(payload),
                         "{\"dev\":\"%s\",\"bat\":%.2f,\"temp\":%d.%02d}",
                         DEVICE_ID, battery,
                         temp / 1000, abs(temp % 1000));
                
                printf("Sending: %s\r\n", payload);
                
                // Send encrypted data
                if (secure_api_send((uint8_t*)payload, strlen(payload)) == SECURE_OK) {
                    printf("✓ Data sent\r\n");
                    
                    // Rotate keys periodically
                    static uint8_t msg_count = 0;
                    if (++msg_count % 5 == 0) {
                        secure_api_rotate_keys();
                    }
                }
                
                // Check for incoming commands
                uint8_t rx_buffer[256];
                size_t rx_len;
                if (secure_api_receive(rx_buffer, sizeof(rx_buffer), &rx_len) == SECURE_OK) {
                    printf("Received: %.*s\r\n", rx_len, rx_buffer);
                    // Process command
                }
            }
        } else {
            printf("Connection error: %d\r\n", err);
        }
        
        // Enter ultra-low-power stop mode
        printf("Entering STOP2 mode for %d seconds...\r\n", TRANSMIT_INTERVAL_S);
        secure_hal_enter_low_power();
        
        // Execution resumes here after RTC wakeup
        printf("Woke up from STOP mode\r\n");
    }
}

// ============================================================================
// PERIPHERAL INITIALIZATION FUNCTIONS
// ============================================================================

static void MX_RTC_Init(void) {
    hrtc.Instance = RTC;
    hrtc.Init.HourFormat = RTC_HOURFORMAT_24;
    hrtc.Init.AsynchPrediv = RTC_ASYNCH_PREDIV;
    hrtc.Init.SynchPrediv = RTC_SYNCH_PREDIV;
    hrtc.Init.OutPut = RTC_OUTPUT_DISABLE;
    hrtc.Init.OutPutRemap = RTC_OUTPUT_REMAP_NONE;
    hrtc.Init.OutPutPolarity = RTC_OUTPUT_POLARITY_HIGH;
    hrtc.Init.OutPutType = RTC_OUTPUT_TYPE_OPENDRAIN;
    
    if (HAL_RTC_Init(&hrtc) != HAL_OK) {
        Error_Handler();
    }
    
    // Enable wakeup timer
    HAL_RTCEx_SetWakeUpTimer(&hrtc, 300, RTC_WAKEUPCLOCK_CK_SPRE_16BITS);
    HAL_NVIC_EnableIRQ(RTC_WKUP_IRQn);
}

static void MX_USART2_UART_Init(void) {
    huart2.Instance = USART2;
    huart2.Init.BaudRate = 115200;
    huart2.Init.WordLength = UART_WORDLENGTH_8B;
    huart2.Init.StopBits = UART_STOPBITS_1;
    huart2.Init.Parity = UART_PARITY_NONE;
    huart2.Init.Mode = UART_MODE_TX_RX;
    huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart2.Init.OverSampling = UART_OVERSAMPLING_16;
    
    if (HAL_UART_Init(&huart2) != HAL_OK) {
        Error_Handler();
    }
}

static void MX_GPIO_Init(void) {
    // GPIO initialization for low power
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    // ... configure GPIOs as needed
}

void SystemClock_Config(void) {
    // Configure system clock (MSI or HSE depending on requirements)
    // After wakeup from STOP, this must be called to restore clocks
}

void Error_Handler(void) {
    __disable_irq();
    while (1);
}

// RTC wakeup interrupt handler
void RTC_WKUP_IRQHandler(void) {
    HAL_RTCEx_WakeUpTimerIRQHandler(&hrtc);
    g_wakeup_flag = true;
}

void HAL_RTCEx_WakeUpTimerEventCallback(RTC_HandleTypeDef *hrtc) {
    g_wakeup_flag = true;
}

// Required for printf support
int _write(int file, char *ptr, int len) {
    HAL_UART_Transmit(&huart2, (uint8_t*)ptr, len, 100);
    return len;
}
