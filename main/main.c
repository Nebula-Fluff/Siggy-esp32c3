/*
开发顺序：
[1] #include
[2] #define 常量
[3] const 常量数组
[4] 结构体定义
[5] 函数声明
[6] main 或 主要调用点（项目核心）
[7] 各种函数定义
项目名称：Siggy固件alpha-v2.0
环境：ESP-IDF in ESP32C3
功能测试：在串口输入HEX“A55A0171776572747975696F706173646667686A6B6C7A786376626E6D717765727479”。返回HEX值应符合以下格式：“0xA5, 0x5A, 0x10, 0x96, 0x4C, 0x16, 0x06, 0xFA, 0x01, 0xD9, 0x03, 0x3E, 0x5F, 0x97, 0x99, 0x59, 0x87, 0x49, 0xBD, 0x18, 0x76, 0x00, 0xE4, 0x12, 0xFD, 0x84, 0x65, 0x1A, 0x36, 0x23, 0xB1, 0xEB, 0x69, 0x80, 0x51, 0x44, 0x5A, 0xF8, 0xCD, 0xBB, 0xA1, 0xDD, 0xE9, 0x74, 0xBA, 0xC2, 0x1F, 0x23, 0xC4, 0x67, 0x34, 0xB6, 0x19, 0xD3, 0xE2, 0x2D, 0x76, 0xCD, 0xB6, 0x2D, 0xFD, 0x34, 0x2A, 0x31, 0x30, 0x2D, 0x01, 0x10, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x7A, 0x78, 0x63, 0x76, 0x62, 0x6E, 0x6D, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x01”
发布前测试状态：uart0串口正常，LED正常，签名正常；uart1串口正常；flash加密正常；安全启动正常
*/

/* version A2.0 安全性得到提升，Ed25519私钥不在固件中存放，改成由不可见hmac秘钥派生*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_hmac.h"

#include "tweetnacl.h"
#include "ssd1306.h"

#define UART_PORT_NUM UART_NUM_0 // 串口号，发布时改为非0串口
#define UART_BAUD_RATE 115200
#define UART_TX_PIN 21 // TX引脚-v A1.0 PCB为4号引脚，v1.0为0，usb串口测试时为21
#define UART_RX_PIN 20 // RX引脚-v A1.0 PCB为5号引脚，v1.0为1，usb串口测试时为20

#define SCL_PIN 5 // SCL引脚-version A1.0 PCB为5号引脚
#define SDA_PIN 4 // SDA引脚-version A1.0 PCB为4号引脚

#define BUF_SIZE 256           // 串口缓冲区大小
#define SEND_PACKET_LEN 105    // 发送数据包长度
#define SEND_PACKET_LEN_PK 35  // 发送公钥数据包长度
#define RX_PACKET_LEN 35       // 接收数据包长度
#define HEADER_LEN 2           // 包头长度
#define RX_PACKET_DATA_LEN 33  // 数据包数据部分长度
#define ID_LEN 5               // ID数据长度
#define TO_SIGN_ID_PART_LEN 38 // 需签名ID部分长度，控制位1字节+随机数32字节+ID5字节
#define SIGNED_ID_PART_LEN 102 // 签名后ID部分长度，签名64字节+签名前数据，ID部分共38字节
#define RND_LEN 32             // 随机数长度
#define KEY_PAIR_LEN 64        // 密钥对长度
#define PRIVATE_KEY_LEN 32     // 私钥长度
#define PUBLIC_KEY_LEN 32      // 公钥长度

#define LED_GREEN_GPIO 19 // 积极态LED引脚-version A1.0 PCB为19号引脚
#define LED_RED_GPIO 18   // 消极态LED引脚-version A1.0 PCB为18号引脚

const uint8_t PACKET_HEADER[HEADER_LEN] = {0xA5, 0x5A};                                                                                                                                                                              // 包头内容
const uint8_t COMMAND0[1] = {0x00};                                                                                                                                                                                                  // 命令0-用来告诉“veri”：“siggy”已经准备好了
const uint8_t COMMAND1[1] = {0x01};                                                                                                                                                                                                  // 命令1-用来判断“veri”是不是在要“siggy”的ID，这条消息也自带签名挑战
const uint8_t COMMAND2[1] = {0x02};                                                                                                                                                                                                  // 命令2-判断“veri”是不是在要本“siggy”的公钥
const uint8_t COMMAND1_0[1] = {0x10};                                                                                                                                                                                                // 命令10-用来告诉“veri”：这条消息里是“siggy”的ID，并且回应了签名挑战
const uint8_t COMMAND1_1[1] = {0x11};                                                                                                                                                                                                // 命令11-用来告诉“veri”：这条消息里是“siggy”的公钥
const uint8_t DEVICE_ID[5] = {0xFF, 0x00, 0x00, 0x00, 0x01};                                                                                                                                                                         // 设备ID
const uint8_t pk[PUBLIC_KEY_LEN] = {0xF9, 0xBF, 0xC4, 0xFC, 0x54, 0x93, 0xC4, 0xE2, 0x59, 0xDB, 0xDF, 0xE6, 0x65, 0x79, 0x72, 0x00, 0x80, 0x44, 0x1E, 0x04, 0x2E, 0xF0, 0x92, 0xEA, 0x53, 0xA6, 0x01, 0x4E, 0x78, 0xD2, 0xE2, 0xAA}; // 公钥存储部分

const char *seed_sk = "Siggy-1-SEED-NebulaFluff"; // 私钥种子
const size_t seed_sk_len = 25;                    // 私钥种子长度

const uint8_t READY_PACKET[3] = {0xA5, 0x5A, 0x00};

int error_count = 0; // 错误计数器

// 创建屏幕对象
SSD1306_t dev;

// 函数声明
void process_data(uint8_t *data, int len);         // 处理数据函数声明
void send_id(uint8_t *rnd_in);                     // 用来发送ID的
static inline void secure_zero(void *p, size_t n); // 安全清零函数声明
void error(void);                                  // 错误显示函数

void app_main(void)
{
    // 配置串口参数
    const uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};

    // 配置GPIO引脚
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << LED_GREEN_GPIO) | (1ULL << LED_RED_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};

    // 初始化GPIO
    gpio_config(&io_conf);

    // 设置LED初始状态
    gpio_set_level(LED_GREEN_GPIO, 1); // 关闭绿色LED
    gpio_set_level(LED_RED_GPIO, 1);   // 关闭红色LED

    // 安装串口驱动，分配缓冲区
    uart_driver_install(UART_PORT_NUM, BUF_SIZE, 0, 0, NULL, 0);
    uart_param_config(UART_PORT_NUM, &uart_config);
    uart_set_pin(UART_PORT_NUM, UART_TX_PIN, UART_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    static uint8_t rx_buf[RX_PACKET_LEN]; // 接收缓冲区
    // 初始化显示器，以及一些信息显示
    i2c_master_init(&dev, SDA_PIN, SCL_PIN, -1);
    ssd1306_init(&dev, 128, 64);
    ssd1306_clear_screen(&dev, false);
    ssd1306_contrast(&dev, 0xff);
    ssd1306_display_text(&dev, 0, "Admin key", 9, false);
    ssd1306_display_text(&dev, 1, "Siggy-V1.0", 10, false);
    ssd1306_display_text(&dev, 2, "By NebulaFluff", 12, false);
    ssd1306_display_text(&dev, 3, "KeyID:FF00000001", 16, false);

    // HMAC读取区-开始（测试用）
    // uint8_t hmac[32];

    // esp_err_t result = esp_hmac_calculate(HMAC_KEY4, seed_sk, seed_sk_len, hmac);

    // if (result == ESP_OK) {
    // // 输出HMAC值
    // uart_write_bytes(UART_PORT_NUM, hmac, 32);
    // } else {
    // // 计算 HMAC 失败

    // }
    // HMAC读取区-结束（测试用）

    // 功能测试区-开始

    // 功能测试区-结束

    vTaskDelay(50);
    // 发送命令0，告诉“veri”：“siggy”已经准备好了
    uart_write_bytes(UART_PORT_NUM, READY_PACKET, 3);

    while (1)
    {
        int received = uart_read_bytes(UART_PORT_NUM, rx_buf, RX_PACKET_LEN, pdMS_TO_TICKS(500)); // 读取数据，超时500ms
        if (received >= HEADER_LEN && memcmp(rx_buf, PACKET_HEADER, 2) == 0)
        {
            process_data(rx_buf + 2, RX_PACKET_DATA_LEN); // 去掉包头，处理数据
        }
        else if (received == 0)
        {
            continue; // 没有数据，继续等待
        }
        else
        { // 暂时啥也不做
          //  gpio_set_level(LED_RED_GPIO, 0); // 点亮红色LED
          //  vTaskDelay(pdMS_TO_TICKS(1000)); // 延时1秒
          //  gpio_set_level(LED_RED_GPIO, 1); // 熄灭红色LED
        }
    }
}

void process_data(uint8_t *data, int len)
{
    if (data[0] == COMMAND2[0])
    {
        // 处理命令11-发公钥给“veri”
        static uint8_t to_send_packet_pk[SEND_PACKET_LEN_PK];                            // 要发送的数据包
        memcpy(to_send_packet_pk, PACKET_HEADER, HEADER_LEN);                            // 装入包头
        memcpy(to_send_packet_pk + HEADER_LEN, COMMAND1_1, sizeof(COMMAND1_1));          // 装入命令
        memcpy(to_send_packet_pk + HEADER_LEN + sizeof(COMMAND1_1), pk, PUBLIC_KEY_LEN); // 装入公钥数据
        // 发送数据包
        uart_write_bytes(UART_PORT_NUM, to_send_packet_pk, SEND_PACKET_LEN_PK);
    }
    else if (data[0] == COMMAND1[0])
    {
        static uint8_t RXRND[RND_LEN];
        memcpy(RXRND, data + sizeof(COMMAND1), RND_LEN); // 将数据包内随机数部分挪到随机数缓存区
        // 处理命令1-发ID给“veri”
        send_id(RXRND);
    }
    else
    {
        // 未知命令
        ssd1306_display_text(&dev, 5, "error", 5, false);
        gpio_set_level(LED_RED_GPIO, 0); // 点亮红色LED
        vTaskDelay(pdMS_TO_TICKS(500));  // 延时
        gpio_set_level(LED_RED_GPIO, 1); // 熄灭红色LED
        vTaskDelay(pdMS_TO_TICKS(100));  // 延时
        gpio_set_level(LED_RED_GPIO, 0); // 点亮红色LED
        vTaskDelay(pdMS_TO_TICKS(500));  // 延时
        gpio_set_level(LED_RED_GPIO, 1); // 熄灭红色LED
        ssd1306_display_text(&dev, 5, "     ", 5, false);
    }
}

void send_id(uint8_t *rnd_in)
{
    static uint8_t to_sign_data[TO_SIGN_ID_PART_LEN]; // 需签名数据部分
    static uint8_t signed_data[SIGNED_ID_PART_LEN];   // 签名数据部分
    static uint8_t to_send_packet[SEND_PACKET_LEN];   // 要发送的数据包
    unsigned long long sign_out_len;                  // 存毫无用处的签名输出信息的长度信息
    static uint8_t key_pair[KEY_PAIR_LEN];            // 私钥存储部分
    // 组合包数据部分
    memcpy(to_sign_data, COMMAND1_0, sizeof(COMMAND1_0));
    memcpy(to_sign_data + sizeof(COMMAND1_0), rnd_in, RND_LEN);             // 随机数
    memcpy(to_sign_data + sizeof(COMMAND1_0) + RND_LEN, DEVICE_ID, ID_LEN); // 设备ID

    // 签名数据部分
    esp_err_t result = esp_hmac_calculate(HMAC_KEY4, seed_sk, seed_sk_len, key_pair); // 计算HMAC，得到私钥并放入key_pair
    memcpy(key_pair + 32, pk, PUBLIC_KEY_LEN);                                        // 将公钥复制到密钥对后32字节

    if (result == ESP_OK)
    {
        if (crypto_sign(signed_data, &sign_out_len, to_sign_data, (unsigned long long)sizeof(to_sign_data), key_pair) != 0)
        {
            // 签名完成后
            secure_zero(key_pair, KEY_PAIR_LEN); // 清除密钥对缓存，防止泄露
            // 签名失败，点亮红色LED
            ssd1306_display_text(&dev, 5, "Sig FAIL!", 9, false);
            gpio_set_level(LED_RED_GPIO, 0); // 点亮红色LED
            vTaskDelay(pdMS_TO_TICKS(1000)); // 延时1秒
            gpio_set_level(LED_RED_GPIO, 1); // 熄灭红色LED
            ssd1306_display_text(&dev, 5, "         ", 9, false);
        }
        else
        {
            secure_zero(key_pair, KEY_PAIR_LEN);                                                       // 清除密钥对缓存，防止泄露
            memcpy(to_send_packet, PACKET_HEADER, HEADER_LEN);                                         // 装入包头
            memcpy(to_send_packet + HEADER_LEN, COMMAND1_0, sizeof(COMMAND1_0));                       // 装入命令
            memcpy(to_send_packet + HEADER_LEN + sizeof(COMMAND1_0), signed_data, SIGNED_ID_PART_LEN); // 装入签名数据
            // 发送数据包
            uart_write_bytes(UART_PORT_NUM, to_send_packet, SEND_PACKET_LEN);
            // 签名成功，点亮绿色LED
            ssd1306_display_text(&dev, 5, "Sig OK!", 7, false);
            gpio_set_level(LED_GREEN_GPIO, 0); // 点亮绿色LED
            vTaskDelay(pdMS_TO_TICKS(100));    // 延时
            gpio_set_level(LED_GREEN_GPIO, 1); // 熄灭绿色LED
            ssd1306_display_text(&dev, 5, "       ", 7, false);
            error_count = 0; // 成功一次，错误计数器归零
        }
    }
    else
    {
        error_count++;
        if (error_count >= 2)
        {
            error(); // 进入错误显示
        }
        else
        {
            ssd1306_display_text(&dev, 5, "HMAC ERROR", 10, false);
            gpio_set_level(LED_RED_GPIO, 0); // 点亮红色LED
            vTaskDelay(pdMS_TO_TICKS(1000)); // 延时1秒
            gpio_set_level(LED_RED_GPIO, 1); // 熄灭红色LED
            ssd1306_display_text(&dev, 5, "         ", 9, false);
        }
    }
}

static inline void secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--)
        *vp++ = 0;
}

void error(void)
{
    ssd1306_display_text(&dev, 0, "Admin key-ERROR", 15, true);
    ssd1306_display_text(&dev, 5, "================", 16, true);
    ssd1306_display_text(&dev, 6, "L O C K D O W N ", 16, true);
    ssd1306_display_text(&dev, 7, "================", 16, true);
    gpio_set_level(LED_RED_GPIO, 0); // 点亮红色LED
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(1000)); // 延时1秒
        ssd1306_display_text(&dev, 5, "                ", 16, false);
        ssd1306_display_text(&dev, 6, "                ", 16, false);
        ssd1306_display_text(&dev, 7, "                ", 16, false);
        vTaskDelay(pdMS_TO_TICKS(1000)); // 延时1秒
        ssd1306_display_text(&dev, 5, "================", 16, true);
        ssd1306_display_text(&dev, 6, "L O C K D O W N ", 16, true);
        ssd1306_display_text(&dev, 7, "================", 16, true);
    }
}