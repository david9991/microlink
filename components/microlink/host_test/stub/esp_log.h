/* ESP-IDF's esp_log.h for the host tests: each line goes to the test, which
 * counts it by its level */
#pragma once
void ml_host_log(char level, const char *tag, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
#define ESP_LOGE(tag, ...) ml_host_log('E', tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...) ml_host_log('W', tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...) ml_host_log('I', tag, __VA_ARGS__)
