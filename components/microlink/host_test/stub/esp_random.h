/* ESP-IDF's esp_random.h for the host tests: the test fills the bytes */
#pragma once
#include <stddef.h>
void esp_fill_random(void *buf, size_t len);
