#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct {
    uint8_t flags;
} config_t;

config_t load_config(void);

#endif
