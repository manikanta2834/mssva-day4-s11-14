#include "config.h"
#include "telemetry.h"
#include <stdlib.h>
#include <common.h>

config_t load_config(void) {
    config_t cfg;
    const char *env = getenv("DATAPROC_FAST");

    cfg.flags = 0;
    if (env && env[0] == '1') {
        cfg.flags |= FAST_MODE;
        sec_info("FAST_MODE enabled");
    }
    return cfg;
}
