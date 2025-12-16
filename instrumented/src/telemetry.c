#include "telemetry.h"
#include <stdio.h>

void sec_log(const char *event, long value) {
    printf("[SEC]%s:%ld\n", event, value);
}

void sec_warn(const char *msg) {
    printf("[WARN]%s\n", msg);
}

void sec_info(const char *msg) {
    printf("[INFO]%s\n", msg);
}
