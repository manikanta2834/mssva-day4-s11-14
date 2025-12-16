#include "stats.h"
#include <stdio.h>

static int records_processed = 0;
static int invalid_records = 0;

void stats_init(void) {
    records_processed = 0;
    invalid_records = 0;
}

void stats_inc_records(void) {
    records_processed++;
}

void stats_inc_invalid(void) {
    invalid_records++;
}

void stats_dump(void) {
    printf("[STATS] records_processed=%d invalid_records=%d\n",
           records_processed, invalid_records);
}
