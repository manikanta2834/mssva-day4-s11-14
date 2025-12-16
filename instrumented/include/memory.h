#ifndef MEMORY_H
#define MEMORY_H

#include "record.h"
#include <stdint.h>

char *process_record(record_t *rec, uint8_t flags);
void cleanup_records(record_t *records, uint16_t count);

#endif
