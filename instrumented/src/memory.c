/*
 * INSTRUMENTED VERSION - memory.c
 * Added instrumentation to detect heap buffer over-read
 * DO NOT USE IN PRODUCTION - vulnerabilities intentionally preserved
 */
#include "memory.h"
#include "telemetry.h"
#include <common.h>
#include <record.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* INSTRUMENTATION: Heap bounds checking */
#define INSTRUMENT_HEAP_BOUNDS
#ifdef INSTRUMENT_HEAP_BOUNDS
#define CHECK_BOUNDS(rec, flags)                                               \
  do {                                                                         \
    if (flags & FAST_MODE) {                                                   \
      fprintf(stderr,                                                          \
              "[INSTRUMENT] FAST_MODE: copying %u+1=%u bytes from payload "    \
              "(allocated: %u)\n",                                             \
              rec->length, rec->length + 1, rec->length);                      \
      fprintf(                                                                 \
          stderr,                                                              \
          "[INSTRUMENT] HEAP OVER-READ: Reading 1 byte beyond allocation!\n"); \
    }                                                                          \
  } while (0)
#endif

char *process_record(record_t *rec, uint8_t flags) {
  char *buf = malloc(rec->length + 1);
  if (!buf)
    return NULL;

#ifdef INSTRUMENT_HEAP_BOUNDS
  CHECK_BOUNDS(rec, flags);
#endif

  /* BUG: Off-by-one heap buffer over-read in FAST_MODE */
  if (flags & FAST_MODE) {
    memcpy(buf, rec->payload,
           rec->length + 1); // off-by-one: reads beyond rec->payload
  } else {
    memcpy(buf, rec->payload, rec->length);
    buf[rec->length] = '\0';
  }
  return buf;
}

void cleanup_records(record_t *records, uint16_t count) {
  for (uint16_t i = 0; i < count; i++) {
    free(records[i].payload);
  }
  free(records);
}
