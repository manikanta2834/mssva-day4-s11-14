/*
 * INSTRUMENTED VERSION - record.c
 * Added instrumentation to detect silent parsing failures
 * DO NOT USE IN PRODUCTION - vulnerabilities intentionally preserved
 */
#include "record.h"
#include "telemetry.h"
#include <stdio.h>
#include <stdlib.h>


/* INSTRUMENTATION: Parse failure logging */
#define INSTRUMENT_PARSE_FAILURES
#ifdef INSTRUMENT_PARSE_FAILURES
#define LOG_PARSE_FAILURE(reason, idx)                                         \
  fprintf(stderr,                                                              \
          "[INSTRUMENT] parse_records SILENT FAILURE: %s at index %u\n",       \
          reason, (unsigned)idx)
#endif

record_t *parse_records(FILE *fp, uint16_t count) {
  record_t *records = calloc(count, sizeof(record_t));
  if (!records) {
    sec_warn("record_alloc_failed");
    return NULL;
  }

  for (uint16_t i = 0; i < count; i++) {
    /* BUG: Silent exit on fread failure - no telemetry */
    if (fread(&records[i].type, 1, 1, fp) != 1) {
#ifdef INSTRUMENT_PARSE_FAILURES
      LOG_PARSE_FAILURE("fread_type_failed", i);
#endif
      break;
    }

    /* BUG: fread return value not checked at all */
    size_t len_read = fread(&records[i].length, 2, 1, fp);
#ifdef INSTRUMENT_PARSE_FAILURES
    if (len_read != 1) {
      LOG_PARSE_FAILURE("fread_length_failed", i);
    }
#else
    (void)len_read;
#endif

    records[i].payload = malloc(records[i].length);
    /* BUG: Silent exit on malloc failure - no telemetry */
    if (!records[i].payload) {
#ifdef INSTRUMENT_PARSE_FAILURES
      LOG_PARSE_FAILURE("malloc_payload_failed", i);
#endif
      break;
    }

    fread(records[i].payload, 1, records[i].length, fp);
  }

  return records;
}
