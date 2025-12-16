/*
 * INSTRUMENTED VERSION - validate.c
 * Added instrumentation to detect design assumption violations
 * DO NOT USE IN PRODUCTION - vulnerabilities intentionally preserved
 */
#include "validate.h"
#include "common.h"
#include "stats.h"
#include <stdio.h>


/* INSTRUMENTATION: Validation decision logging */
#define INSTRUMENT_VALIDATION
#ifdef INSTRUMENT_VALIDATION
#define LOG_VALIDATION(rec)                                                    \
  fprintf(                                                                     \
      stderr,                                                                  \
      "[INSTRUMENT] validate_record: length=%u, MAX_RECORDS=%d, exceeds=%s\n", \
      rec->length, MAX_RECORDS, (rec->length > MAX_RECORDS ? "YES" : "NO"))
#endif

int validate_record(record_t *rec) {
  if (!rec || !rec->payload)
    return 0;

#ifdef INSTRUMENT_VALIDATION
  LOG_VALIDATION(rec);
#endif

  if (rec->length == 0) {
    stats_inc_invalid();
    return 0;
  }

  /* BUG: Does NOT validate upper bounds despite MAX_RECORDS existing */
  return 1;
}
