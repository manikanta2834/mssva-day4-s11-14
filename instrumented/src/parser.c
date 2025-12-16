/*
 * INSTRUMENTED VERSION - parser.c
 * Added instrumentation to detect silent I/O failures
 * DO NOT USE IN PRODUCTION - vulnerabilities intentionally preserved
 */
#include "parser.h"
#include "telemetry.h"
#include <stdio.h>

/* INSTRUMENTATION: fread return value checking */
#define INSTRUMENT_FREAD_CHECKS
#ifdef INSTRUMENT_FREAD_CHECKS
#define CHECK_FREAD(result, expected, field)                                   \
  if (result != expected) {                                                    \
    fprintf(                                                                   \
        stderr,                                                                \
        "[INSTRUMENT] SILENT FAILURE: fread %s returned %zu, expected %zu\n",  \
        field, result, (size_t)expected);                                      \
  }
#endif

header_t parse_header(FILE *fp) {
  header_t hdr;

#ifdef INSTRUMENT_FREAD_CHECKS
  size_t r1, r2, r3;

  r1 = fread(&hdr.version, 1, 1, fp);
  CHECK_FREAD(r1, 1, "version");

  r2 = fread(&hdr.record_count, 2, 1, fp);
  CHECK_FREAD(r2, 1, "record_count");

  r3 = fread(&hdr.flags, 1, 1, fp);
  CHECK_FREAD(r3, 1, "flags");
#else
  /* BUG: Unchecked fread return values - silent failure */
  fread(&hdr.version, 1, 1, fp);
  fread(&hdr.record_count, 2, 1, fp);
  fread(&hdr.flags, 1, 1, fp);
#endif

  sec_log("record_count", hdr.record_count);
  sec_log("flags", hdr.flags);

  return hdr;
}
