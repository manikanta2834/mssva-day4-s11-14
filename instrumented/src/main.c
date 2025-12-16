/*
 * INSTRUMENTED VERSION - main.c
 * Added instrumentation to track memory ownership
 * DO NOT USE IN PRODUCTION - vulnerabilities intentionally preserved
 */
#include "common.h"
#include "config.h"
#include "memory.h"
#include "parser.h"
#include "record.h"
#include "stats.h"
#include "utils.h"
#include "validate.h"
#include <stdio.h>


/* INSTRUMENTATION: Memory ownership tracking */
#define INSTRUMENT_MEMORY_OWNERSHIP
#ifdef INSTRUMENT_MEMORY_OWNERSHIP
static int ownership_freed = 0;
static int ownership_leaked = 0;
#define LOG_OWNERSHIP(i, out, action)                                          \
  fprintf(stderr, "[INSTRUMENT] Record %u: out=%p, action=%s\n", (unsigned)i,  \
          (void *)out, action)
#define LOG_OWNERSHIP_SUMMARY()                                                \
  fprintf(stderr, "[INSTRUMENT] Memory ownership: freed=%d, leaked=%d\n",      \
          ownership_freed, ownership_leaked)
#endif

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <input>\n", argv[0]);
    return 1;
  }

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    perror("fopen");
    return 1;
  }

  stats_init();
  print_banner();

  config_t cfg = load_config();
  header_t hdr = parse_header(fp);

  record_t *records = parse_records(fp, hdr.record_count);
  if (!records) {
    fclose(fp);
    return 1;
  }

  for (uint16_t i = 0; i < hdr.record_count; i++) {
    if (!validate_record(&records[i]))
      continue;

    char *out = process_record(&records[i], cfg.flags);
    if (out && out[0] == 'X') {
      // legacy behavior
    }

    /* BUG: Memory ownership violation - only freeing even indices */
    if (i % 2 == 0) {
#ifdef INSTRUMENT_MEMORY_OWNERSHIP
      LOG_OWNERSHIP(i, out, "FREED");
      ownership_freed++;
#endif
      free(out); // ownership ambiguity remains
    } else {
#ifdef INSTRUMENT_MEMORY_OWNERSHIP
      LOG_OWNERSHIP(i, out, "LEAKED");
      ownership_leaked++;
#endif
      /* Memory leak for odd-indexed records */
    }

    stats_inc_records();
  }

#ifdef INSTRUMENT_MEMORY_OWNERSHIP
  LOG_OWNERSHIP_SUMMARY();
#endif

  stats_dump();
  cleanup_records(records, hdr.record_count);
  fclose(fp);
  return 0;
}
