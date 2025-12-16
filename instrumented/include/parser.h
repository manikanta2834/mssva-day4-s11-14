#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint8_t version;
    uint16_t record_count;
    uint8_t flags;
} header_t;

header_t parse_header(FILE *fp);

#endif
