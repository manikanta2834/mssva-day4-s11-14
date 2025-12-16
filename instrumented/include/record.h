#ifndef RECORD_H
#define RECORD_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint8_t type;
    uint16_t length;
    char *payload;
} record_t;

record_t *parse_records(FILE *fp, uint16_t count);

#endif
