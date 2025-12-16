#ifndef TELEMETRY_H
#define TELEMETRY_H

void sec_log(const char *event, long value);
void sec_warn(const char *msg);
void sec_info(const char *msg);   // NEW

#endif
