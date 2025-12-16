#ifndef STATS_H
#define STATS_H

void stats_init(void);
void stats_inc_records(void);
void stats_inc_invalid(void);   // NEW
void stats_dump(void);

#endif
