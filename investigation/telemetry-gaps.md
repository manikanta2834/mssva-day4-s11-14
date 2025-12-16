# Telemetry Gaps Analysis

## Investigation Target: dataproc-agent
## Date: December 16, 2025

---

## Executive Summary

The `dataproc-agent` has a basic telemetry framework (`telemetry.c`) but significant gaps exist in its deployment throughout the codebase. This analysis identifies all locations where failures occur without logging, quantifies the blind spots, and provides recommendations.

---

## 1. Current Telemetry Infrastructure

### 1.1 Available Functions

| Function | Purpose | Usage Count |
|----------|---------|-------------|
| `sec_log(event, value)` | Log event with numeric value | 2 |
| `sec_warn(msg)` | Log warning message | 1 |
| `sec_info(msg)` | Log informational message | 1 |

### 1.2 Current Telemetry Coverage

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TELEMETRY COVERAGE MAP                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  main.c          [░░░░░░░░░░░░░░░░░░░░]  0%   ❌ No telemetry      │
│  parser.c        [████░░░░░░░░░░░░░░░░]  20%  ⚠️ Partial           │
│  record.c        [██░░░░░░░░░░░░░░░░░░]  10%  ⚠️ Partial           │
│  memory.c        [░░░░░░░░░░░░░░░░░░░░]  0%   ❌ No telemetry      │
│  config.c        [████░░░░░░░░░░░░░░░░]  20%  ⚠️ Partial           │
│  validate.c      [░░░░░░░░░░░░░░░░░░░░]  0%   ❌ No telemetry      │
│  stats.c         [░░░░░░░░░░░░░░░░░░░░]  0%   ❌ N/A (stats only)  │
│  utils.c         [░░░░░░░░░░░░░░░░░░░░]  0%   ❌ No telemetry      │
│                                                                     │
│  OVERALL         [██░░░░░░░░░░░░░░░░░░]  8%   ❌ CRITICAL GAP      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Identified Telemetry Gaps

### Gap 1: Record Parsing Failures (CRITICAL)

**Location:** `src/record.c:parse_records` (lines 12-23)

**Missing Telemetry Points:**

| Line | Code | Should Log |
|------|------|------------|
| 13-14 | `if (fread(...) != 1) break;` | fread failure with record index |
| 16 | `fread(&records[i].length, 2, 1, fp);` | Unchecked read result |
| 18-20 | `if (!records[i].payload) break;` | malloc failure with size |
| 22 | `fread(records[i].payload, ...);` | Unchecked payload read |

**Impact:**
- Cannot detect truncated input files in production
- Memory allocation failures go unnoticed
- Partial data processing without alerting

**Recommended Instrumentation:**
```c
for (uint16_t i = 0; i < count; i++) {
    if (fread(&records[i].type, 1, 1, fp) != 1) {
        sec_warn("parse_records:fread_type_failed");
        sec_log("parse_records:failed_at_index", i);
        break;
    }

    if (fread(&records[i].length, 2, 1, fp) != 1) {
        sec_warn("parse_records:fread_length_failed");
        sec_log("parse_records:failed_at_index", i);
        break;
    }

    records[i].payload = malloc(records[i].length);
    if (!records[i].payload) {
        sec_warn("parse_records:malloc_failed");
        sec_log("parse_records:requested_size", records[i].length);
        break;
    }

    size_t read = fread(records[i].payload, 1, records[i].length, fp);
    if (read != records[i].length) {
        sec_warn("parse_records:payload_read_incomplete");
        sec_log("parse_records:expected", records[i].length);
        sec_log("parse_records:actual", read);
    }
}
```

---

### Gap 2: Header Parsing I/O Errors (HIGH)

**Location:** `src/parser.c:parse_header` (lines 7-9)

**Missing Telemetry Points:**

| Line | Code | Should Log |
|------|------|------------|
| 7 | `fread(&hdr.version, 1, 1, fp);` | Version read failure |
| 8 | `fread(&hdr.record_count, 2, 1, fp);` | Record count read failure |
| 9 | `fread(&hdr.flags, 1, 1, fp);` | Flags read failure |

**Current State:**
```c
// Only logs AFTER reads (which may have failed)
sec_log("record_count", hdr.record_count);  // May log garbage
sec_log("flags", hdr.flags);                // May log garbage
```

**Impact:**
- Corrupted headers processed without warning
- Garbage values logged as legitimate data
- No way to distinguish valid vs. corrupted input

**Recommended Instrumentation:**
```c
header_t parse_header(FILE *fp) {
    header_t hdr = {0};  // Zero-initialize
    size_t r;

    r = fread(&hdr.version, 1, 1, fp);
    if (r != 1) sec_warn("header:version_read_failed");
    sec_log("header:version", hdr.version);
    
    r = fread(&hdr.record_count, 2, 1, fp);
    if (r != 1) sec_warn("header:record_count_read_failed");
    sec_log("header:record_count", hdr.record_count);
    
    r = fread(&hdr.flags, 1, 1, fp);
    if (r != 1) sec_warn("header:flags_read_failed");
    sec_log("header:flags", hdr.flags);

    return hdr;
}
```

---

### Gap 3: Memory Operations (HIGH)

**Location:** `src/memory.c:process_record` (lines 8-19)

**Missing Telemetry Points:**

| Scenario | Should Log |
|----------|------------|
| malloc returns NULL | Allocation failure with requested size |
| FAST_MODE activated | Mode indicator for debugging |
| Processing complete | Record processing success |

**Current State:** Zero telemetry in memory.c

**Impact:**
- Memory exhaustion goes undetected
- Cannot determine which code path was taken
- Performance issues impossible to diagnose

**Recommended Instrumentation:**
```c
char *process_record(record_t *rec, uint8_t flags) {
    sec_log("process_record:length", rec->length);
    
    char *buf = malloc(rec->length + 1);
    if (!buf) {
        sec_warn("process_record:malloc_failed");
        sec_log("process_record:requested_bytes", rec->length + 1);
        return NULL;
    }

    if (flags & FAST_MODE) {
        sec_info("process_record:using_fast_mode");
        memcpy(buf, rec->payload, rec->length + 1);
    } else {
        memcpy(buf, rec->payload, rec->length);
        buf[rec->length] = '\0';
    }
    
    return buf;
}
```

---

### Gap 4: Validation Decisions (MEDIUM)

**Location:** `src/validate.c:validate_record` (lines 4-14)

**Missing Telemetry Points:**

| Decision | Should Log |
|----------|------------|
| NULL record | Invalid input received |
| NULL payload | Corrupted record structure |
| Zero length | Zero-length record rejected |
| Validation passed | Record accepted with attributes |

**Impact:**
- Cannot correlate invalid record stats with root cause
- No audit trail for security-relevant decisions
- Rate of malformed input unknown

**Recommended Instrumentation:**
```c
int validate_record(record_t *rec) {
    if (!rec) {
        sec_warn("validate:null_record");
        return 0;
    }
    
    if (!rec->payload) {
        sec_warn("validate:null_payload");
        sec_log("validate:record_type", rec->type);
        return 0;
    }

    if (rec->length == 0) {
        sec_warn("validate:zero_length");
        sec_log("validate:record_type", rec->type);
        stats_inc_invalid();
        return 0;
    }

    sec_log("validate:accepted_length", rec->length);
    return 1;
}
```

---

### Gap 5: Main Processing Loop (MEDIUM)

**Location:** `src/main.c:main` (lines 35-48)

**Missing Telemetry Points:**

| Event | Should Log |
|-------|------------|
| Loop start | Total records to process |
| Record skipped | Validation failure details |
| Legacy behavior triggered | Output starting with 'X' |
| Memory freed | Ownership tracking |
| Memory leaked | Ownership violation detected |

**Impact:**
- Processing progress unknown
- Memory leaks invisible
- Legacy code paths untraceable

---

## 3. Summary Statistics

| Metric | Value |
|--------|-------|
| Total failure paths | 12 |
| Failure paths with telemetry | 1 (8%) |
| Failure paths without telemetry | 11 (92%) |
| Critical gaps | 2 |
| High-severity gaps | 2 |
| Medium-severity gaps | 1 |

---

## 4. Telemetry Gap Severity Matrix

```
                    Frequency of Occurrence
                    Low         Medium      High
                ┌───────────┬───────────┬───────────┐
        High    │           │  Gap 1    │           │
                │           │ (record)  │           │
Impact          ├───────────┼───────────┼───────────┤
                │  Gap 3    │  Gap 2    │  Gap 5    │
        Medium  │ (memory)  │ (header)  │ (main)    │
                ├───────────┼───────────┼───────────┤
        Low     │           │  Gap 4    │           │
                │           │ (validate)│           │
                └───────────┴───────────┴───────────┘
```

---

## 5. Recommendations

### Immediate (P0)
1. Add telemetry to all `fread()` calls with return value checks
2. Log all memory allocation failures with requested size
3. Add telemetry for parsed record counts vs. expected counts

### Short-term (P1)
1. Implement structured logging format (JSON) for automated parsing
2. Add unique error codes for each failure path
3. Create telemetry for FAST_MODE activation

### Long-term (P2)
1. Implement metrics collection (counters, histograms)
2. Add trace IDs for request correlation
3. Implement health check endpoint with telemetry stats
