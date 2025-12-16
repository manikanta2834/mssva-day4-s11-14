# System Overview - dataproc-agent

## 1. Purpose

The `dataproc-agent` is a C-based internal data preprocessing service designed for batch ingestion of proprietary binary data formats. According to the README, it processes input files with a proprietary format and has evolved over time without formal security review.

## 2. Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        main.c                                │
│  Entry point: CLI argument handling, orchestration           │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  config.c   │      │  parser.c   │      │  record.c   │
│ Load config │      │Parse header │      │Parse records│
└─────────────┘      └─────────────┘      └─────────────┘
                                                 │
                                                 ▼
                            ┌─────────────────────────────┐
                            │          memory.c           │
                            │  process_record()           │
                            │  cleanup_records()          │
                            └─────────────────────────────┘
                                         │
              ┌──────────────────────────┼──────────────────┐
              ▼                          ▼                  ▼
      ┌─────────────┐           ┌─────────────┐     ┌─────────────┐
      │ validate.c  │           │   stats.c   │     │ telemetry.c │
      │  Validation │           │ Statistics  │     │  Logging    │
      └─────────────┘           └─────────────┘     └─────────────┘
```

### 2.2 Data Flow

1. **Input**: Binary file passed via CLI argument
2. **Header Parsing**: `parse_header()` reads 4 bytes (version, record_count, flags)
3. **Record Parsing**: `parse_records()` allocates and reads N records
4. **Processing Loop**: For each record:
   - Validate with `validate_record()`
   - Process with `process_record()`
   - Stats tracking with `stats_inc_records()`
5. **Cleanup**: `cleanup_records()` frees allocated memory

### 2.3 Binary Input Format

```
┌────────────────────────────────────────────────────────┐
│                      HEADER (4 bytes)                  │
├──────────┬───────────────────┬─────────────────────────┤
│ version  │   record_count    │         flags           │
│ (1 byte) │     (2 bytes)     │        (1 byte)         │
├──────────┴───────────────────┴─────────────────────────┤
│                      RECORDS (variable)                │
├──────────┬───────────────────┬─────────────────────────┤
│   type   │      length       │        payload          │
│ (1 byte) │     (2 bytes)     │     (length bytes)      │
├──────────┴───────────────────┴─────────────────────────┤
│                  [More records...]                     │
└────────────────────────────────────────────────────────┘
```

## 3. Key Data Structures

### 3.1 header_t (parser.h)
```c
typedef struct {
    uint8_t version;       // Protocol version
    uint16_t record_count; // Number of records (0-65535)
    uint8_t flags;         // Processing flags
} header_t;
```

### 3.2 record_t (record.h)
```c
typedef struct {
    uint8_t type;          // Record type identifier
    uint16_t length;       // Payload length (0-65535)
    char *payload;         // Dynamically allocated data
} record_t;
```

### 3.3 config_t (config.h)
```c
typedef struct {
    uint8_t flags;         // Runtime flags (e.g., FAST_MODE)
} config_t;
```

## 4. Configuration

### 4.1 Environment Variables
- `DATAPROC_FAST=1`: Enables FAST_MODE processing (triggers vulnerable code path)

### 4.2 Compile-time Constants
- `FAST_MODE (0x1)`: Flag indicating fast processing mode
- `MAX_RECORDS (1024)`: Maximum expected records (not enforced!)

## 5. Design Assumptions (Observed)

| Assumption | Reality | Risk |
|------------|---------|------|
| Input files are well-formed | Untrusted input possible | High |
| record_count < MAX_RECORDS | Not validated | Medium |
| fread always succeeds | May fail silently | Medium |
| Caller always frees processed output | Ownership unclear | High |
| payload is null-terminated | Not guaranteed | High |

## 6. Security-Relevant Code Paths

### 6.1 FAST_MODE Path (memory.c:13-14)
```c
if (flags & FAST_MODE) {
    memcpy(buf, rec->payload, rec->length + 1); // OFF-BY-ONE
}
```
**Risk**: Heap buffer over-read when `rec->length + 1` exceeds allocated size.

### 6.2 Ownership Ambiguity (main.c:44-45)
```c
if (i % 2 == 0)
    free(out);  // ownership ambiguity remains
```
**Risk**: Memory leak for odd-indexed records, potential use-after-free.

### 6.3 Unchecked I/O (parser.c:7-9)
```c
fread(&hdr.version, 1, 1, fp);      // No return check
fread(&hdr.record_count, 2, 1, fp); // No return check
fread(&hdr.flags, 1, 1, fp);        // No return check
```
**Risk**: Silent corruption on I/O errors or truncated files.

### 6.4 Incomplete Validation (validate.c:8-13)
```c
if (rec->length == 0) {
    stats_inc_invalid();
    return 0;
}
return 1; // does NOT validate upper bounds
```
**Risk**: Arbitrary length values accepted without bounds checking.

## 7. Build Configuration

### Standard Build
```makefile
CC=clang
CFLAGS=-g -O0 -Wall -Iinclude
```

### ASan Build
```makefile
$(CC) $(CFLAGS) -fsanitize=address src/*.c -o dataproc-agent
```

## 8. Telemetry Infrastructure

Current telemetry functions in `telemetry.c`:
- `sec_log(event, value)`: Logs security events with numeric values
- `sec_warn(msg)`: Logs warnings
- `sec_info(msg)`: Logs informational messages

**Gap**: Telemetry is not used in critical failure paths in `parse_records()`.
