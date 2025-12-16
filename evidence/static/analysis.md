# Static Analysis Evidence

## Investigation Target: dataproc-agent
## Date: December 16, 2025

---

## 1. Code Review Findings

### 1.1 Unchecked Return Values

**File:** `src/parser.c` (lines 7-9)
```c
fread(&hdr.version, 1, 1, fp);      // Return value ignored
fread(&hdr.record_count, 2, 1, fp); // Return value ignored
fread(&hdr.flags, 1, 1, fp);        // Return value ignored
```
**Issue:** CWE-252 - Unchecked Return Value

### 1.2 Off-by-One Read

**File:** `src/memory.c` (line 14)
```c
memcpy(buf, rec->payload, rec->length + 1); // OFF-BY-ONE
```
**Issue:** CWE-126 - Buffer Over-read

### 1.3 Incomplete Validation

**File:** `src/validate.c` (line 13)
```c
return 1; // does NOT validate upper bounds
```
**Issue:** CWE-20 - Improper Input Validation

### 1.4 Memory Leak Pattern

**File:** `src/main.c` (lines 44-45)
```c
if (i % 2 == 0)
    free(out);  // ownership ambiguity remains
```
**Issue:** CWE-401 - Memory Leak

## 2. Grep Search Results

### MAX_RECORDS Definition vs Usage
```
$ grep -n "MAX_RECORDS" include/*.h src/*.c
include/common.h:10:#define MAX_RECORDS 1024
```
**Finding:** MAX_RECORDS is defined but never used in validation

### Telemetry Coverage
```
$ grep -n "sec_log\|sec_warn\|sec_info" src/*.c
src/config.c:13:        sec_info("FAST_MODE enabled");
src/parser.c:11:    sec_log("record_count", hdr.record_count);
src/parser.c:12:    sec_log("flags", hdr.flags);
src/record.c:8:        sec_warn("record_alloc_failed");
```
**Finding:** Only 4 telemetry calls in entire codebase
