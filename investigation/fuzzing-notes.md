# Fuzzing Notes

## Investigation Target: dataproc-agent
## Date: December 16, 2025

---

## 1. Fuzzing Strategy

### 1.1 Target Selection

The `dataproc-agent` is an ideal fuzzing target because:
- It processes untrusted binary input from files
- It has a well-defined input format (header + records)
- It performs memory allocations based on input-controlled sizes
- It has environment-dependent code paths (FAST_MODE)

### 1.2 Build Commands

```bash
# AFL++ build with ASan
CC=afl-clang-fast CFLAGS="-g -O0 -fsanitize=address" make

# libFuzzer build
clang -g -O0 -fsanitize=fuzzer,address -Iinclude src/*.c -o fuzz_dataproc
```

## 2. Fuzzing Results

### Crash 1: Heap Buffer Over-Read (FAST_MODE)

**Trigger:** Set `DATAPROC_FAST=1` and provide any valid record

**Input (hex):**
```
01 01 00 00 01 0A 00 41 41 41 41 41 41 41 41 41 41
```

**ASan Output:**
```
==54321==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000001a
READ of size 11 at 0x602000000010 thread T0
    #0 0x4a8721 in __asan_memcpy
    #1 0x4f8a43 in process_record memory.c:14
```

**Root Cause:** Off-by-one in `memcpy(buf, rec->payload, rec->length + 1)`

## 3. Why This Bug Requires Fuzzing

1. **Environmental Condition:** Requires `DATAPROC_FAST=1`
2. **Edge Case Trigger:** 1-byte over-read is subtle
3. **No Visible Symptom:** Without sanitizers, program appears to work

## 4. Artifacts

Crash inputs located in evidence/fuzzing/
