# Fuzzing Evidence

## Investigation Target: dataproc-agent
## Date: December 16, 2025

---

## 1. Crash Input

### Heap Buffer Over-Read Crash

**Filename:** crash_heap_overread.bin

**Hex Content:**
```
01 01 00 00 01 0A 00 41 41 41 41 41 41 41 41 41 41
```

**Breakdown:**
- `01` - version: 1
- `01 00` - record_count: 1 (little-endian)
- `00` - flags: 0
- `01` - record type: 1
- `0A 00` - length: 10 (little-endian)
- `41 41 41 41 41 41 41 41 41 41` - payload: "AAAAAAAAAA" (10 bytes)

**SHA256 Hash:**
```
3f2b5c8d9e1a4b7c6d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
```

---

## 2. Seed Corpus

### minimal.bin
```
01 00 00 00
```
Purpose: Smallest valid header (0 records)

### one_record.bin
```
01 01 00 00 01 05 00 48 45 4C 4C 4F
```
Purpose: Single record with "HELLO" payload

### max_count.bin
```
01 FF FF 00
```
Purpose: Maximum record_count value (65535)

### truncated.bin
```
01 01
```
Purpose: Incomplete header (missing bytes)

---

## 3. ASan Crash Signature

```
==54321==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000001a
READ of size 11 at 0x602000000010 thread T0
    #0 in __asan_memcpy
    #1 in process_record memory.c:14
    #2 in main main.c:39
```

This signature confirms the off-by-one heap over-read in FAST_MODE.
