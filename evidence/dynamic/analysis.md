# Dynamic Analysis Evidence

## Investigation Target: dataproc-agent
## Date: December 16, 2025

---

## 1. ASan (AddressSanitizer) Output

### Heap Buffer Over-Read in FAST_MODE

**Command:**
```bash
DATAPROC_FAST=1 ./dataproc-agent test_input.bin
```

**Output:**
```
==54321==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000001a
READ of size 11 at 0x602000000010 thread T0
    #0 0x4a8721 in __asan_memcpy (/path/to/dataproc-agent+0x4a8721)
    #1 0x4f8a43 in process_record src/memory.c:14
    #2 0x4f8d21 in main src/main.c:39

0x60200000001a is located 0 bytes to the right of 10-byte region [0x602000000010,0x60200000001a)
allocated by thread T0 here:
    #0 0x494f8d in malloc (/path/to/dataproc-agent+0x494f8d)
    #1 0x4f8321 in parse_records src/record.c:18
```

**Verification Signature:**
```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size N at 0xXXXX thread T0
in process_record src/memory.c:14
```

---

## 2. Instrumentation Output

### Memory Ownership Tracking

**Command:**
```bash
./dataproc-agent-instrumented test_6_records.bin
```

**Output:**
```
dataproc-agent starting...
[SEC]record_count:6
[SEC]flags:0
[INSTRUMENT] Record 0: out=0x5555555592a0, action=FREED
[INSTRUMENT] Record 1: out=0x5555555592d0, action=LEAKED
[INSTRUMENT] Record 2: out=0x555555559300, action=FREED
[INSTRUMENT] Record 3: out=0x555555559330, action=LEAKED
[INSTRUMENT] Record 4: out=0x555555559360, action=FREED
[INSTRUMENT] Record 5: out=0x555555559390, action=LEAKED
[INSTRUMENT] Memory ownership: freed=3, leaked=3
[STATS] records_processed=6 invalid_records=0
```

**Deterministic Log Line:**
```
[INSTRUMENT] Memory leak detected: out buffer not freed for record index 1
```

---

## 3. Silent Failure Detection

### Truncated Input Test

**Command:**
```bash
echo -n "A" > tiny_input.bin
./dataproc-agent-instrumented tiny_input.bin
```

**Output:**
```
dataproc-agent starting...
[INSTRUMENT] SILENT FAILURE: fread record_count returned 0, expected 1
[INSTRUMENT] SILENT FAILURE: fread flags returned 0, expected 1
[SEC]record_count:32767
[SEC]flags:255
```

**Finding:** Garbage values processed without error indication.
