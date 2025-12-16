# MSSVA Day 4 - Security Investigation Report

## Software Security Lab 
**Role:** Security Researcher  
**Investigation Target:** dataproc-agent  
**Date:** December 16, 2025

---

## Overview

This repository contains a comprehensive security investigation of the `dataproc-agent` system, a C-based internal data preprocessing service used for batch ingestion.

## Investigation Summary

The investigation identified **5 mandatory security flags** through static analysis, dynamic analysis, instrumentation, and fuzzing:

| Flag | Title | Severity |
|------|-------|----------|
| Design Assumption Broken | Unbounded Record Length Validation | High |
| Telemetry Gap Identified | Silent Parse Failure Without Logging | Medium |
| Memory Ownership Violation | Inconsistent Ownership in Main Loop | High |
| Silent Failure Detected | Unchecked fread Return Values in Header Parsing | Medium |
| Fuzzer-Only Bug Explained | Heap Buffer Over-Read in FAST_MODE | Critical |

## Repository Structure

```
mssva-day4-s11-14/
├── README.md                  # This file
├── investigation/
│   ├── system-overview.md     # System architecture and design
│   ├── findings.md            # Detailed findings for all 5 flags
│   ├── telemetry-gaps.md      # Analysis of observability gaps
│   ├── fuzzing-notes.md       # Fuzzing methodology and results
│   └── reflection.md          # Security insights and lessons
├── evidence/
│   ├── static/                # Static analysis artifacts
│   ├── dynamic/               # Dynamic analysis artifacts
│   └── fuzzing/               # Fuzzing inputs and crash data
└── instrumented/              # Instrumented source code
    ├── src/
    └── include/
```

## Key Findings

### 1. Design Assumption Broken
The `validate_record()` function does not check if `rec->length` exceeds `MAX_RECORDS` or any reasonable bound, violating the implicit design assumption that input is well-formed.

### 2. Telemetry Gap Identified
Critical failures in `parse_records()` (failed fread, failed malloc) occur without any logging or telemetry, making debugging impossible.

### 3. Memory Ownership Violation
In `main.c`, the `out` buffer is only freed for even-indexed records (`i % 2 == 0`), causing memory leaks and ownership ambiguity.

### 4. Silent Failure Detected
In `parse_header()`, `fread()` return values are not checked, allowing partial reads to silently produce corrupted header data.

### 5. Fuzzer-Only Bug Explained
In FAST_MODE, `memcpy(buf, rec->payload, rec->length + 1)` reads one byte beyond the allocated payload buffer—a classic off-by-one heap over-read.

## Build & Test

### Build with ASan
```bash
cd dataproc-agent
make asan
```

### Run with Test Input
```bash
DATAPROC_FAST=1 ./dataproc-agent test_input.bin
```

## Verification Signature

**ASan Error Signature (Fuzzer-Only Bug):**
```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xXXXX
READ of size N at 0xXXXX thread T0
```

**Instrumentation Log Line:**
```
[INSTRUMENT] Memory leak detected: out buffer not freed for record index 1
```

