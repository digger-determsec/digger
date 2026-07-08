@echo off
REM Digger Quality Gates — runs all validation checks
REM Usage: quality-gates.bat [--full]
REM 
REM Checks performed:
REM 1. Build full workspace
REM 2. Run benchmark suite
REM 3. Verify ingestion integrity
REM 4. Run cargo check (zero warnings)
REM 5. Run cargo test (all tests pass)

setlocal enabledelayedexpansion
set "FAILED=0"
set "PASSED=0"

echo ═══════════════════════════════════════════════════════
echo   DIGGER QUALITY GATES
echo ═══════════════════════════════════════════════════════
echo.

REM 1. Build
echo [1/5] Building workspace...
cargo build --release 2>nul
if %ERRORLEVEL% neq 0 (
    echo   FAIL: Build failed
    set /a FAILED+=1
) else (
    echo   PASS: Build succeeded
    set /a PASSED+=1
)

REM 2. Cargo check (zero warnings)
echo [2/5] Checking warnings...
cargo check 2>check_output.txt
findstr /C:"warning" check_output.txt >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   FAIL: Warnings detected
    type check_output.txt | findstr /C:"warning"
    set /a FAILED+=1
) else (
    echo   PASS: Zero warnings
    set /a PASSED+=1
)
del check_output.txt 2>nul

REM 3. Run tests
echo [3/5] Running tests...
cargo test 2>nul
if %ERRORLEVEL% neq 0 (
    echo   FAIL: Tests failed
    set /a FAILED+=1
) else (
    echo   PASS: All tests passed
    set /a PASSED+=1
)

REM 4. Run benchmark
echo [4/5] Running benchmark suite...
.\target\release\digger.exe benchmark 2>bench_output.txt
findstr /C:"ALL CASES PASSED" bench_output.txt >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   FAIL: Benchmark failed
    set /a FAILED+=1
) else (
    echo   PASS: All benchmark cases passed
    set /a PASSED+=1
)
del bench_output.txt 2>nul

REM 5. Ingestion integrity
echo [5/5] Verifying ingestion integrity...
.\target\release\digger.exe ingest validate 2>nul
if %ERRORLEVEL% neq 0 (
    echo   FAIL: Ingestion validation failed
    set /a FAILED+=1
) else (
    echo   PASS: Ingestion integrity verified
    set /a PASSED+=1
)

echo.
echo ═══════════════════════════════════════════════════════
echo   RESULTS: %PASSED% passed, %FAILED% failed
echo ═══════════════════════════════════════════════════════

if %FAILED% gtr 0 (
    echo   VERDICT: FAIL — regressions detected
    exit /b 1
) else (
    echo   VERDICT: PASS — all quality gates passed
    exit /b 0
)
