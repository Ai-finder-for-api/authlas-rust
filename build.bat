@echo off
rem One command to build and test authlas on Windows (MSVC + OpenSSL 3).
rem Usage:  build.bat            build release and run the test suite
rem         build.bat build      build only
rem Override any path by setting the variable before running, e.g.:
rem         set OPENSSL_DIR=D:\libs\openssl-3
setlocal

if not defined OPENSSL_DIR set "OPENSSL_DIR=%USERPROFILE%\vcpkg\installed\x64-windows"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

if not exist "%OPENSSL_DIR%\include\openssl\err.h" (
  echo OpenSSL 3 not found at "%OPENSSL_DIR%". Set OPENSSL_DIR to the folder holding include\ and lib\.
  exit /b 1
)
if not exist "%VCVARS%" (
  echo MSVC not found: "%VCVARS%". Install Visual Studio Build Tools with the C++ workload.
  exit /b 1
)
call "%VCVARS%" >nul

set "FEATURES=--no-default-features --features backend-openssl,capi,net"
cd /d "%~dp0"

cargo build --release %FEATURES%
if errorlevel 1 exit /b %errorlevel%
if /i "%~1"=="build" (
  echo Build OK.
  exit /b 0
)

cargo test --release %FEATURES%
if errorlevel 1 exit /b %errorlevel%
echo Build and tests OK.
endlocal
