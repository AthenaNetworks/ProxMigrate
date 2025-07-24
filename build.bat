@echo off
setlocal enabledelayedexpansion

REM Proxmigrate Cross-Platform Build Script for Windows
REM Builds binaries for macOS, Linux, and Windows

echo.
echo 🚀 Proxmigrate Cross-Platform Build Script
echo.

REM Get version from git tag or use default
for /f "tokens=*" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
if "%VERSION%"=="" set VERSION=dev

REM Get build time
for /f "tokens=*" %%i in ('powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC"') do set BUILD_TIME=%%i

set BUILD_DIR=dist

echo Version: %VERSION%
echo Build Time: %BUILD_TIME%
echo.

REM Clean previous builds
echo 🧹 Cleaning previous builds...
if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
mkdir %BUILD_DIR%

REM Check if Go is installed
go version >nul 2>&1
if errorlevel 1 (
    echo ❌ Go is not installed or not in PATH
    exit /b 1
)

REM Clean up dependencies
echo 🧹 Cleaning up Go modules...
go mod tidy

echo 🔨 Starting cross-platform builds...
echo.

REM Build function simulation using labels
call :build_binary darwin amd64 ""
call :build_binary darwin arm64 ""
call :build_binary linux amd64 ""
call :build_binary linux arm64 ""
call :build_binary windows amd64 ".exe"

echo.
echo 🎉 Build completed successfully!
echo 📁 Build artifacts are in the %BUILD_DIR%/ directory
echo.

REM Show build summary
echo 📊 Build Summary:
dir /b %BUILD_DIR%\*.tar.gz %BUILD_DIR%\*.zip 2>nul

echo.
echo ✨ Ready for distribution!
echo Each archive contains the executable, config, SSH keys, and README
goto :eof

:build_binary
set os=%1
set arch=%2
set ext=%3
set output_name=proxmigrate-%VERSION%-%os%-%arch%%ext%

echo 🔨 Building for %os%/%arch%...

set GOOS=%os%
set GOARCH=%arch%
go build -ldflags="-s -w -X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME%" -o "%BUILD_DIR%\%output_name%" main.go

if errorlevel 1 (
    echo ❌ Failed to build for %os%/%arch%
    goto :eof
)

echo ✅ Successfully built %output_name%

REM Create platform-specific directory
set platform_dir=%BUILD_DIR%\%os%-%arch%
mkdir "%platform_dir%"

REM Copy binary to platform directory
copy "%BUILD_DIR%\%output_name%" "%platform_dir%\proxmigrate%ext%"

REM Copy config files and SSH key to each platform directory
copy config.json "%platform_dir%\"
copy proxmigrate_key "%platform_dir%\"
copy proxmigrate_key.pub "%platform_dir%\"

REM Create README for each platform
(
echo # Proxmigrate %VERSION% - %os%/%arch%
echo.
echo ## Quick Start
echo.
echo 1. Add the public key to your Proxmox servers:
echo    ```bash
echo    # Copy the contents of proxmigrate_key.pub to ~/.ssh/authorized_keys on each Proxmox server
echo    cat proxmigrate_key.pub
echo    ```
echo.
echo 2. Update config.json with your server details if needed
echo.
echo 3. Run a migration:
echo    ```bash
echo    ./proxmigrate --source=ara-asp-pxnode1 --target=ara-asp-pve15 --vmid=109
echo    ```
echo.
echo ## Files Included
echo.
echo - `proxmigrate%ext%` - Main executable
echo - `config.json` - Configuration file with server definitions
echo - `proxmigrate_key` - Private SSH key for server authentication
echo - `proxmigrate_key.pub` - Public SSH key ^(add to Proxmox servers^)
echo - `README.md` - This file
echo.
echo ## Configuration
echo.
echo The tool automatically finds config.json in the same directory as the executable.
echo No need to specify --config flag.
echo.
echo Available servers:
echo - Sources/Targets: ara-asp-pve15, ara-asp-pve16, ara-asp-pve17, ara-asp-pve18
echo - Sources/Targets: ara-asp-pxnode1, ara-asp-pxnode2, ara-asp-pxnode3, ara-asp-pxnode4
) > "%platform_dir%\README.md"

REM Create archive
cd %BUILD_DIR%
if "%os%"=="windows" (
    powershell -Command "Compress-Archive -Path '%os%-%arch%' -DestinationPath '%output_name%.zip' -Force"
    echo 📦 Created %output_name%.zip
) else (
    REM For non-Windows platforms, create tar.gz using PowerShell or 7zip if available
    where tar >nul 2>&1
    if not errorlevel 1 (
        tar -czf "%output_name%.tar.gz" "%os%-%arch%/"
        echo 📦 Created %output_name%.tar.gz
    ) else (
        powershell -Command "Compress-Archive -Path '%os%-%arch%' -DestinationPath '%output_name%.zip' -Force"
        echo 📦 Created %output_name%.zip ^(tar not available, using zip^)
    )
)
cd ..

goto :eof
