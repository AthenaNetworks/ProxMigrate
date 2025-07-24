#!/bin/bash

# Proxmigrate Cross-Platform Build Script
# Builds binaries for macOS, Linux, and Windows

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get version from git tag or use default
VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DIR="dist"

echo -e "${BLUE}Proxmigrate Cross-Platform Build Script${NC}"
echo -e "${BLUE}Version: ${VERSION}${NC}"
echo -e "${BLUE}Build Time: ${BUILD_TIME}${NC}"
echo ""

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Build function
build_binary() {
    local os=$1
    local arch=$2
    local ext=$3
    local output_name="proxmigrate-${VERSION}-${os}-${arch}${ext}"
    
    echo -e "${BLUE}Building for ${os}/${arch}...${NC}"
    
    GOOS=${os} GOARCH=${arch} go build \
        -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
        -o "${BUILD_DIR}/${output_name}" \
        main.go
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully built ${output_name}${NC}"
        
        # Create platform-specific directory
        platform_dir="${BUILD_DIR}/${os}-${arch}"
        mkdir -p "${platform_dir}"
        
        # Copy binary to platform directory
        cp "${BUILD_DIR}/${output_name}" "${platform_dir}/proxmigrate${ext}"

        cp config.json.example "${platform_dir}/config.json"
        cp README.md "${platform_dir}/README.md"
        if [ -f "proxmigrate_key" ] && [ -f "proxmigrate_key.pub" ]; then
            cp proxmigrate_key "${platform_dir}/proxmigrate_key"
            cp proxmigrate_key.pub "${platform_dir}/proxmigrate_key.pub"
        fi

        # Set executable permissions on Unix systems
        if [ "${os}" != "windows" ]; then
            chmod +x "${platform_dir}/proxmigrate${ext}"
            if [ -f "${platform_dir}/proxmigrate_key" ] && [ -f "${platform_dir}/proxmigrate_key.pub" ]; then
                chmod 600 "${platform_dir}/proxmigrate_key"
                chmod 644 "${platform_dir}/proxmigrate_key.pub"
            fi
        fi
        
        # Create archive
        cd "${BUILD_DIR}"
        if [ "${os}" = "windows" ]; then
            zip -r "${output_name}.zip" "${os}-${arch}/"
            echo -e "${GREEN}Created ${output_name}.zip${NC}"
        else
            tar -czf "${output_name}.tar.gz" "${os}-${arch}/"
            echo -e "${GREEN}Created ${output_name}.tar.gz${NC}"
        fi
        cd ..
        
    else
        echo -e "${RED}Failed to build for ${os}/${arch}${NC}"
        return 1
    fi
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Go is not installed or not in PATH${NC}"
    exit 1
fi

# Clean up dependencies
echo -e "${YELLOW}Cleaning up Go modules...${NC}"
go mod tidy

# Build for different platforms
echo -e "${YELLOW}Starting cross-platform builds...${NC}"
echo ""

# macOS
build_binary "darwin" "amd64" ""
build_binary "darwin" "arm64" ""

# Linux
build_binary "linux" "amd64" ""
build_binary "linux" "arm64" ""

# Windows
build_binary "windows" "amd64" ".exe"

echo ""
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${BLUE}Build artifacts are in the ${BUILD_DIR}/ directory${NC}"
echo ""

# Show build summary
echo -e "${YELLOW}Build Summary:${NC}"
ls -la ${BUILD_DIR}/*.tar.gz ${BUILD_DIR}/*.zip 2>/dev/null || true
echo ""

# Calculate total size
total_size=$(du -sh ${BUILD_DIR} | cut -f1)
echo -e "${BLUE}Total build size: ${total_size}${NC}"

echo ""
echo -e "${GREEN}Ready for distribution!${NC}"
echo -e "${BLUE}Each archive contains the executable, config, SSH keys, and README${NC}"
