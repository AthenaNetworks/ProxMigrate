# Proxmigrate Makefile
# Simple build automation for cross-platform builds

.PHONY: all build clean test help

# Default target
all: build

# Build for all platforms
build:
	@echo "🚀 Building Proxmigrate for all platforms..."
	@./build.sh

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf dist/
	@rm -f proxmigrate

# Test the application
test:
	@echo "🧪 Running tests..."
	@go test -v ./...

# Build for current platform only (development)
dev:
	@echo "🔨 Building for current platform..."
	@go build -o proxmigrate main.go
	@echo "✅ Built proxmigrate for current platform"

# Run the application (development)
run:
	@go run main.go

# Format code
fmt:
	@echo "🎨 Formatting code..."
	@go fmt ./...

# Lint code
lint:
	@echo "🔍 Linting code..."
	@golangci-lint run || echo "golangci-lint not installed, skipping..."

# Tidy dependencies
tidy:
	@echo "🧹 Tidying Go modules..."
	@go mod tidy

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	@go mod download

# Show help
help:
	@echo "Proxmigrate Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all     - Build for all platforms (default)"
	@echo "  build   - Build for all platforms"
	@echo "  clean   - Clean build artifacts"
	@echo "  test    - Run tests"
	@echo "  dev     - Build for current platform only"
	@echo "  run     - Run the application"
	@echo "  fmt     - Format code"
	@echo "  lint    - Lint code"
	@echo "  tidy    - Tidy Go modules"
	@echo "  deps    - Install dependencies"
	@echo "  help    - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make build    # Build for all platforms"
	@echo "  make dev      # Quick build for development"
	@echo "  make clean    # Clean up build files"
