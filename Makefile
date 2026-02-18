.PHONY: build clean test run install

# Build variables
BINARY_NAME=snyft
BUILD_DIR=.
GO=go

# Build the project
build:
	CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) .

# Clean build artifacts
clean:
	$(GO) clean
	rm -f $(BUILD_DIR)/$(BINARY_NAME)

# Run tests
test:
	$(GO) test -v ./...

# Run the tool
run:
	$(GO) run main.go

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Install the binary
install:
	$(GO) install .

# Format code
fmt:
	$(GO) fmt ./...

# Lint code
lint:
	golangci-lint run

# Build for multiple platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

# Help
help:
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run tests"
	@echo "  run        - Run the tool"
	@echo "  deps       - Install/update dependencies"
	@echo "  install    - Install binary to GOPATH"
	@echo "  fmt        - Format code"
	@echo "  lint       - Lint code"
	@echo "  build-all  - Build for multiple platforms"
	@echo "  help       - Show this help message"
