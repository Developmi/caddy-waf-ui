# Makefile - development workflow for caddy-waf-ui.
# Every quality target is a verifier: it fails on findings instead of fixing.
# Follow the pattern of the sibling repo (caddy-waf): tool pins live in
# tools/versions.mk and binaries are installed by tools/install.sh into tools/bin.

include tools/versions.mk

TOOLS := tools/bin
UV := uv run

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo ""
	@echo "Development Commands"
	@echo "===================="
	@echo ""
	@echo "Setup"
	@echo "-----"
	@echo "  make tools          Install development tools"
	@echo "  make reinstall      Reinstall development tools"
	@echo "  make doctor         Verify development environment"
	@echo ""
	@echo "Quality"
	@echo "-------"
	@echo "  make fmt            Check Go formatting (gofmt -l)"
	@echo "  make vet            Run go vet"
	@echo "  make lint           Run all linters"
	@echo "  make lint-go        Run golangci-lint"
	@echo "  make lint-yaml      Lint YAML files"
	@echo "  make lint-actions   Lint GitHub Actions workflows"
	@echo "  make lint-docker    Lint Dockerfile"
	@echo "  make lint-security  Scan GitHub Actions for security issues"
	@echo ""
	@echo "Testing"
	@echo "-------"
	@echo "  make test           Run unit tests"
	@echo "  make test-race      Run unit tests with the race detector"
	@echo "  make vuln           Check for known vulnerabilities"
	@echo ""
	@echo "Build"
	@echo "-----"
	@echo "  make build          Compile all packages"
	@echo "  make docker-build   Build the Docker image"
	@echo "  make compose-config Validate the docker-compose configuration"
	@echo ""
	@echo "Release"
	@echo "-------"
	@echo "  make release-ready  Run the full pre-push gate"
	@echo ""

.PHONY: tools
tools:                                   # Install pinned development tools into tools/bin
	@ACTIONLINT_VERSION=$(ACTIONLINT_VERSION) \
	HADOLINT_VERSION=$(HADOLINT_VERSION) \
	GOLANGCI_VERSION=$(GOLANGCI_VERSION) \
	./tools/install.sh
	@echo "✓ Development tools are ready."

.PHONY: reinstall
reinstall:                               # Force reinstall of all development tools
	@REINSTALL=1 $(MAKE) tools
	@echo "✓ Development tools reinstalled."

.PHONY: doctor
doctor:                                  # Print toolchain and tool versions
	@test -x $(TOOLS)/actionlint || $(MAKE) --no-print-directory tools
	@printf "\n"
	@printf "Development Environment\n"
	@printf "=======================\n\n"
	@printf "%-18s %s\n" "go" "$$(go version | awk '{print $$3}')"
	@printf "%-18s %s\n" "uv" "$$(uv --version | awk '{print $$2}')"
	@printf "%-18s %s\n" "Docker" "$$(docker version --format '{{.Client.Version}}')"
	@printf "%-18s %s\n" "golangci-lint" "$$($(TOOLS)/golangci-lint version | awk '{print $$4}')"
	@printf "%-18s %s\n" "hadolint" "$$($(TOOLS)/hadolint --version | awk '{print $$NF}')"
	@printf "%-18s %s\n" "actionlint" "$$($(TOOLS)/actionlint -version | head -1)"
	@printf "%-18s %s\n" "govulncheck" "$$($(TOOLS)/govulncheck -version 2>/dev/null | head -1)"
	@printf "%-18s %s\n" "yamllint" "$$(uv run yamllint --version | awk '{print $$2}')"
	@printf "%-18s %s\n" "zizmor" "$$(uv run zizmor --version | awk '{print $$2}')"
	@echo

.PHONY: fmt
fmt:                                     # Check Go formatting; lists unformatted files and exits 1 (fix with gofmt -w)
	@echo "==> Go format"
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "✓ Go formatting passed."

.PHONY: vet
vet:                                     # Run go vet static analysis
	@echo "==> Go vet"
	@go vet ./...
	@echo "✓ go vet passed."

.PHONY: lint-go
lint-go:                                 # Run golangci-lint on all Go packages
	@echo "==> Go"
	@$(TOOLS)/golangci-lint run ./...
	@echo "✓ Go lint passed."

.PHONY: lint-yaml
lint-yaml:                               # Lint all YAML files
	@echo "==> YAML"
	@$(UV) yamllint .
	@echo "✓ YAML lint passed."

.PHONY: lint-actions
lint-actions:                            # Lint GitHub Actions workflows (no-op until .github/workflows exists)
	@echo "==> GitHub Actions"
	@if [ -d .github/workflows ]; then \
		$(TOOLS)/actionlint; \
	else \
		echo "No .github/workflows directory yet; skipping actionlint."; \
	fi
	@echo "✓ GitHub Actions lint passed."

.PHONY: lint-docker
lint-docker:                             # Lint the Dockerfile
	@echo "==> Docker"
	@$(TOOLS)/hadolint --failure-threshold warning Dockerfile
	@echo "✓ Docker lint passed."

.PHONY: lint-security
lint-security:                           # Scan GitHub Actions for security issues (no-op until .github/workflows exists)
	@echo "==> Security"
	@if [ -d .github/workflows ]; then \
		$(UV) zizmor .; \
	else \
		echo "No .github/workflows directory yet; skipping zizmor."; \
	fi
	@echo "✓ Security lint passed."

.PHONY: lint
lint: lint-go lint-yaml lint-actions lint-docker lint-security   # Run all linters
	@echo
	@echo "✓ All lint checks passed."

.PHONY: test
test:                                    # Run unit tests
	@echo "==> Tests"
	@go test ./...
	@echo "✓ Tests passed."

.PHONY: test-race
test-race:                               # Run unit tests with the race detector
	@echo "==> Tests (race)"
	@go test -race ./...
	@echo "✓ Race tests passed."

.PHONY: vuln
vuln:                                    # Check dependencies for known vulnerabilities
	@echo "==> Vulnerabilities"
	@$(TOOLS)/govulncheck ./...
	@echo "✓ Vulnerability scan passed."

.PHONY: build
build:                                   # Compile all packages
	@echo "==> Build"
	@go build ./...
	@echo "✓ Build passed."

.PHONY: docker-build
docker-build:                            # Build the local Docker image
	@echo "==> Docker build"
	@docker build -t caddy-waf-ui:local .
	@echo "✓ Docker build passed."

.PHONY: compose-config
compose-config:                          # Validate the docker-compose configuration
	@echo "==> Compose config"
	@docker compose config --quiet
	@echo "✓ Compose config passed."

.PHONY: release-ready
release-ready: fmt vet lint vuln test-race compose-config build docker-build   # Run the full pre-push gate: fmt, vet, lint, vuln, race tests, compose, builds
	@echo
	@echo "✓ Release-ready gate passed."
