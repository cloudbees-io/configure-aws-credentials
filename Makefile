ANSI_BOLD := $(if $NO_COLOR,$(shell tput bold),)
ANSI_RESET := $(if $NO_COLOR,$(shell tput sgr0),)

# Switch this to podman if you are using that in place of docker
CONTAINERTOOL := docker

MODULE_NAME := $(lastword $(subst /, ,$(shell go list -m)))

##@ Build

.PHONY: build
build: .cloudbees/staging/action.yml ## Build the container image
	@echo "⚡️ Building container image..."
	@$(CONTAINERTOOL) build --rm -t $(MODULE_NAME):v$(shell git rev-parse HEAD) -t $(MODULE_NAME):latest -f Dockerfile .
	@echo "✅ Container image built"

.PHONY: test
test: ## Runs unit tests
	@echo "⚡️ Running unit tests..."
	@go test ./...
	@echo "✅ Unit tests passed"

.cloudbees/staging/action.yml: action.yml ## Ensures that the test version of the action.yml is in sync with the production version
	@echo "⚡️ Updating $@..."
	@sed -e 's|docker://public.ecr.aws/l7o7z1g8/actions/|docker://registry.saas-dev.beescloud.com/staging/|g' < action.yml > .cloudbees/staging/action.yml

.cloudbees/workflows/workflow.yml: Dockerfile ## Ensures that the workflow uses the same version of go as the Dockerfile
	@echo "⚡️ Updating $@..."
	@IMAGE=$$(sed -ne 's/FROM[ \t]*golang:\([^ \t]*\)-alpine[0-9.]*[ \t].*/\1/p' Dockerfile) ; \
	sed -e 's|\(uses:[ \t]*docker://golang:\)[^ \t]*|\1'"$$IMAGE"'|;' < $@ > $@.bak ; \
	mv -f $@.bak $@

.PHONY: sync
sync: .cloudbees/staging/action.yml .cloudbees/workflows/workflow.yml ## Ensures that all generated files have been resynchronized
	@echo "✅ All files synchronized"

.PHONY: check-git-status
check-git-status: ## Checks if there are any uncommitted changes in the repository
	@echo "⚡️ Checking for uncommitted changes..."
	@if ! git diff-index --quiet HEAD --; then \
		echo "❌ There are uncommitted changes in the repository." ; \
		git status ; \
		exit 1; \
	fi
	@echo "✅ No uncommitted changes in the repository"

.PHONY: format
format: ## Applies the project code style
	@echo "⚡️ Applying project code style..."
	@gofmt -w .
	@echo "✅ Project code style applied"

##@ Miscellaneous

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

