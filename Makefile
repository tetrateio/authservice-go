# Copyright 2024 Tetrate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PKG	   	   ?= ./cmd
BUILD_OPTS ?=
TEST_OPTS  ?=
TEST_PKGS  ?= $(shell go list ./... | grep -v /e2e)
OUTDIR     ?= bin

include env.mk    # Load common variables


##@ Build targets

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS:%=$(OUTDIR)/$(NAME)-%)  ## Build all the binaries

.PHONY: static
static: $(TARGETS:%=$(OUTDIR)/$(NAME)-static-%)  ## Build all the static binaries

$(OUTDIR):
	@mkdir -p $@

$(OUTDIR)/$(NAME)-%: GOOS=$(word 1,$(subst -, ,$(subst $(NAME)-,,$(@F))))
$(OUTDIR)/$(NAME)-%: GOARCH=$(word 2,$(subst -, ,$(subst $(NAME)-,,$(@F))))
$(OUTDIR)/$(NAME)-%: $(OUTDIR)
	@echo "Build $(@F)"
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_OPTS) -o $@ $(PKG)

$(OUTDIR)/$(NAME)-static-%: GOOS=$(word 1,$(subst -, ,$(subst $(NAME)-static-,,$(@F))))
$(OUTDIR)/$(NAME)-static-%: GOARCH=$(word 2,$(subst -, ,$(subst $(NAME)-static-,,$(@F))))
$(OUTDIR)/$(NAME)-static-%: $(OUTDIR)
	@echo "Build $(@F)"
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_OPTS) \
		-ldflags '-s -w -extldflags "-static"' -tags "netgo" \
		-o $@ $(PKG)

.PHONY: clean
clean: clean/e2e  ## Clean the build artifacts
	@rm -rf $(OUTDIR)

.PHONY: clean/coverage
clean/coverage:  ## Clean the coverage report
	@rm -rf $(OUTDIR)/coverage

.PHONY: clean/all
clean/all: clean config/clean   ## Clean everything
	@rm -rf $(OUTDIR)

.PHONY: clean/e2e
clean/e2e:  ## Clean the e2e test artifacts
	@$(MAKE) -C $(@F) $(@D)


##@ Config Proto targets

.PHONY: config/build
config/build:  ## Build the API
	@$(MAKE) -C $(@D) $(@F)

.PHONY: config/clean
config/clean:  ## Clean the Config Proto generated code
	@$(MAKE) -C $(@D) $(@F)

.PHONY: config/lint
config/lint:  ## Lint the Config Proto generated code
	@$(MAKE) -C $(@D) $(@F)


##@ Test targets

.PHONY: test
test:  ## Run all the tests
	@KUBEBUILDER_ASSETS="$(shell go run $(ENVTEST) use -p path)" \
		go test $(TEST_OPTS) $(TEST_PKGS)

COVERAGE_OPTS ?=
.PHONY: coverage
coverage: ## Creates coverage report for all projects
	@echo "Running test coverage"
	@mkdir -p $(OUTDIR)/$@
	@KUBEBUILDER_ASSETS="$(shell go run $(ENVTEST) use -p path)" \
		go test $(COVERAGE_OPTS) \
			-timeout 30s \
			-coverprofile $(OUTDIR)/$@/coverage.out \
			-covermode atomic \
			$(TEST_PKGS)
	@go tool cover -html="$(OUTDIR)/$@/coverage.out" -o "$(OUTDIR)/$@/coverage.html"

.PHONY: e2e
e2e:  ## Runt he e2e tests
	@$(MAKE) -C e2e e2e

e2e/%: force-e2e
	@$(MAKE) -C e2e $(@)

.PHONY: force-e2e
force-e2e:

##@ Docker targets

.PHONY: docker-pre
docker-pre: $(DOCKER_TARGETS:%=$(OUTDIR)/$(NAME)-static-%)
	@docker buildx inspect $(DOCKER_BUILDER_NAME) || \
		docker buildx create --name $(DOCKER_BUILDER_NAME) \
			--driver docker-container --driver-opt network=host \
			--buildkitd-flags '--allow-insecure-entitlement network.host' --use

comma     := ,
space     := $(empty) $(empty)
PLATFORMS := $(subst -,/,$(subst $(space),$(comma),$(DOCKER_TARGETS)))
INSECURE_REGISTRY_ARG := --output=type=registry,registry.insecure=true

.PHONY: docker
docker: $(DOCKER_TARGETS:%=docker-%)  ## Build the docker images

docker-%: PLATFORM=$(subst -,/,$(*))
docker-%: ARCH=$(notdir $(subst -,/,$(PLATFORM)))
docker-%: docker-pre $(OUTDIR)/$(NAME)-static-%
	@echo "Building Docker image $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)-$(ARCH)"
	@docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--builder $(DOCKER_BUILDER_NAME) \
		--load \
		-f Dockerfile \
		--platform $(PLATFORM) \
		-t $(DOCKER_HUB)/$(NAME):latest-$(ARCH) \
		-t $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)-$(ARCH) \
		.

.PHONY: docker-push
docker-push: docker-pre  ## Build and push the multi-arch Docker images
	@echo "Pushing Docker image $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)"
	@docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--builder $(DOCKER_BUILDER_NAME) \
		$(if $(USE_INSECURE_REGISTRY),$(INSECURE_REGISTRY_ARG),--push) \
		-f Dockerfile \
		--platform $(PLATFORMS) \
		-t $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG) \
		.

##@ Other targets

.PHONY: generate
generate: config/build  ## Run code generation targets

LINT_OPTS ?= --timeout 5m
GOLANGCI_LINT_CONFIG ?= .golangci.yml
.PHONY: lint
lint: $(GOLANGCI_LINT_CONFIG) config/lint  ## Lint checks for all Go code
	@echo "Linting Go code"
	@go run $(GOLANGCI_LINT) run $(LINT_OPTS) --build-tags "$(TEST_TAGS)" --config $(GOLANGCI_LINT_CONFIG)

.PHONY: format
format: go.mod  ## Format all Go code
	@echo "Formatting code"
	@go run $(LICENSER) apply -r "Tetrate"
	@go run $(GOSIMPORTS) -local $(GO_MODULE) -w .
	@gofmt -w .

.PHONY: check
check:  ## CI blocks merge until this passes. If this fails, run "make check" locally and commit the difference.
	@echo "Running CI checks"
	@$(MAKE) clean/all generate
	@$(MAKE) format
	@if [ ! -z "`git status -s`" ]; then \
		echo "The following differences will fail CI until committed:"; \
		git diff; \
		exit 1; \
	fi

.PHONY: help
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
			/^[.a-zA-Z0-9\/_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } \
			/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
