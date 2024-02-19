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

root		:= $(shell git rev-parse --show-toplevel)
auth0_dir	:= $(root)/e2e/auth0
build_dir	:= $(auth0_dir)/build
certs_dir	:= $(auth0_dir)/build/certs

CA_FILES	:= $(addprefix $(certs_dir)/,ca.crt ca.key)
CERT_FILES	:= $(addprefix $(certs_dir)/,server.crt server.key server.csr)
ALT_NAME	:= localhost

SHELL := bash

## Look for targets not defined in this file in ../suite.mk
%:
	@$(MAKE) -f ../suite.mk $@

## Overrides from ../suite.mk

.PHONY: e2e
e2e: e2e-pre
	@$(MAKE) e2e-test

.PHONY: e2e-test
e2e-test:
	@echo "Unable to run e2e for external oidc since it requires browser login"
	@echo "Please run the tests manually using the following command:"
	@echo "open https://localhost:8443"
	@exit 1
	@#go test $(E2E_TEST_OPTS) ./... || ( $(MAKE) e2e-post-error; exit 1 )

.PHONY: e2e-pre
e2e-pre: gen
	@#docker compose up --detach --wait --force-recreate --remove-orphans || ($(MAKE) e2e-post-error; exit 1)
	@$(MAKE) -f ../suite.mk e2e-pre

.PHONY: clean
clean: ## Cleans All
	rm -rf $(build_dir) .logs


## Original targets

.PHONY: clean/ca clean/certs gen gen/ca gen/certs gen/auth0 require-file-%

clean/ca: ## Cleans the CA cert files
	@rm -rf $(CA_FILES)

clean/certs: ## Cleans the certs files (not the CA)
	@rm -rf $(CERTS_FILES)

clean/auth0: ## Cleans the auth0 config file
	@rm -rf $(build_dir)/config

$(certs_dir):
	@mkdir -p $(certs_dir)

$(build_dir)/config:
	@mkdir -p $(build_dir)/config

gen: gen/auth0 gen/ca gen/certs ## Generates all certs

CONFIG_FILES := authz-config.json envoy-config.yaml envoy-auth0-config.yaml
gen/auth0: $(build_dir)/config $(addprefix $(build_dir)/config/, $(CONFIG_FILES)) ## Generates the auth0 config files

$(build_dir)/config/%: require-file-variables.env
	@echo "Generating $* config"
	@export $$(cat $(auth0_dir)/variables.env | xargs) && envsubst < $(auth0_dir)/$* > $(build_dir)/config/$*


gen/ca: $(certs_dir) $(CA_FILES) ## Generates the CA cert files

$(CA_FILES):
	@echo "Generating CA"
	@openssl genrsa -out "$(certs_dir)/ca.key" 4096
	@openssl req -x509 -new -sha256 -nodes -days 365 -key "$(certs_dir)/ca.key" -out "$(certs_dir)/ca.crt" \
		-subj "/C=US/ST=California/O=Tetrate/OU=Engineering/CN=$(ALT_NAME)" \
		-addext "basicConstraints=critical,CA:true,pathlen:1" \
		-addext "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,keyCertSign" \
		-addext "subjectAltName=DNS:$(ALT_NAME)"


gen/certs: $(certs_dir) $(CERT_FILES)  ## Generates the certs files

$(certs_dir)/%.crt $(certs_dir)/%.key $(certs_dir)/%.csr:
	@echo "Generating $(*) cert"
	@openssl genrsa -out "$(certs_dir)/$(*).key" 2048
	@openssl req -new -sha256 -key "$(certs_dir)/$(*).key" -out "$(certs_dir)/$(*).csr" \
		-subj "/C=US/ST=California/O=Tetrate/OU=Engineering/CN=$(ALT_NAME)" \
		-addext "subjectAltName=DNS:$(ALT_NAME)"
	@openssl x509 -req -sha256 -days 120 -in "$(certs_dir)/$(*).csr" -out "$(certs_dir)/$(*).crt" \
		-CA "$(certs_dir)/ca.crt" -CAkey "$(certs_dir)/ca.key" -CAcreateserial -CAserial $(certs_dir)/ca.srl \
		-extfile <(printf "subjectAltName=DNS:$(ALT_NAME)")

require-file-%:
	@if [ ! -f $(auth0_dir)/$* ]; then echo "File $(auth0_dir)/$* is required"; exit 1; fi
