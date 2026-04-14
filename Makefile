.DEFAULT_GOAL := help
SHELL:=/bin/bash

## Run all tests with ed25519 keys (default)
test: test-ed25519

## Run all tests with minisign keys
test-minisign:
	$(MAKE) check-format
	$(MAKE) clippy
	cargo nextest run
	# Some integration tests require the rest-api to accept registrations of
	# signers files served on localhost, which should not happen in production.
	# This behaviour is enabled with the test-utils features, and tests requiring
	# this localhost acceptance only run with this feature.
	$(MAKE) test-with-test-utils
	# Re-run rest-api tests with sha256 backend
	$(MAKE) -C rest-api test-sha256
	$(MAKE) -C rest-api test-with-test-utils-sha256
	KEY_TYPE=minisign $(MAKE) -C tests/e2e_tests test-local

## Run tests with test-utils feature enabled (for integration tests)
# Note that if test-utils is added to other packages, they need to be added here.
test-with-test-utils:
	cargo nextest run --features test-utils  --package rest-api --package forge-url

## Fix rust code formatting
format:
	cargo fmt --verbose

## Check rust code formatting without fixing
check-format:
	cargo fmt --check

## run clippy
clippy:
	cargo clippy

help:
	@echo "$$(tput bold)Available rules:$$(tput sgr0)"
	@echo
	@sed -n -e "/^## / { \
		h; \
		s/.*//; \
		:doc" \
		-e "H; \
		n; \
		s/^## //; \
		t doc" \
		-e "s/:.*//; \
		G; \
		s/\\n## /---/; \
		s/\\n/ /g; \
		p; \
	}" ${MAKEFILE_LIST} \
	| LC_ALL='C' sort --ignore-case \
	| awk -F '---' \
		-v ncol=$$(tput cols) \
		-v indent=19 \
		-v col_on="$$(tput setaf 6)" \
		-v col_off="$$(tput sgr0)" \
	'{ \
		printf "%s%*s%s ", col_on, -indent, $$1, col_off; \
		n = split($$2, words, " "); \
		line_length = ncol - indent; \
		for (i = 1; i <= n; i++) { \
			line_length -= length(words[i]) + 1; \
			if (line_length <= 0) { \
				line_length = ncol - indent - length(words[i]) - 1; \
				printf "\n%*s ", -indent, " "; \
			} \
			printf "%s ", words[i]; \
		} \
		printf "\n"; \
	}' \
	| more $(shell test $(shell uname) == Darwin && echo '--no-init --raw-control-chars')

## Run all tests with ed25519 keys
test-ed25519:
	$(MAKE) check-format
	$(MAKE) clippy
	KEY_TYPE=ed25519 cargo nextest run
	KEY_TYPE=ed25519 $(MAKE) test-with-test-utils
	KEY_TYPE=ed25519 $(MAKE) -C rest-api test-sha256
	KEY_TYPE=ed25519 $(MAKE) -C rest-api test-with-test-utils-sha256
	KEY_TYPE=ed25519 $(MAKE) -C tests/e2e_tests test-local

## Run mutation tests (with ed25519 keys). Select packages in .cargo/mutants.toml
test-mutants:
	KEY_TYPE=ed25519 cargo mutants --test-tool nextest

## Run client-server integration tests
client-server-tests:
	cargo test --package client-server-integration-tests

.PHONY: docs docs-serve docs-clean

## Build documentation site
docs:
	@mkdir -p docs/site/src/client-cli docs/site/src/rest-api
	@ln -sfn ../../../../client-cli/docs/howto docs/site/src/client-cli/howto
	@ln -sfn ../../../../client-cli/docs/manual docs/site/src/client-cli/manual
	@ln -sfn ../../../../rest-api/docs/manual docs/site/src/rest-api/manual
	mdbook build docs/site

## Serve documentation site locally for preview
docs-serve:
	@mkdir -p docs/site/src/client-cli docs/site/src/rest-api
	@ln -sfn ../../../../client-cli/docs/howto docs/site/src/client-cli/howto
	@ln -sfn ../../../../client-cli/docs/manual docs/site/src/client-cli/manual
	@ln -sfn ../../../../rest-api/docs/manual docs/site/src/rest-api/manual
	mdbook serve docs/site

## Remove generated documentation files
docs-clean:
	rm -rf docs/site/src/client-cli docs/site/src/rest-api docs/site/book


RCLONE_CONFIG := private/rclone.conf
## Configure rclone for deployment.
## If the configuration file at private/rclone.conf already exists if stops.
docs-setup-rclone:
	[[ ! -f $(RCLONE_CONFIG) ]]  || { echo "Config file already exists at $(RCLONE_CONFIG)"; exit 1; }
	mkdir -p private
	rclone --config $(RCLONE_CONFIG) config

## Deploy generated static site
docs-deploy: docs-clean docs
	rclone --config $(RCLONE_CONFIG) sync --verbose ./docs/site/book/ ovh:/home/asfaloc/www/doc/
