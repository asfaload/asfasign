.DEFAULT_GOAL := help
SHELL:=/bin/bash

## Run tests of all components
test:
	$(MAKE) clippy
	$(MAKE) check-format

	cargo nextest run
	# Some integration tests require the rest-api to accept registrations of
	# signers files served on localhost, which should not happen in production.
	# This behaviour is enabled with the test-utils features, and tests requiring
	# this localhost acceptance only run with this feature.
	$(MAKE) test-with-test-utils

## Run tests with test-utils feature enabled (for integration tests)
test-with-test-utils:
	cargo nextest run --features test-utils

## Fix rust code formatting
format:
	cargo fmt --verbose

## Check rust code formatting without fixing
check-format:
	cargo fmt --check

## run clippy
clippy:
	cargo clippy

## Run client-server integration tests
client-server-tests:
	cargo test --package client-server-integration-tests

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
