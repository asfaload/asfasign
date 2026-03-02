.DEFAULT_GOAL := help
SHELL := /bin/bash

TESTS := basic_flow.sh signers_update_by_master.sh
KEY_TYPES ?= minisign ed25519

## Run all e2e tests with both oid formats and all key types
test: test-sha1 test-sha256

## Run all e2e tests with sha1 oids (all key types)
test-sha1:
	@for kt in $(KEY_TYPES); do \
		for t in $(TESTS); do \
			printf '\n══ Running %s (sha1, %s) ══\n\n' "$$t" "$$kt"; \
			KEY_TYPE=$$kt ./$$t || exit 1; \
		done; \
	done

## Run all e2e tests with sha256 oids (all key types)
test-sha256:
	@for kt in $(KEY_TYPES); do \
		for t in $(TESTS); do \
			printf '\n══ Running %s (sha256, %s) ══\n\n' "$$t" "$$kt"; \
			ASFALOAD_GIT_BACKEND=sha256 KEY_TYPE=$$kt ./$$t || exit 1; \
		done; \
	done

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
	}'
