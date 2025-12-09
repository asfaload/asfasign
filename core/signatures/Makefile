.PHONY: check

check:
	cargo clippy --bins --tests --examples --all -- -D rust_2018_idioms -D warnings
	cargo fmt -- --check
