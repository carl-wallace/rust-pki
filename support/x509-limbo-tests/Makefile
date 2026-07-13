test-rust-certval:
	@cargo build --bin rust-certval-harness
	$(MAKE) -C ../x509-limbo run ARGS="harness '$(CURDIR)/target/debug/rust-certval-harness' --output '$(CURDIR)/rust-certval.json'"
