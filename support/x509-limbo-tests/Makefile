test-rust-certval:
	@cargo build --bin rust-certval-harness
	$(MAKE) -C ../x509-limbo run ARGS="harness '$(shell realpath -m ./target/debug/rust-certval-harness)' --output '$(shell realpath ./rust-certval.json)'"
