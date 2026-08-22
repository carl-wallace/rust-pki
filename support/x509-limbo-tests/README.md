# certval harness for x509-limbo

This directory holds `rust-certval-harness`, which runs the
[x509-limbo](https://github.com/C2SP/x509-limbo) testsuite against `certval`. The testsuite itself
is the `support/x509-limbo` submodule beside it; that submodule also carries upstream's harnesses
for other implementations, and none of those are this one.

## Running it

```sh
git submodule update --init support/x509-limbo
make -C support/x509-limbo-tests
```

`cargo build` on its own only produces the binary. The `Makefile` is what hands it to the
testsuite's own runner, which then writes the outcome of every case to `rust-certval.json`.

## `rust-certval.json` is committed on purpose

CI regenerates the file and runs `git diff --exit-code` on it (`.github/workflows/certval.yml`), so
a run that leaves it dirty means certval now reaches a different conclusion somewhere in the
testsuite — not that the build broke. Read the diff, and commit it alongside the change that caused
it.
