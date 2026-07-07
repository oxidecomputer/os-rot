#!/bin/bash
#:
#: name = "build-and-test"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/out/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build

ptime -m cargo build --release --verbose

banner test

ptime -m cargo test --verbose

banner test (miri)

ptime -m cargo +nightly miri test

