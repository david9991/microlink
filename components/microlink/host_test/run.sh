#!/bin/sh
# Build and run the host tests: the parts of MicroLink that are pure
# functions, with the host's C compiler. From anywhere: sh components/microlink/host_test/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src="$here/../src"
out="${TMPDIR:-/tmp}/microlink-host-tests"
mkdir -p "$out"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 \
    -I "$here/stub" -I "$here/../include" -I "$src" \
    "$src/ml_register.c" "$here/test_register.c" -o "$out/test_register"
"$out/test_register"
