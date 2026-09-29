#!/bin/sh
# Build and run the host tests: the parts of MicroLink that are pure
# functions, with the host's C compiler. From anywhere: sh components/microlink/host_test/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src="$here/../src"
out="${TMPDIR:-/tmp}/microlink-host-tests"
mkdir -p "$out"
# Under AddressSanitizer and UndefinedBehaviorSanitizer: a read past a
# buffer, an overflow or a bad shift fails the run, not only a wrong answer.
cflags="-std=c11 -Wall -Wextra -Werror -O2 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -fno-sanitize-recover=all"
build() {
    name=$1
    shift
    # shellcheck disable=SC2086
    ${CC:-cc} $cflags -I "$here/stub" -I "$here/../include" -I "$src" "$@" -o "$out/$name"
    "$out/$name"
}
build test_register "$src/ml_register.c" "$here/test_register.c"
build test_peer_table "$src/ml_peer_table.c" "$here/test_peer_table.c"
build test_frame_read "$src/ml_frame_read.c" "$here/test_frame_read.c"
build test_derp_node "$src/ml_derp_node.c" "$here/test_derp_node.c"
# The CertName check, against certificate chains built with mbedtls:
# MBEDTLS_DIR names its prefix (include/, lib/), else the system's is used.
if [ -n "${MBEDTLS_DIR:-}" ]; then
    # shellcheck disable=SC2086
    build test_derp_cert "$src/ml_derp_cert.c" "$here/test_derp_cert.c" \
        -I "$MBEDTLS_DIR/include" -L "$MBEDTLS_DIR/lib" -Wl,-rpath,"$MBEDTLS_DIR/lib" \
        -lmbedx509 -lmbedcrypto
elif [ -e /usr/include/mbedtls/x509_crt.h ]; then
    build test_derp_cert "$src/ml_derp_cert.c" "$here/test_derp_cert.c" -lmbedx509 -lmbedcrypto
else
    echo "test_derp_cert: not run, no mbedtls (set MBEDTLS_DIR to its prefix)"
fi
