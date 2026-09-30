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
# The OS a request reports is the one fixed with the node's keys
# (microlink_t.hostinfo_os): only the start that reads the keys, in
# microlink.c, may name the build's.
if grep -l 'CONFIG_ML_HOSTINFO_OS' "$src"/*.c "$src"/*.h | grep -v '/microlink\.c$'; then
    echo "the build's OS is named outside microlink.c: a request must report microlink_t.hostinfo_os" >&2
    exit 1
fi
build test_peer_table "$src/ml_peer_table.c" "$here/test_peer_table.c"
build test_frame_read "$src/ml_frame_read.c" "$here/test_frame_read.c"
build test_derp_node "$src/ml_derp_node.c" "$here/test_derp_node.c"
# The CertName check, against certificate chains built with mbedtls:
# MBEDTLS_DIR names its prefix (include/, lib/), else the system's is used.
# With neither the run fails, unless SKIP_DERP_CERT=1 leaves this test out.
if [ -n "${MBEDTLS_DIR:-}" ]; then
    # shellcheck disable=SC2086
    build test_derp_cert "$src/ml_derp_cert.c" "$here/test_derp_cert.c" \
        -I "$MBEDTLS_DIR/include" -L "$MBEDTLS_DIR/lib" -Wl,-rpath,"$MBEDTLS_DIR/lib" \
        -lmbedx509 -lmbedcrypto
elif [ -e /usr/include/mbedtls/x509_crt.h ]; then
    build test_derp_cert "$src/ml_derp_cert.c" "$here/test_derp_cert.c" -lmbedx509 -lmbedcrypto
elif [ "${SKIP_DERP_CERT:-}" = 1 ]; then
    echo "test_derp_cert: not run, SKIP_DERP_CERT=1"
else
    echo "test_derp_cert: no mbedtls; set MBEDTLS_DIR to its prefix, or SKIP_DERP_CERT=1 to leave it out" >&2
    exit 1
fi
