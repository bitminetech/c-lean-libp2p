#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PROJECT_ROOT="$REPO_ROOT/c-lean-libp2p"
BUILD_DIR="$PROJECT_ROOT/build"
CC=${CC:-clang}
CFLAGS="-std=c11 -Wall -Wextra -Werror -ffreestanding -I $PROJECT_ROOT/include"
CLANG_FORMAT_BIN=${CLANG_FORMAT_BIN:-clang-format}
CLANG_TIDY_BIN=${CLANG_TIDY_BIN:-}

TEST_SOURCES="
$PROJECT_ROOT/tests/common/multiformats_test_utils.h
$PROJECT_ROOT/tests/common/multiformats_test_utils.c
$PROJECT_ROOT/tests/unit/multiformats/unsigned_varint/test_unsigned_varint.c
$PROJECT_ROOT/tests/unit/multiformats/multicodec/test_multicodec.c
$PROJECT_ROOT/tests/unit/multiformats/multibase/test_multibase.c
$PROJECT_ROOT/tests/unit/multiformats/multihash/test_multihash.c
$PROJECT_ROOT/tests/unit/multiformats/multiaddr/test_multiaddr.c
$PROJECT_ROOT/tests/spec/multiformats/unsigned_varint/test_unsigned_varint.c
$PROJECT_ROOT/tests/spec/multiformats/multicodec/test_multicodec.c
$PROJECT_ROOT/tests/spec/multiformats/multibase/test_multibase.c
$PROJECT_ROOT/tests/spec/multiformats/multihash/test_multihash.c
$PROJECT_ROOT/tests/spec/multiformats/multiaddr/test_multiaddr.c
"

run_clang_format() {
    if ! command -v "$CLANG_FORMAT_BIN" >/dev/null 2>&1; then
        echo "clang-format not found: $CLANG_FORMAT_BIN" >&2
        exit 1
    fi

    for file in $TEST_SOURCES; do
        "$CLANG_FORMAT_BIN" -i "$file"
    done
}

run_clang_tidy_file() {
    file=$1

    if [ -z "$CLANG_TIDY_BIN" ]; then
        if command -v clang-tidy >/dev/null 2>&1; then
            CLANG_TIDY_BIN=clang-tidy
        else
            return 0
        fi
    fi

    "$CLANG_TIDY_BIN" "$file" -- \
        -std=c11 \
        -Wall \
        -Wextra \
        -Werror \
        -ffreestanding \
        -I "$PROJECT_ROOT/include"
}

run_clang_tidy() {
    if [ -z "$CLANG_TIDY_BIN" ] && ! command -v clang-tidy >/dev/null 2>&1; then
        echo "clang-tidy not found; skipping clang-tidy pass" >&2
        return 0
    fi

    for file in $TEST_SOURCES; do
        case $file in
            *.c) run_clang_tidy_file "$file" ;;
        esac
    done
}

build_test() {
    output=$1
    shift
    "$CC" $CFLAGS "$@" -o "$output"
}

run_test() {
    output=$1
    shift
    "$output" "$@"
}

mkdir -p "$BUILD_DIR"
cd "$REPO_ROOT"

run_clang_format
run_clang_tidy

build_test \
    "$BUILD_DIR/unsigned_varint_unit" \
    "$PROJECT_ROOT/tests/common/multiformats_test_utils.c" \
    "$PROJECT_ROOT/tests/unit/multiformats/unsigned_varint/test_unsigned_varint.c" \
    "$PROJECT_ROOT/src/multiformats/unsigned_varint/unsigned_varint.c"
run_test "$BUILD_DIR/unsigned_varint_unit"

build_test \
    "$BUILD_DIR/multicodec_unit" \
    "$PROJECT_ROOT/tests/common/multiformats_test_utils.c" \
    "$PROJECT_ROOT/tests/unit/multiformats/multicodec/test_multicodec.c" \
    "$PROJECT_ROOT/src/multiformats/multicodec/multicodec.c"
run_test "$BUILD_DIR/multicodec_unit"

build_test \
    "$BUILD_DIR/multibase_unit" \
    "$PROJECT_ROOT/tests/unit/multiformats/multibase/test_multibase.c" \
    "$PROJECT_ROOT/src/multiformats/multibase/multibase.c"
run_test "$BUILD_DIR/multibase_unit"

build_test \
    "$BUILD_DIR/multihash_unit" \
    "$PROJECT_ROOT/tests/unit/multiformats/multihash/test_multihash.c" \
    "$PROJECT_ROOT/src/multiformats/multihash/multihash.c" \
    "$PROJECT_ROOT/src/multiformats/unsigned_varint/unsigned_varint.c"
run_test "$BUILD_DIR/multihash_unit"

build_test \
    "$BUILD_DIR/multiaddr_unit" \
    "$PROJECT_ROOT/tests/common/multiformats_test_utils.c" \
    "$PROJECT_ROOT/tests/unit/multiformats/multiaddr/test_multiaddr.c" \
    "$PROJECT_ROOT/src/multiformats/multiaddr/multiaddr.c" \
    "$PROJECT_ROOT/src/multiformats/multibase/multibase.c" \
    "$PROJECT_ROOT/src/multiformats/multihash/multihash.c" \
    "$PROJECT_ROOT/src/multiformats/unsigned_varint/unsigned_varint.c"
run_test "$BUILD_DIR/multiaddr_unit"

build_test \
    "$BUILD_DIR/unsigned_varint_spec" \
    "$PROJECT_ROOT/tests/common/multiformats_test_utils.c" \
    "$PROJECT_ROOT/tests/spec/multiformats/unsigned_varint/test_unsigned_varint.c" \
    "$PROJECT_ROOT/src/multiformats/unsigned_varint/unsigned_varint.c"
run_test "$BUILD_DIR/unsigned_varint_spec"

build_test \
    "$BUILD_DIR/multicodec_spec" \
    "$PROJECT_ROOT/tests/common/multiformats_test_utils.c" \
    "$PROJECT_ROOT/tests/spec/multiformats/multicodec/test_multicodec.c" \
    "$PROJECT_ROOT/src/multiformats/multicodec/multicodec.c"
run_test "$BUILD_DIR/multicodec_spec"

build_test \
    "$BUILD_DIR/multibase_spec" \
    "$PROJECT_ROOT/tests/spec/multiformats/multibase/test_multibase.c" \
    "$PROJECT_ROOT/src/multiformats/multibase/multibase.c"
run_test "$BUILD_DIR/multibase_spec"

build_test \
    "$BUILD_DIR/multihash_spec" \
    "$PROJECT_ROOT/tests/spec/multiformats/multihash/test_multihash.c" \
    "$PROJECT_ROOT/src/multiformats/multihash/multihash.c" \
    "$PROJECT_ROOT/src/multiformats/unsigned_varint/unsigned_varint.c"
run_test "$BUILD_DIR/multihash_spec"

build_test \
    "$BUILD_DIR/multiaddr_spec" \
    "$PROJECT_ROOT/tests/common/multiformats_test_utils.c" \
    "$PROJECT_ROOT/tests/spec/multiformats/multiaddr/test_multiaddr.c" \
    "$PROJECT_ROOT/src/multiformats/multiaddr/multiaddr.c" \
    "$PROJECT_ROOT/src/multiformats/multibase/multibase.c" \
    "$PROJECT_ROOT/src/multiformats/multihash/multihash.c" \
    "$PROJECT_ROOT/src/multiformats/unsigned_varint/unsigned_varint.c"
run_test "$BUILD_DIR/multiaddr_spec"
