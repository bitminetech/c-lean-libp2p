# c-lean-libp2p

`c-lean-libp2p` is a C11 implementation of the minimal Libp2p components needed for Lean (post-quantum) Ethereum.

## Dependencies

Dependencies are vendored as git submodules:

- `external/aws-lc`
- `external/ngtcp2`
- `external/secp256k1`

After cloning, initialize them with:

```sh
git submodule update --init --recursive
```

## Build

```sh
cmake -S . -B build
cmake --build build --parallel
```

The main target is the static library:

```text
c_lean_libp2p
```

Tests are enabled by default. To build only the library:

```sh
cmake -S . -B build -DBUILD_TESTING=OFF
cmake --build build --parallel
```

## Test

```sh
ctest --test-dir build --output-on-failure
```

The test suite includes unit tests and spec-oriented tests for multiformats,
peer IDs, QUIC transport behavior, and QUIC TLS identity vectors.

## Development Checks

Useful local checks:

```sh
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The CI suite also runs sanitizer builds, static analysis, 32-bit builds, Windows
builds, and MISRA C analysis for project headers and sources.
