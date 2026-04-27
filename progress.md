# c-lean-libp2p Progress

## Current Scope

c-lean-libp2p is focused on the minimal libp2p surface needed for Lean Ethereum work: peer IDs, QUIC v1 with libp2p TLS, multistream-select, a pollable host, identify, and ping. Project code in `src/` and `include/` keeps caller-owned storage and avoids project-owned heap allocation.

## Completed

- Host abstraction with QUIC transport integration.
- secp256k1 host identity adapter.
- identify and ping protocol handlers.
- Vendored unified-testing harness under `interop/unified-testing`.
- Milestone 1 interop wiring: c-lean-libp2p now has a gated transport interop binary, Docker image recipe, harness image entry, and manual/nightly CI workflow for c-lean-libp2p loopback over `quic-v1`.

## Interop Notes

- The harness root has no top-level `run.sh`; transport tests run from `interop/unified-testing/transport/run.sh`.
- The current transport implementations coordinate listener addresses through Redis `RPUSH`/`BLPOP` on `<TEST_KEY>_listener_multiaddr`, even though the transport app guide still describes `SET`/polling in places.
- c-lean-libp2p registers only `quic-v1`; secure channel and muxer lists are empty because QUIC subsumes both for the transport matrix.
- The first PR only claims c-lean-libp2p loopback. go-libp2p interop remains milestone 2.

## Next Step

Backpressure hardening is the better next task before gossipsub. The interop path exercises real event-loop pressure, stream negotiation, and ping, so tightening bounded send/receive behavior and documenting host-level observability gaps should come before adding a broader pubsub surface.
