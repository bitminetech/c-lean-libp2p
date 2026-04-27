FROM debian:bookworm-slim AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        ninja-build && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B /build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DLIBP2P_BUILD_INTEROP_BINARY=ON && \
    cmake --build /build --target c_lean_libp2p_transport_interop

FROM debian:bookworm-slim

COPY --from=build /build/bin/c_lean_libp2p_transport_interop /usr/local/bin/c_lean_libp2p_transport_interop

USER nobody
ENTRYPOINT ["/usr/local/bin/c_lean_libp2p_transport_interop"]
