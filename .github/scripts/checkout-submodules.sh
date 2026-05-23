#!/usr/bin/env bash
set -euo pipefail

repo="${1:-c-lean-libp2p}"

clear_auth_headers() {
  git config --global --unset-all http.https://github.com/.extraheader || true
  git -C "$repo" config --local --unset-all http.https://github.com/.extraheader || true
}

clear_auth_headers
git -C "$repo" submodule sync --recursive

for attempt in 1 2 3; do
  if GIT_TERMINAL_PROMPT=0 git -C "$repo" -c protocol.version=2 submodule update --init --force --depth=1 --recursive; then
    exit 0
  fi

  clear_auth_headers
  git -C "$repo" submodule deinit --force --all || true
  sleep "$((attempt * 10))"
done

GIT_TERMINAL_PROMPT=0 git -C "$repo" -c protocol.version=2 submodule update --init --force --recursive
