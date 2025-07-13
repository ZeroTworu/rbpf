#!/usr/bin/env bash

set -euo pipefail

IMAGE="hanyuu/rbpf-rust-builder:xtask"
WORKDIR="$(pwd)"

run_xtask() {
  mkdir -p .cargo-cache
  chown "$(id -u):$(id -g)" .cargo-cache

  docker run --rm \
    -v "$WORKDIR":/app \
    -v "$WORKDIR/.cargo-cache":/cargo-home \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e CARGO_HOME=/cargo-home \
    -w /app \
    "$IMAGE" \
    cargo xtask $1
}


help() {
  echo "USE ./build.sh [PARAM]:
        * --build-bin - Сборка Rust приложения. (x86_64)
        * --build-bin-armv7 - Сборка Rust приложения. (armv7)
        * --build-bin-aarch64 - Сборка Rust приложения. (aarch64)

        * --build-bin-zip - Сборка и упаковка Rust приложения. (x86_64)
        * --build-bin-zip-armv7 - Сборка и упаковка Rust приложения. (armv7)

        * --build-vue - Сборка WebUI приложения.
        * --build-vue-zip - Сборка и упаковка WebUI приложения.

        * --build-zst - Полная сборка пакета формата Arch Linux (x86_64).
        * --build-deb - Полная сборка пакета формата Debian Linux (x86_64).
        * --build-rpm - Полная сборка пакета формата Red Hat Linux (x86_64).

        * --build-node-cache - Сборка образа для сборки фронта.
        * --build-rust-cache - Сборка образа для сборки Rust bin's под x86_64.
        * --build-rust-cache-armv7 - Сборка образа для сборки Rust bin's под armv7.
        "
}

full_build() {
        run_xtask "build-bin x86_64"
        run_xtask "build-vue"
        run_xtask "prepare"
}

main() {
  run_xtask "check-docker"
  if [[ $# -eq 0 ]]; then
      help
      exit 1
  fi

  CMD="$1"
  shift || true

  case $CMD in
    --build-bin)
      run_xtask "build-bin x86_64"
      ;;
    --build-bin-armv7)
      run_xtask "build-bin armv7"
      ;;
    --build-bin-aarch64)
      run_xtask "build-bin aarch64"
      ;;
    --build-zst)
      run_xtask "build-pkg zst"
      run_xtask "clean"
      ;;
    --build-deb)
      run_xtask "build-pkg deb"
      run_xtask "clean"
      ;;
    --build-rpm)
      run_xtask "build-pkg rpm"
      run_xtask "clean"
      ;;
    --build-vue)
      run_xtask "build-vue"
      ;;
    --build-bin-zip)
      run_xtask "build-bin-zip x86_64"
      run_xtask "clean"
      ;;
    --build-bin-zip-armv7)
      run_xtask "build-bin-zip armv7"
      run_xtask "clean"
      ;;
    --build-bin-zip-aarch64)
      run_xtask "build-bin-zip aarch64"
      run_xtask "clean"
      ;;
    --build-vue-zip)
      run_xtask "build-vue-zip"
      run_xtask "clean"
      ;;
    --build-node-cache)
      run_xtask "build-node-cache"
      run_xtask "clean"
      ;;
    --build-rust-cache)
      run_xtask "build-rust-cache x86_64"
      run_xtask "clean"
      ;;
    --build-rust-cache-armv7)
      run_xtask "build-rust-cache armv7"
      run_xtask "clean"
      ;;
    *)
      help
      exit 1
      ;;
  esac
}

main "$@"
