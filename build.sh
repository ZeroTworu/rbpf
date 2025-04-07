#!/usr/bin/env bash

set -e

REQUIRED_DOCKER_VERSION="20.10.0"

check_docker() {
  if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
  fi

  DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')
  if [[ "$(printf '%s\n' "$REQUIRED_DOCKER_VERSION" "$DOCKER_VERSION" | sort -V | head -n1)" != "$REQUIRED_DOCKER_VERSION" ]]; then
    echo "❌ Docker version $REQUIRED_DOCKER_VERSION or higher is required. Found: $DOCKER_VERSION"
    exit 1
  fi
}

build_rust_cache() {
  docker build -f ./contrib/docker/Dockerfile.rust.x86_64 -t hanyuu/rbpf-rust-builder:x86_64 .
  docker push hanyuu/rbpf-rust-builder:x86_64
}

build_rust_arm_cache() {
  echo "Build armv7 eBPF module"
  docker build -f ./contrib/docker/Dockerfile.rust.arm.ebpf -t hanyuu/rbpf-rust-builder:arm-ebpf .
  echo "Build armv7 ELF modules"
  docker build -f ./contrib/docker/Dockerfile.rust.arm.elf -t hanyuu/rbpf-rust-builder:arm-elf .
  echo "Push images"
  docker push hanyuu/rbpf-rust-builder:arm-ebpf
  docker push hanyuu/rbpf-rust-builder:arm-elf
  echo "Done"
}

build_node_cache() {
  docker build -f Dockerfile.node -t hanyuu/rbpf-node-builder:cached .
  docker push hanyuu/rbpf-node-builder:cached
}

build_rust_binaries_generic() {
  ARCH=$1
  TAG="ERROR"
  DOCKERFILE="ERROR"
  BIN_PATH="./rbpf-build/opt/rbpf/bin/$ARCH/"

  if [[ "$ARCH" == "armv7" ]]; then
    FULL_PATH="armv7-unknown-linux-gnueabihf/release"
    DOCKERFILE="Dockerfile.rustbuild.arm"
    TAG="rbpf-build-armv7"
  elif [[ "$ARCH" == "mips" ]]; then
    TAG="rbpf-build-mips"
    DOCKERFILE="Dockerfile.rustbuild.mips"
  elif [[ "$ARCH" == "x86_64" ]]; then
      TAG="rbpf-build-x86_64"
      FULL_PATH="release"
      DOCKERFILE="Dockerfile.rustbuild.x86_64"
      BIN_PATH="./rbpf-build/opt/rbpf/bin/"
  fi

  echo "🚀 Building Rust binaries for $ARCH..."

  if [[ "$CI" != "true" ]]; then
    rm -rf ./rbpf-build/
  fi

  docker build -f $DOCKERFILE -t $TAG .
  docker create --name "extract-bin-$ARCH" $TAG
  mkdir -p "$BIN_PATH"
  docker cp "extract-bin-$ARCH":/app/target/$FULL_PATH/rbpf_loader "$BIN_PATH/rbpf_loader"
  docker cp "extract-bin-$ARCH":/app/target/$FULL_PATH/rbpf_http "$BIN_PATH/rbpf_http"
  if [[ "$ARCH" == "armv7" ]]; then
    docker cp "extract-bin-$ARCH":/app/ebpf/rbpf.o "$BIN_PATH/rbpf.o"
  fi
  docker rm "extract-bin-$ARCH"
  echo "✅ Rust bin's for $ARCH built successfully."
}


build_rust_binaries_x86_x64() {
  build_rust_binaries_generic "x86_64"
}

build_rust_binaries_armv7() {
  build_rust_binaries_generic "armv7"
}

build_rust_binaries_mips() {
  build_rust_binaries_generic "mips"
}

build_vue() {
  echo "🌐 Building Vue WebUI..."
  docker build -f Dockerfile.vuebuild -t rbpf-ui-build .
  docker create --name extract-ui rbpf-ui-build
  mkdir -p ./rbpf-build/opt/rbpf/ui/dist
  docker cp extract-ui:/app/dist ./rbpf-build/opt/rbpf/ui/dist
  docker rm extract-ui
  echo "✅ Vue WebUI built successfully."
}

prepare_package_contents() {
  echo "📦 Preparing package contents..."
  mkdir -p ./rbpf-build/opt/rbpf/config
  cp -r ./contrib/settings ./rbpf-build/opt/rbpf/config/
  cp -r ./contrib/rules ./rbpf-build/opt/rbpf/config/
  cp -r ./contrib/migrations ./rbpf-build/opt/rbpf/config/

  mkdir -p ./rbpf-build/opt/rbpf/systemd/
  cp ./contrib/systemd/rbpf-loader.service ./rbpf-build/opt/rbpf/systemd/
  cp ./contrib/systemd/rbpf-http.service ./rbpf-build/opt/rbpf/systemd/
}

build_zst() {
  echo "📦 Building .zst package inside Docker..."

  if [[ "$CI" != "true" ]]; then
    build_rust_binaries_generic "x86_64"
    build_vue
    prepare_package_contents
  fi

  docker build -f Dockerfile.pkgbuild -t rbpf-pkgbuild .

  rm -rf ./contrib/pkg/arch/src
  mkdir -p ./contrib/pkg/arch/src
  mv ./rbpf-build/* ./contrib/pkg/arch/src

  docker run --rm \
    -v "$PWD":/build \
    -w /build/contrib/pkg/arch \
    -u "$(id -u):$(id -g)" \
    rbpf-pkgbuild \
    bash -c "makepkg -f"

  mv ./contrib/pkg/arch/*.zst ./
  rm -rf ./contrib/pkg/arch/src ./contrib/pkg/arch/pkg ./contrib/pkg/src
  echo "✅ .zst package built successfully."
}

build_deb() {
  echo "📦 Building .deb package inside Docker..."

  if [[ "$CI" != "true" ]]; then
    build_rust_binaries_generic "x86_64"
    build_vue
    prepare_package_contents
  fi

  docker build -f Dockerfile.debbuild -t rbpf-debbuild .

  docker run --rm \
    -v "$PWD":/home/builder \
    -w /home/builder \
    -u "$(id -u):$(id -g)" \
    rbpf-debbuild \
    bash -c "dpkg-deb --build contrib/pkg/debian rbpf.deb"

  echo "✅ .deb package built successfully."
}

build_rpm() {
  echo "📦 Building .rpm package inside Docker..."

  if [[ "$CI" != "true" ]]; then
    build_rust_binaries_generic "x86_64"
    build_vue
    prepare_package_contents
  fi

  mkdir -p ./rpmbuild/SOURCES/rbpf
  cp -r ./rbpf-build/* ./rpmbuild/SOURCES/rbpf/

  docker build \
    --build-arg USER_ID="$(id -u)" \
    -f Dockerfile.rpmbuild \
    -t rbpf-rpmbuild .

  docker run --rm \
    -v "$PWD":/home/builder \
    -w /home/builder \
    -u "$(id -u):$(id -g)" \
    rbpf-rpmbuild \
    bash -c "rpmbuild -bb contrib/pkg/rpm/rbpf.spec --define '_topdir /home/builder/rpmbuild' && cp /home/builder/rpmbuild/RPMS/*/*.rpm /home/builder/"

  rm -rf ./rpmbuild
  echo "✅ .rpm package built successfully."
}

build_bin_zip() {
  ARCH=$1
  echo "📦 Creating a TAR archive of Rust binaries for $ARCH..."

  if [[ "$CI" != "true" ]]; then
    build_rust_binaries_generic "$ARCH"
    prepare_package_contents
  fi

  tar -czf "rbpf-binaries-$ARCH.tar.gz" -C ./rbpf-build/opt/ rbpf/
  echo "✅ Rust binaries archive for $ARCH created successfully."
}

build_vue_zip() {
  echo "📦 Creating a TAR archive of WebUI..."

  if [[ "$CI" != "true" ]]; then
    build_vue
  fi

  mkdir -p ./rbpf-build/opt/rbpf/ui/dist
  tar -czf rbpf-vue.tar.gz -C ./rbpf-build/opt/rbpf/ui dist
  echo "✅ WebUI archive created successfully."
}

clean() {
  echo "🧹 Cleaning up..."
  rm -rf ./rbpf-build/
  rm -rf ./src/
  rm -rf ./pkg/
}

help() {
  echo "USE ./build.sh [PARAM]:
        * --build-bin - Сборка Rust приложения. (x86_64)
        * --build-bin-armv7 - Сборка Rust приложения. (armv7)

        * --build-bin-zip - Сборка и упаковка Rust приложения. (x86_64)
        * --build-bin-zip-armv7 - Сборка и упаковка Rust приложения. (armv7)

        * --build-vue - Сборка WebUI приложения.
        * --build-vue-zip - Сборка и упаковка WebUI приложения.

        * --build-zst - Полная сборка пакета формата Arch Linux (x86_64).
        * --build-deb - Полная сборка пакета формата Debian Linux (x86_64).
        * --build-rpm - Полная сборка пакета формата Red Hat Linux (x86_64).
        "
}

main() {
  check_docker

  case "$1" in
    --build-bin)
      build_rust_binaries_x86_x64
      ;;
    --build-bin-armv7)
      build_rust_binaries_armv7
      ;;
    --build-bin-mips)
      build_rust_binaries_mips
      ;;
    --build-zst)
      build_zst
      clean
      ;;
    --build-deb)
      build_deb
      clean
      ;;
    --build-rpm)
      build_rpm
      clean
      ;;
    --build-vue)
      build_vue
      ;;
    --prepare)
      prepare_package_contents
      ;;
    --build-bin-zip)
      build_bin_zip "x86_64"
      if [[ "$CI" != "true" ]]; then
          clean
      fi
      ;;
    --build-bin-zip-armv7)
      build_bin_zip "armv7"
      if [[ "$CI" != "true" ]]; then
          clean
      fi
      ;;
    --build-vue-zip)
      build_vue_zip
      if [[ "$CI" != "true" ]]; then
          clean
      fi
      ;;
    --build-node-cache)
      build_node_cache
      clean
      ;;
    --build-rust-cache)
      build_rust_cache
      clean
      ;;
    --build-rust-cache-armv7)
      build_rust_arm_cache
      clean
      ;;
    *)
      help
      exit 1
      ;;
  esac
}

main "$@"
