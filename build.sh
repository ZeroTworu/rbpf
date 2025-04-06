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

build_rust_binaries() {
  echo "🚀 Building Rust binaries..."
  rm -rf ./rbpf-build/
  docker build -f Dockerfile.rustbuild -t rbpf-build .
  docker create --name extract-bin rbpf-build
  mkdir -p ./rbpf-build/opt/rbpf/bin/
  docker cp extract-bin:/app/target/release/rbpf_loader ./rbpf-build/opt/rbpf/bin/
  docker cp extract-bin:/app/target/release/rbpf_http ./rbpf-build/opt/rbpf/bin/
  docker rm extract-bin
  echo "✅ Rust bin's built successfully."
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

  build_rust_binaries
  build_vue
  prepare_package_contents


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
  rm -rf ./contrib/pkg/arch/src
  rm -rf ./contrib/pkg/src
  rm -rf ./contrib/pkg/arch/pkg
  echo "✅ .zst package built successfully."
}

build_deb() {
  echo "📦 Building .deb package inside Docker..."

  build_rust_binaries
  build_vue
  prepare_package_contents

  docker build -f Dockerfile.debbuild -t rbpf-debbuild .

  docker run --rm \
    -v "$PWD":/home/builder \
    -w /home/builder \
    -u "$(id -u):$(id -g)" \
    rbpf-debbuild \
    bash -c "dpkg-deb --build contrib/pkg/debian rbpf.deb"
  rm -rf rbpf-deb
  echo "✅ .deb package built successfully."
}

build_rpm() {
  echo "📦 Building .rpm package inside Docker..."

  build_rust_binaries
  build_vue
  prepare_package_contents

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
  echo "📦 Creating a TAR archive of Rust binaries..."
  build_rust_binaries
  mkdir -p ./rbpf-build/opt/rbpf/bin/
  tar -czf rbpf-binaries.tar.gz -C ./rbpf-build/opt/rbpf bin/
  echo "✅ Rust binaries archive created successfully."
}

build_vue_zip() {
  echo "📦 Creating a TAR archive of WebUI..."
  build_vue
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

main() {
  check_docker

  case "$1" in
    --build-bin)
      build_rust_binaries
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
      clean
      ;;
    --prepare)
      prepare_package_contents
      clean
      ;;
    --build-bin-zip)
      build_bin_zip
      clean
      ;;
    --build-vue-zip)
      build_vue_zip
      clean
      ;;
    *)
      echo "Usage: $0 [--build-bin | --build-zst | --build-deb | --build-rpm]"
      exit 1
      ;;
  esac
}

main "$@"
