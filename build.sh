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
  docker build -f Dockerfile.rust -t rbpf-build .
  docker create --name extract rbpf-build
  mkdir -p ./rbpf-build/opt/rbpf/bin/
  docker cp extract:/usr/local/bin/rbpf_loader ./rbpf-build/opt/rbpf/bin/
  docker cp extract:/usr/local/bin/rbpf_http ./rbpf-build/opt/rbpf/bin/
  docker rm extract
  echo "✅ Rust bin's built successfully."
}

build_vue() {
  echo "🌐 Building Vue WebUI..."
  docker build -f Dockerfile.frontend -t rbpf-ui-build .
  docker create --name extract-ui rbpf-ui-build
  mkdir -p ./rbpf-build/opt/rbpf/ui/dist
  docker cp extract-ui:/usr/share/nginx/html ./rbpf-build/opt/rbpf/ui/dist
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

  rm -rf ./src
  mkdir -p ./src
  cp -r ./rbpf-build/* ./src/

  docker build -f Dockerfile.pkgbuild -t rbpf-pkgbuild .

  rm -rf ./contrib/pkg/src

  mkdir -p ./contrib/pkg/src

  mv ./src/* ./contrib/pkg/src

  docker run --rm \
    -v "$PWD":/build \
    -w /build/contrib/pkg \
    -u "$(id -u):$(id -g)" \
    rbpf-pkgbuild \
    bash -c "makepkg -f"

  mv ./contrib/pkg/*.zst ./
  rm -rf ./contrib/pkg/src
  rm -rf ./contrib/pkg/pkg
  echo "✅ .zst package built successfully."
}

build_deb() {
  echo "📦 Building .deb package inside Docker..."

  build_rust_binaries
  build_vue
  prepare_package_contents

  docker build -f Dockerfile.debbuild -t rbpf-debbuild .

  docker run --rm \
    -v "$PWD":/home/builder/debbuild \
    -w /home/builder/debbuild \
    -u "$(id -u):$(id -g)" \
    rbpf-debbuild \
    bash -c "./contrib/pkg/build-deb.sh"
  rm -rf rbpf-deb
  echo "✅ .deb package built successfully."
}

build_rpm() {
  echo "📦 Building .rpm package inside Docker..."

  build_rust_binaries
  build_vue
  prepare_package_contents

  docker build -f Dockerfile.rpmbuild -t rbpf-rpmbuild .

  docker run --rm \
    -v "$PWD":/home/builder/rpmbuild \
    -w /home/builder/rpmbuild \
    -u "$(id -u):$(id -g)" \
    rbpf-rpmbuild \
    bash -c "./contrib/pkg/build-rpm.sh"
  echo "✅ .rpm package built successfully."
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
      build_rust_binaries
      build_vue
      prepare_package_contents
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
    *)
      echo "Usage: $0 [--build-bin | --build-zst | --build-deb | --build-rpm]"
      exit 1
      ;;
  esac
}

main "$@"
