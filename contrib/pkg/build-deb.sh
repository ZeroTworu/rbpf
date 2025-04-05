#!/bin/bash
set -e

mkdir -p rbpf-deb/DEBIAN
mkdir -p rbpf-deb/opt/rbpf
cp -r ./rbpf-build/* rbpf-deb/opt/rbpf/

cat > rbpf-deb/DEBIAN/control <<EOF
Package: rbpf
Version: 0.1.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Zero Two <hau.au.999@gmail.com>
Description: Rust eBPF Firewall
EOF

dpkg-deb --build rbpf-deb
mv rbpf-deb.deb rbpf_0.1.0_amd64.deb
