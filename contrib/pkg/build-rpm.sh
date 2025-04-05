#!/bin/bash
set -e

mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp -r ./rbpf-build rpmbuild/SOURCES/rbpf

cat > rpmbuild/SPECS/rbpf.spec <<EOF
Name:           rbpf
Version:        0.1.0
Release:        1%{?dist}
Summary:        Rust eBPF firewall

License:        MIT
Source0:        rbpf
BuildArch:      x86_64

%description
Rust eBPF Firewall.

%install
mkdir -p %{buildroot}/opt/rbpf
cp -r %{_sourcedir}/rbpf/* %{buildroot}/opt/rbpf/

%files
/opt/rbpf

%changelog
* Sat Apr 05 2025 You <hau.au.999@gmail.com> - 0.1.0-1
- Initial build
EOF

rpmbuild --define "_topdir %(pwd)/rpmbuild" -bb rpmbuild/SPECS/rbpf.spec
mv rpmbuild/RPMS/x86_64/rbpf-0.1.0-1.fc41.x86_64.rpm .
rm -rf rpmbuild
