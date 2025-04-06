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
* Sat Apr 05 2025 Zero Two <hau.au.999@gmail.com> - 0.1.0-1
- Initial build
