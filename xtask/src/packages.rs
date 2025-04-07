use std::fs;
use std::path::Path;

use crate::fs_ext;
use anyhow::{Context, Result};
use std::process::Command;


pub fn build_pkg(pkg_type: &str) -> Result<()> {
    match pkg_type {
        "zst" => build_zst(),
        "deb" => build_deb(),
        "rpm" => build_rpm(),
        _ => panic!("Unsupported pkg type type!"),
    }
}

pub fn build_zst() -> Result<()> {
    println!("📦 Building .zst package inside Docker...");

    if std::env::var("CI").unwrap_or_default() != "true" {
        crate::binaries::build_rust_binaries_x86_64()?;
        crate::vue::build_vue()?;
        prepare_package_contents()?;
    }

    Command::new("docker")
        .args([
            "build",
            "-f",
            "Dockerfile.pkgbuild",
            "-t",
            "rbpf-pkgbuild",
            ".",
        ])
        .status()
        .context("Failed to build Docker image for .zst")?;

    fs::remove_dir_all("./contrib/pkg/arch/src").ok();
    fs::create_dir_all("./contrib/pkg/arch/src").context("Failed to create src dir")?;

    for entry in fs::read_dir("./rbpf-build")? {
        let entry = entry?;
        let dest = Path::new("./contrib/pkg/arch/src").join(entry.file_name());
        fs::rename(entry.path(), dest)?;
    }

    Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/build", std::env::current_dir()?.display()),
            "-w",
            "/build/contrib/pkg/arch",
            "-u",
            &format!("{}:{}", uid(), gid()),
            "rbpf-pkgbuild",
            "bash",
            "-c",
            "makepkg -f",
        ])
        .status()
        .context("Failed to build .zst package")?;

    for entry in fs::read_dir("./contrib/pkg/arch")? {
        let entry = entry?;
        if entry.path().extension().and_then(|e| e.to_str()) == Some("zst") {
            let dest = Path::new("./").join(entry.file_name());
            fs::rename(entry.path(), dest)?;
        }
    }


    if std::env::var("CI").unwrap_or_default() != "true" {
        fs::remove_dir_all("./contrib/pkg/arch/src").ok();
        fs::remove_dir_all("./contrib/pkg/arch/pkg").ok();
        fs::remove_dir_all("./contrib/pkg/src").ok();
    }


    println!("✅ .zst package built successfully.");
    Ok(())
}

pub fn build_deb() -> Result<()> {
    println!("📦 Building .deb package inside Docker...");

    if std::env::var("CI").unwrap_or_default() != "true" {
        crate::binaries::build_rust_binaries_x86_64()?;
        crate::vue::build_vue()?;
        prepare_package_contents()?;
    }

    Command::new("docker")
        .args([
            "build",
            "-f",
            "Dockerfile.debbuild",
            "-t",
            "rbpf-debbuild",
            ".",
        ])
        .status()
        .context("Failed to build Docker image for .deb")?;

    Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/home/builder", std::env::current_dir()?.display()),
            "-w",
            "/home/builder",
            "-u",
            &format!("{}:{}", uid(), gid()),
            "rbpf-debbuild",
            "bash",
            "-c",
            "dpkg-deb --build contrib/pkg/debian rbpf-x86_64.deb",
        ])
        .status()
        .context("Failed to build .deb package")?;

    println!("✅ .deb package built successfully.");
    Ok(())
}

pub fn build_rpm() -> Result<()> {
    println!("📦 Building .rpm package inside Docker...");

    if std::env::var("CI").unwrap_or_default() != "true" {
        crate::binaries::build_rust_binaries_x86_64()?;
        crate::vue::build_vue()?;
        prepare_package_contents()?;
    }

    fs::create_dir_all("./rpmbuild/SOURCES/rbpf")?;

    for entry in fs::read_dir("./rbpf-build")? {
        let entry = entry?;
        let dest = Path::new("./rpmbuild/SOURCES/rbpf").join(entry.file_name());
        fs_ext::copy_dir_recursive(entry.path(), dest)?;
    }

    Command::new("docker")
        .args([
            "build",
            "--build-arg",
            &format!("USER_ID={}", uid()),
            "-f",
            "Dockerfile.rpmbuild",
            "-t",
            "rbpf-rpmbuild",
            ".",
        ])
        .status()
        .context("Failed to build Docker image for .rpm")?;

    Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/home/builder", std::env::current_dir()?.display()),
            "-w",
            "/home/builder",
            "-u",
            &format!("{}:{}", uid(), gid()),
            "rbpf-rpmbuild",
            "bash",
            "-c",
            "rpmbuild -bb contrib/pkg/rpm/rbpf.spec --define '_topdir /home/builder/rpmbuild' && cp /home/builder/rpmbuild/RPMS/*/*.rpm /home/builder/",
        ])
        .status()
        .context("Failed to build .rpm package")?;

    if std::env::var("CI").unwrap_or_default() != "true" {
        fs::remove_dir_all("./rpmbuild").ok();
    }

    println!("✅ .rpm package built successfully.");
    Ok(())
}

pub fn prepare_package_contents() -> Result<()> {
    println!("📦 Preparing package contents...");

    let config_dir = Path::new("./rbpf-build/opt/rbpf/config");
    fs::create_dir_all(config_dir)?;

    fs_ext::copy_dir_recursive("./contrib/settings", config_dir.join("settings"))?;
    fs_ext::copy_dir_recursive("./contrib/rules", config_dir.join("rules"))?;
    fs_ext::copy_dir_recursive("./contrib/migrations", config_dir.join("migrations"))?;

    let systemd_dir = Path::new("./rbpf-build/opt/rbpf/systemd/");
    fs::create_dir_all(systemd_dir)?;

    fs::copy(
        "./contrib/systemd/rbpf-loader.service",
        systemd_dir.join("rbpf-loader.service"),
    )?;

    fs::copy(
        "./contrib/systemd/rbpf-http.service",
        systemd_dir.join("rbpf-http.service"),
    )?;
    println!("Content done");
    Ok(())
}
fn uid() -> u32 {
    users::get_current_uid()
}

fn gid() -> u32 {
    users::get_current_gid()
}
