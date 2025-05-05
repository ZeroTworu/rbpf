use std::fs;
use std::process::Command;

use anyhow::{Context, Result};

use crate::binaries::build_rust_binaries_generic;
use crate::clean::clean;
use crate::packages::prepare_package_contents;
use crate::vue::build_vue;

pub fn build_bin_zip(arch: &str) -> Result<()> {
    println!("📦 Creating a TAR archive of Rust binaries for {arch}...");

    let ci = std::env::var("CI").unwrap_or_default() == "true";

    if !ci {
        build_rust_binaries_generic(arch)?;
        prepare_package_contents()?;
    }



    let archive_name = format!("rbpf-binaries-{arch}.tar.gz");

    let output = Command::new("tar")
        .args(["-czf", &archive_name, "-C", "./rbpf-build/opt/", "rbpf/"])
        .output()
        .context("Failed to create binary archive")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to create archive: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("✅ Rust binaries archive for {arch} created successfully.");

    if !ci {
        clean().ok();
    }

    Ok(())
}

pub fn build_vue_zip() -> Result<()> {
    println!("📦 Creating a TAR archive of WebUI...");

    let ci = std::env::var("CI").unwrap_or_default() == "true";

    if !ci {
        build_vue()?;
    }

    fs::create_dir_all("./rbpf-build/opt/rbpf/ui/dist")
        .context("Failed to create output directory for Vue dist")?;

    let output = Command::new("tar")
        .args([
            "-czf",
            "rbpf-vue.tar.gz",
            "-C",
            "./rbpf-build/opt/rbpf/ui",
            "dist",
        ])
        .output()
        .context("Failed to create vue archive")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to create Vue archive: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("✅ WebUI archive created successfully.");

    if !ci {
        clean().ok();
    }

    Ok(())
}
