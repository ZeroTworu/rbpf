use anyhow::{Context, Result};
use std::fs;
use std::process::Command;

pub fn build_rust_binaries_x86_64() -> Result<()> {
    build_rust_binaries_generic("x86_64")
}

// pub fn build_rust_binaries_armv7() -> Result<()> {
//     build_rust_binaries_generic("armv7")
// }

// pub fn build_rust_binaries_mips() -> Result<()> {
//     build_rust_binaries_generic("mips")
// }

pub fn build_rust_binaries_generic(arch: &str) -> Result<()> {
    let (tag, dockerfile, full_path, bin_path) = match arch {
        "x86_64" => (
            "rbpf-build-x86_64",
            "Dockerfile.rustbuild.x86_64",
            "release",
            "./rbpf-build/opt/rbpf/bin/",
        ),
        "armv7" => (
            "rbpf-build-armv7",
            "Dockerfile.rustbuild.arm",
            "armv7-unknown-linux-gnueabihf/release",
            "./rbpf-build/opt/rbpf/bin/armv7/",
        ),
        "mips" => (
            "rbpf-build-mips",
            "Dockerfile.rustbuild.mips",
            "release",
            "./rbpf-build/opt/rbpf/bin/mips/",
        ),
        _ => anyhow::bail!("Unsupported arch: {}", arch),
    };

    println!("🚀 Building Rust binaries for {arch}...");

    if std::env::var("CI").unwrap_or_default() != "true" {
        fs::remove_dir_all("./rbpf-build/").ok();
    }

    Command::new("docker")
        .arg("build")
        .arg("-f")
        .arg(dockerfile)
        .arg("-t")
        .arg(tag)
        .arg(".")
        .status()
        .context("Failed to build docker image")?;

    Command::new("docker")
        .arg("create")
        .arg("--name")
        .arg(format!("extract-bin-{arch}"))
        .arg(tag)
        .status()
        .context("Failed to create container")?;

    fs::create_dir_all(bin_path).context("Failed to create bin output directory")?;

    let binaries = ["rbpf_loader", "rbpf_http"];
    for bin in binaries {
        Command::new("docker")
            .arg("cp")
            .arg(format!("extract-bin-{arch}:/app/target/{full_path}/{bin}"))
            .arg(format!("{bin_path}/{bin}"))
            .status()
            .with_context(|| format!("Failed to copy binary {bin}"))?;
    }

    if arch == "armv7" {
        Command::new("docker")
            .arg("cp")
            .arg(format!("extract-bin-{arch}:/app/ebpf/rbpf.o"))
            .arg(format!("{bin_path}/rbpf.o"))
            .status()
            .context("Failed to copy eBPF object")?;
    }

    Command::new("docker")
        .arg("rm")
        .arg(format!("extract-bin-{arch}"))
        .status()
        .context("Failed to remove temporary container")?;

    println!("✅ Rust binaries for {arch} built successfully.");

    Ok(())
}
