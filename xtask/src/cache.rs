use anyhow::{Context, Result};
use std::process::{Command, ExitStatus};

fn run(cmd: &mut Command) -> Result<ExitStatus> {
    let status = cmd
        .status()
        .with_context(|| format!("Failed to run: {:?}", cmd))?;
    if !status.success() {
        anyhow::bail!("Command {:?} exited with status: {}", cmd, status);
    }
    Ok(status)
}

pub fn build_rust_cache(arch: &str) -> Result<()> {
    match arch {
        "x86_64" => build_rust_cache_x86_64(),
        "armv7" => build_rust_cache_armv7(),
        _ => {
            println!("cargo:warning=Unsupported architecture: {}", arch);
            Ok(())
        }
    }
}

pub fn build_rust_cache_x86_64() -> Result<()> {
    println!("🐋 Building x86_64 Rust cache...");
    run(Command::new("docker")
        .arg("build")
        .arg("-f")
        .arg("./contrib/docker/Dockerfile.rust.x86_64")
        .arg("-t")
        .arg("hanyuu/rbpf-rust-builder:x86_64")
        .arg("."))?;

    run(Command::new("docker")
        .arg("push")
        .arg("hanyuu/rbpf-rust-builder:x86_64"))?;

    super::clean::clean()?;
    Ok(())
}

pub fn build_rust_cache_armv7() -> Result<()> {
    println!("🐋 Building armv7 Rust eBPF cache...");
    run(Command::new("docker")
        .arg("build")
        .arg("-f")
        .arg("./contrib/docker/Dockerfile.rust.arm.ebpf")
        .arg("-t")
        .arg("hanyuu/rbpf-rust-builder:arm-ebpf")
        .arg("."))?;

    println!("🐋 Building armv7 Rust ELF cache...");
    run(Command::new("docker")
        .arg("build")
        .arg("-f")
        .arg("./contrib/docker/Dockerfile.rust.arm.elf")
        .arg("-t")
        .arg("hanyuu/rbpf-rust-builder:arm-elf")
        .arg("."))?;

    println!("📤 Pushing images...");
    run(Command::new("docker")
        .arg("push")
        .arg("hanyuu/rbpf-rust-builder:arm-ebpf"))?;
    run(Command::new("docker")
        .arg("push")
        .arg("hanyuu/rbpf-rust-builder:arm-elf"))?;

    super::clean::clean()?;
    Ok(())
}

pub fn build_node_cache() -> Result<()> {
    println!("🐋 Building Node.js cache...");
    run(Command::new("docker")
        .arg("build")
        .arg("-f")
        .arg("./contrib/docker/Dockerfile.node")
        .arg("-t")
        .arg("hanyuu/rbpf-node-builder:cached")
        .arg("."))?;

    run(Command::new("docker")
        .arg("push")
        .arg("hanyuu/rbpf-node-builder:cached"))?;

    super::clean::clean()?;
    Ok(())
}
