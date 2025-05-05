use anyhow::{Context, Result};
use std::fs;
use std::process::Command;

pub fn build_vue() -> Result<()> {
    println!("🌐 Building Vue WebUI...");

    // Сборка Vue WebUI из Docker-контейнера
    Command::new("docker")
        .arg("build")
        .arg("-f")
        .arg("./contrib/docker/Dockerfile.vuebuild")
        .arg("-t")
        .arg("rbpf-ui-build")
        .arg(".")
        .status()
        .context("Failed to build Docker image for Vue WebUI")?;

    Command::new("docker")
        .arg("create")
        .arg("--name")
        .arg("extract-ui")
        .arg("rbpf-ui-build")
        .status()
        .context("Failed to create Docker container for Vue WebUI")?;

    // Копирование сгенерированных файлов из контейнера
    let dist_path = "rbpf-build/opt/rbpf/ui/dist";
    fs::create_dir_all(dist_path).context("Failed to create directory for WebUI")?;

    Command::new("docker")
        .arg("cp")
        .arg("extract-ui:/app/dist")
        .arg(dist_path)
        .status()
        .context("Failed to copy WebUI dist from Docker container")?;

    Command::new("docker")
        .arg("rm")
        .arg("extract-ui")
        .status()
        .context("Failed to remove Docker container for Vue WebUI")?;

    println!("✅ Vue WebUI built successfully.");

    Ok(())
}
