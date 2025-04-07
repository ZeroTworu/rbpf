use std::process::Command;

use anyhow::{Context, Result, bail};

const REQUIRED_DOCKER_VERSION: &str = "20.10.0";

pub fn check_docker() -> Result<()> {
    let which = Command::new("which")
        .arg("docker")
        .output()
        .context("Failed to run `which docker`")?;

    if !which.status.success() {
        bail!("❌ Docker not found. Please install Docker.");
    }

    let output = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .context("Failed to get Docker version")?;

    if !output.status.success() {
        bail!("❌ Failed to fetch Docker version");
    }

    let docker_version = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if version_lt(&docker_version, REQUIRED_DOCKER_VERSION) {
        bail!(
            "❌ Docker version {} or higher is required. Found: {}",
            REQUIRED_DOCKER_VERSION,
            docker_version
        );
    }

    println!("✅ Docker version {} OK", docker_version);
    Ok(())
}

fn version_lt(found: &str, required: &str) -> bool {
    let found_parts: Vec<u32> = found.split('.').filter_map(|s| s.parse().ok()).collect();

    let required_parts: Vec<u32> = required.split('.').filter_map(|s| s.parse().ok()).collect();

    for (f, r) in found_parts.iter().zip(required_parts.iter()) {
        if f < r {
            return true;
        } else if f > r {
            return false;
        }
    }

    found_parts.len() < required_parts.len()
}
