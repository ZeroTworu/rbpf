use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub fn clean() -> Result<()> {
    println!("🧹 Cleaning up...");
    for dir in ["rbpf-build", "src", "pkg"] {
        let path = Path::new(dir);
        if path.exists() {
            fs::remove_dir_all(path).with_context(|| format!("Failed to remove {dir}"))?;
        }
    }
    Ok(())
}
