use anyhow::{anyhow, Context as _};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    if std::env::var("CARGO_FEATURE_EMBED_EBPF").is_err() {
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "rbpf-ebpf")
        .ok_or_else(|| anyhow!("rbpf-ebpf package not found"))?;

    aya_build::build_ebpf([ebpf_package])
}

