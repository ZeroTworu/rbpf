mod archive;
mod binaries;
mod cache;
mod clean;
mod docker;
mod fs_ext;
mod packages;
mod vue;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Xtask {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    CheckDocker,
    BuildBin { arch: String },
    BuildBinZip { arch: String },
    BuildVue,
    BuildVueZip,
    Prepare,
    BuildPkg { pkg_type: String },
    BuildRustCache { arch: String },
    BuildNodeCache,
}

fn main() -> anyhow::Result<()> {
    let xtask = Xtask::parse();

    match xtask.command {
        Commands::CheckDocker => docker::check_docker(),
        Commands::BuildBin { arch } => binaries::build_rust_binaries_generic(&arch),
        Commands::BuildBinZip { arch } => archive::build_bin_zip(&arch),
        Commands::BuildVue => vue::build_vue(),
        Commands::BuildVueZip => archive::build_vue_zip(),
        Commands::Prepare => packages::prepare_package_contents(),
        Commands::BuildPkg {pkg_type} => packages::build_pkg(&pkg_type),
        Commands::BuildRustCache { arch } => cache::build_rust_cache(&arch),
        Commands::BuildNodeCache => cache::build_node_cache(),
    }
}
