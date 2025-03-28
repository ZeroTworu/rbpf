mod loader;

use crate::loader::v4::load_v4;
use crate::loader::v6::load_v6;
use aya::programs::{SchedClassifier, TcAttachType};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info, warn};
use tokio::fs::read_to_string;
use tokio::signal;
use yaml_rust2::YamlLoader;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./settings.yaml")]
    cfg: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    init_bpf().await?;
    println!("Exiting...");
    Ok(())
}

async fn init_bpf() -> anyhow::Result<()> {
    println!("Initializing BPF program...");

    let opt = Opt::parse();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rbpf"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let _ = read_settings(&mut ebpf, opt.cfg).await?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    Ok(())
}

async fn read_settings(ebpf: &mut Ebpf, path: String) -> anyhow::Result<()> {
    let yaml = read_to_string(path).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    let _ = load_v4(ebpf, &settings[0])?;
    let _ = load_v6(ebpf, &settings[0])?;

    // TODO: Придумать как это красиво убрать в отдельный лоадер
    let interfaces = &settings[0]["interfaces"];

    match interfaces["output"].as_vec() {
        Some(interfaces) => {
            let program_egress: &mut SchedClassifier =
                ebpf.program_mut("tc_egress").unwrap().try_into()?;
            program_egress.load()?;
            for iface in interfaces {
                let iface = iface.as_str().unwrap();
                program_egress.attach(&iface, TcAttachType::Egress)?;
                info!("Append output listener to: {}", iface);
            }
        }
        None => warn!("no output interfaces found"),
    }

    match interfaces["input"].as_vec() {
        Some(interfaces) => {
            let program_ingress: &mut SchedClassifier =
                ebpf.program_mut("tc_ingress").unwrap().try_into()?;
            program_ingress.load()?;

            for iface in interfaces {
                let iface = iface.as_str().unwrap();
                program_ingress.attach(&iface, TcAttachType::Ingress)?;
                info!("Append input listener to: {}", iface);
            }
        }
        None => warn!("no input interfaces found"),
    }

    Ok(())
}
