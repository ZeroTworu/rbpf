use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info, warn};

use rbpf::events;
use rbpf::rules;
use tokio::fs::read_to_string;
use yaml_rust2::YamlLoader;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "./settings.yaml")]
    cfg: String,
    #[clap(short, long, default_value = "./rules/")]
    rules: String,
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

    let _ = read_settings(&mut ebpf, &opt).await?;

    println!("Waiting for logs...");
    events::log_listener(&mut ebpf).await?;
    Ok(())
}

async fn read_settings(ebpf: &mut Ebpf, opt: &Opt) -> anyhow::Result<()> {
    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;

    rules::load_rules(&opt.rules, ebpf).await?;

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
        None => warn!("No output interfaces found"),
    }

    match interfaces["input"].as_vec() {
        Some(interfaces) => {
            let program_ingress: &mut Xdp = ebpf.program_mut("tc_ingress").unwrap().try_into()?;
            program_ingress.load()?;

            for iface in interfaces {
                let iface = iface.as_str().unwrap();
                program_ingress.attach(&iface, XdpFlags::default())?;
                info!("Append input listener to: {}", iface);
            }
        }
        None => warn!("No input interfaces found"),
    }

    Ok(())
}
