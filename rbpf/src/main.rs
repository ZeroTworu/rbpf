use aya::maps::HashMap;
use aya::programs::{SchedClassifier, TcAttachType};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info, warn};
use std::net::Ipv4Addr;
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

    let iface = read_settings(&mut ebpf, opt.cfg).await?;

    let program_egress: &mut SchedClassifier = ebpf.program_mut("tc_egress").unwrap().try_into()?;

    program_egress.load()?;
    program_egress.attach(&iface, TcAttachType::Egress)?;

    let program_ingress: &mut SchedClassifier =
        ebpf.program_mut("tc_ingress").unwrap().try_into()?;

    program_ingress.load()?;
    program_ingress.attach(&iface, TcAttachType::Ingress)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    Ok(())
}

async fn read_settings(ebpf: &mut Ebpf, path: String) -> anyhow::Result<String> {
    let yaml = read_to_string(path).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;

    {
        let mut in_blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST_ADDRESSES").unwrap())?;

        for addr in settings[0]["input"]["addresses"].as_vec().unwrap().iter() {
            let v4: Ipv4Addr = String::from(addr.as_str().unwrap()).parse()?;
            info!("address: {} added to IN BLOCKLIST", v4);
            in_blocklist.insert(&v4.into(), 0, 0)?;
        }
    }

    {
        let mut in_blocklist: HashMap<_, u16, u16> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST_PORTS").unwrap())?;

        for port in settings[0]["input"]["ports"].as_vec().unwrap().iter() {
            let port: u16 = String::from(port.as_str().unwrap()).parse()?;
            info!("port: {} added to IN BLOCKLIST", port);
            in_blocklist.insert(&port, 0, 0)?;
        }
    }

    {
        let mut out_blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST_ADDRESSES").unwrap())?;

        for addr in settings[0]["output"]["addresses"].as_vec().unwrap().iter() {
            let v4: Ipv4Addr = String::from(addr.as_str().unwrap()).parse()?;
            info!("address: {} added to OUT BLOCKLIST", v4);
            out_blocklist.insert(&v4.into(), 0, 0)?;
        }
    }

    {
        let mut out_blocklist: HashMap<_, u16, u16> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST_PORTS").unwrap())?;

        for port in settings[0]["output"]["ports"].as_vec().unwrap().iter() {
            let port: u16 = String::from(port.as_str().unwrap()).parse()?;
            info!("port: {} added to OUT BLOCKLIST", port);
            out_blocklist.insert(&port, 0, 0)?;
        }
    }

    Ok(settings[0]["interface"].as_str().unwrap().into())
}
