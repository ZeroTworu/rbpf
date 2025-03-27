use aya::programs::{SchedClassifier, TcAttachType};
use aya::maps::HashMap;
use clap::Parser;
use log::{debug, warn};
use tokio::signal;
use std::net::Ipv4Addr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long, default_value = "127.0.0.1")]
    iaddr: String,
    #[clap(long, default_value = "127.0.0.1")]
    oaddr: String,
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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rbpf"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program_egress: &mut SchedClassifier =
        ebpf.program_mut("tc_egress").unwrap().try_into()?;

    program_egress.load()?;
    program_egress.attach(&opt.iface, TcAttachType::Egress)?;


    let program_ingress: &mut SchedClassifier =
        ebpf.program_mut("tc_ingress").unwrap().try_into()?;

    program_ingress.load()?;
    program_ingress.attach(&opt.iface, TcAttachType::Ingress)?;

    {
        let mut in_blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST").unwrap())?;
        let in_addr: Ipv4Addr = opt.iaddr.parse()?;
        in_blocklist.insert(&in_addr.into(), 0, 0)?;
    }

    {
        let mut out_blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST").unwrap())?;

        let out_addr: Ipv4Addr = opt.oaddr.parse()?;
        out_blocklist.insert(&out_addr.into(), 0, 0)?;
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;

    Ok(())
}
