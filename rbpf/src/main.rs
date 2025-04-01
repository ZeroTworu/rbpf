use aya::maps::RingBuf;
use aya::Ebpf;
use log::{debug, warn};
use rbpf::events;
use rbpf::events::EVENTS;
use rbpf::http;
use rbpf::settings;
use tokio::task::spawn;

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

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rbpf"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let settings = settings::read_settings(&mut ebpf).await?;

    println!("Waiting for logs...");

    if settings.http_api_on {
        spawn(http::api_server());
    }

    let logs_ring_buf = RingBuf::try_from(ebpf.take_map(EVENTS).unwrap())?;
    events::log_listener(logs_ring_buf, settings.resolve_ptr_records).await?;
    Ok(())
}
