use crate::logs::WLogMessage;
use aya::maps::RingBuf;
use aya::Ebpf;
use log::{debug, info, warn};
use rbpf_loader::control;
use rbpf_loader::logs;
use rbpf_loader::logs::log_sender;
use rbpf_loader::settings;
use std::sync::mpsc;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
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
    info!("Initializing BPF program...");

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rbpf"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let settings = Arc::new(settings::read_settings(&mut ebpf).await?);
    let logs_ring_buf = RingBuf::try_from(ebpf.take_map(logs::LOGS_RING_BUF).unwrap())?;
    let (tx, rx) = mpsc::channel::<WLogMessage>();
    spawn(logs::log_listener(logs_ring_buf, settings.clone(), tx));

    if settings.logs_on {
        log_sender(settings.clone(), rx).await;
    } else {
        info!("Send logs to LogsSocket is disabled");
    }

    if settings.control_on {
        control::control_loop(settings.clone(), &mut ebpf).await?;
    } else {
        let mut sig = signal(SignalKind::terminate())?;
        loop {
            sig.recv().await;
        }
    }
    Ok(())
}
