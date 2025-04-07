use crate::logs::WLogMessage;
use aya::Ebpf;
use aya::maps::RingBuf;
use log::{debug, info};
use rbpf_loader::control;
use rbpf_loader::logs;
use rbpf_loader::logs::log_sender;
use rbpf_loader::settings;
use std::sync::Arc;
use std::sync::mpsc;
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};
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

    let mut ebpf = get_rbpf().await?;

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

async fn get_rbpf() -> anyhow::Result<Ebpf> {
    #[cfg(feature = "embed-ebpf")]
    {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rbpf"));
        let ebpf = Ebpf::load(&bytes)?;
        Ok(ebpf)
    }

    #[cfg(not(feature = "embed-ebpf"))]
    {
        use std::path::PathBuf;
        use tokio::fs;

        let mut path = PathBuf::from("/app/ebpf/rbpf.o");
        if !path.exists() {
            path = PathBuf::from("./rbpf.o");
        }
        let data = fs::read(path).await?;
        let mut ebpf = Ebpf::load(&data)?;
        Ok(ebpf)
    }
}
