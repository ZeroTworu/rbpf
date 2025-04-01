use crate::rules;
use aya::Ebpf;
use log::info;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct Control {
    pub reload: bool,
    pub rules_path: String,
}

pub async fn control_loop(ebpf: &mut Ebpf, rx: &mut mpsc::Receiver<Control>) -> anyhow::Result<()> {
    info!("Starting control loop...");
    loop {
        while let Some(event) = rx.recv().await {
            if event.reload {
                rules::load_rules(&event.rules_path, ebpf).await?;
            }
            tokio::time::sleep(Duration::from_millis(100)).await; // Симуляция обработки
        }
    }
}
