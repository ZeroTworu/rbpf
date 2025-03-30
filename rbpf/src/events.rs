use aya::maps::HashMap;
use aya::Ebpf;
use aya::Pod;
use tokio::time::{sleep, Duration};

use core::str::from_utf8;
//use crate::rules::{RULES};

const EVENTS: &str = "EVENTS";

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct LogMessage {
    pub message: [u8; 128],
    pub level: u8,
    pub rule_id: u32,
    pub by_rule: bool,
}

unsafe impl Pod for LogMessage {}

impl LogMessage {
    fn log(&self) -> String {
        let msg = from_utf8(&self.message).unwrap_or_else(|_| "utf-8 decode error");
        if self.by_rule {
            return format!("{} by ({})", &msg, &self.rule_id);
        }
        msg.to_string()
    }
}

pub async fn log_listener(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut events: HashMap<_, u32, LogMessage> = HashMap::try_from(ebpf.map_mut(EVENTS).unwrap())?;
    loop {
        let data = events.get(&0, 0);
        match data {
            Ok(log) => {
                println!("Received: {}", log.log());
            }
            Err(_) => {}
        }
        sleep(Duration::from_millis(500)).await;
    }
}
