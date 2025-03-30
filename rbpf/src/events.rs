use crate::rules::get_rule_name;
use aya::maps::HashMap;
use aya::Ebpf;
use aya::Pod;
use core::str::from_utf8;
use log::{debug, error, info, warn};
use std::net::Ipv4Addr;
use tokio::time::{sleep, Duration};

const EVENTS: &str = "EVENTS";

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LogMessage {
    pub message: [u8; 128],

    pub input: bool,
    pub output: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,

    pub source_port: u16,
    pub destination_port: u16,

    pub level: u8,
}

unsafe impl Pod for LogMessage {}

// Костыль что бы не заморачиваться с передачей enum eBPF -> userspace
pub const DEBUG: u8 = 0;
pub const INFO: u8 = 1;
pub const WARN: u8 = 2;

impl LogMessage {
    async fn log(&self) -> String {
        let source_addr_v4 = Ipv4Addr::from(self.source_addr_v4);
        let destination_addr_v4 = Ipv4Addr::from(self.destination_addr_v4);
        let info = if self.input {
            format!(
                "INPUT: {}:{} -> {}:{}",
                source_addr_v4, self.source_port, destination_addr_v4, self.destination_port
            )
        } else {
            format!(
                "OUTPUT: {}:{} -> {}:{}",
                source_addr_v4, self.source_port, destination_addr_v4, self.destination_port
            )
        };

        let msg = from_utf8(&self.message).unwrap_or_else(|_| "utf-8 decode error");
        if self.rule_id != 0 {
            let rule_name = get_rule_name(self.rule_id).await.unwrap();
            return format!("{} {} by ({})", &info, &msg, &rule_name);
        }

        format!("{} {}", &msg, &info)
    }
}

pub async fn log_listener(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut events: HashMap<_, u32, LogMessage> = HashMap::try_from(ebpf.map_mut(EVENTS).unwrap())?;
    loop {
        let data = events.get(&0, 0);
        match data {
            Ok(log) => {
                events.remove(&0)?;
                info!("{}", log.log().await)
            }
            Err(_) => {}
        }
        sleep(Duration::from_millis(100)).await;
    }
}
