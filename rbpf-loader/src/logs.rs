use crate::control::change_socket_owner_mode;
use crate::elasticsearch::ElasticLogs;
use crate::ipproto;
use crate::rules::get_rule_name;
use crate::settings::Settings;
use aya::maps::{MapData, RingBuf};
use core::str::from_utf8;
use libc::if_indextoname;
use libc::{CLOCK_MONOTONIC, clock_gettime, timespec};
use log::{debug, error, info, warn};
use rbpf_common::logs::logs::{
    ActionType, LogMessageSerialized, ProtocolType, ProtocolVersionType, TrafficType,
};
use rbpf_common::logs::{DEBUG, ERROR, INFO, LogMessage, WARN};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::net::UnixListener;
use tokio::sync::watch;

pub const LOGS_RING_BUF: &str = "LOGS_RING_BUF";

#[derive(Debug)]
pub struct WLogMessage {
    pub msg: LogMessage,
}

impl WLogMessage {
    pub async fn get_rule_name<'a>(&'a self) -> &'a str {
        if self.msg.rule_id != 0 {
            let rule = get_rule_name(self.msg.rule_id).await.unwrap();
            rule.name;
        }
        ""
    }

    pub async fn to_serialized(&self) -> LogMessageSerialized {
        let rule_name = if self.msg.rule_id != 0 {
            match get_rule_name(self.msg.rule_id).await {
                Some(rule) => rule.name,
                None => "No rule for this ID".to_string(),
            }
        } else {
            "".to_string()
        };

        let rule_action = if self.msg.rule_id != 0 {
            match get_rule_name(self.msg.rule_id).await {
                Some(rule) => {
                    if rule.drop {
                        ActionType::Drop
                    } else {
                        ActionType::Ok
                    }
                }
                None => ActionType::Pipe,
            }
        } else {
            ActionType::Pipe
        };

        LogMessageSerialized {
            traffic_type: if self.msg.input {
                TrafficType::Input
            } else {
                TrafficType::Output
            },
            protocol_type: if self.msg.tcp {
                ProtocolType::TCP
            } else {
                ProtocolType::UDP
            },
            protocol_version_type: if self.msg.v4 {
                ProtocolVersionType::V4
            } else {
                ProtocolVersionType::V6
            },
            action: rule_action,
            source_addr_v4: self.src_v4(),
            destination_addr_v4: self.dest_v4(),

            source_addr_v6: self.src_v6(),
            destination_addr_v6: self.dest_v6(),
            rule_id: self.msg.rule_id,
            level: self.msg.level,
            if_name: self.iface(),
            source_port: self.msg.source_port,
            destination_port: self.msg.destination_port,
            rule_name,
            timestamp: self.unix_time_stamp(),
        }
    }
    pub fn iface(&self) -> String {
        let mut name_buf = [0u8; libc::IF_NAMESIZE];
        let name_ptr = name_buf.as_mut_ptr() as *mut c_char;

        unsafe {
            if if_indextoname(self.msg.ifindex, name_ptr).is_null() {
                String::from("*")
            } else {
                CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
            }
        }
    }
    pub fn dest_v4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.msg.destination_addr_v4)
    }
    pub fn dest_v6(&self) -> Ipv6Addr {
        let dst_ip = ((self.msg.dst_ip_high as u128) << 64) | (self.msg.dst_ip_low as u128);
        Ipv6Addr::from(dst_ip)
    }
    pub fn src_v4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.msg.source_addr_v4)
    }
    pub fn src_v6(&self) -> Ipv6Addr {
        let src_ip = ((self.msg.src_ip_high as u128) << 64) | (self.msg.src_ip_low as u128);
        Ipv6Addr::from(src_ip)
    }

    pub async fn log(&self) -> String {
        let s_ip = if !self.msg.v4 {
            self.src_v6().to_string()
        } else {
            self.src_v4().to_string()
        };

        let d_ip = if !self.msg.v4 {
            self.dest_v6().to_string()
        } else {
            self.dest_v4().to_string()
        };

        let proto = format!(
            "{}",
            if self.msg.udp && self.msg.tcp {
                " TCP UDP"
            } else if self.msg.udp {
                " UDP"
            } else if self.msg.tcp {
                " TCP"
            } else {
                ""
            }
        );

        let info = if self.msg.input {
            format!(
                "INPUT: ({}{}) {} -> {}",
                self.iface(),
                proto,
                if self.msg.source_port != 0 {
                    format!("{}:{}", s_ip, self.msg.source_port)
                } else {
                    s_ip.to_string()
                },
                if self.msg.destination_port != 0 {
                    format!("{}:{}", d_ip, self.msg.destination_port)
                } else {
                    d_ip.to_string()
                }
            )
        } else {
            format!(
                "OUTPUT: ({}{}) {} -> {}",
                self.iface(),
                proto,
                if self.msg.source_port != 0 {
                    format!("{}:{}", s_ip, self.msg.source_port)
                } else {
                    s_ip.to_string()
                },
                if self.msg.destination_port != 0 {
                    format!("{}:{}", d_ip, self.msg.destination_port)
                } else {
                    d_ip.to_string()
                }
            )
        };

        let msg = from_utf8(&self.msg.message).unwrap_or_else(|_| "utf-8 decode error");
        if self.msg.rule_id != 0 {
            let rule_name = get_rule_name(self.msg.rule_id).await.unwrap();
            return format!("[{}] {} {}", &msg, &info, &rule_name.name);
        }

        if self.msg.level == ERROR {
            format!(
                "[{}] {} {}",
                &msg,
                ipproto::from_u8_to_str(&self.msg.unhandled_protocol),
                &info
            )
        } else {
            format!("[{}] {}", &msg, &info)
        }
    }

    pub fn unix_time_stamp(&self) -> u64 {
        let mut ts: timespec = unsafe { MaybeUninit::zeroed().assume_init() };
        let res = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
        if res != 0 {
            return 0;
        }

        let now_ktime_ns = (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64);

        let now = SystemTime::now();
        let boot_time = now - Duration::from_nanos(now_ktime_ns);
        let event_time = boot_time + Duration::from_nanos(self.msg.timestamp);
        event_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

pub async fn log_listener(
    ring: RingBuf<MapData>,
    settings: Arc<Settings>,
    tx: mpsc::Sender<WLogMessage>,
) -> anyhow::Result<()> {
    let (_, rx) = watch::channel(false);
    info!("Starting log listener...");
    let elastic = if settings.elk_on {
        let instance = ElasticLogs::new(settings.elastic_url.as_str()).await?;
        let _ = instance.create_index().await?;
        Some(instance)
    } else {
        None
    };
    let task = tokio::spawn(async move {
        let mut async_fd = AsyncFd::new(ring).unwrap();
        let mut rx = rx.clone();
        loop {
            tokio::select! {
                _ = async_fd.readable_mut() => {
                    let mut guard = async_fd.readable_mut().await.unwrap();
                    let rb = guard.get_inner_mut();
                    while let Some(read) = rb.next() {
                        let msg: LogMessage = unsafe { std::ptr::read_unaligned(read.as_ptr() as *const _) };
                        let msg_wrapper: WLogMessage = WLogMessage { msg };

                        match msg_wrapper.msg.level {
                            DEBUG => debug!("{}", msg_wrapper.log().await),
                            INFO => info!("{}", msg_wrapper.log().await),
                            WARN => warn!("{}", msg_wrapper.log().await),
                            _ => error!("{}", msg_wrapper.log().await),
                        }

                        if let Some(elastic) = &elastic {
                            let res = elastic.index_log_message(&msg_wrapper).await;
                            match res {
                                Ok(_) => {},
                                Err(e) => error!("Elastic error: {}", e)
                            }
                        }

                        if settings.logs_on {
                            tx.send(msg_wrapper).unwrap()
                        }
                    }

                    guard.clear_ready();
                },
                _ = rx.changed() => {
                    if *rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
    task.await?;
    Ok(())
}

pub async fn log_sender(settings: Arc<Settings>, rx: mpsc::Receiver<WLogMessage>) {
    tokio::spawn(async move {
        if Path::new(&settings.logs_socket_path).exists() {
            std::fs::remove_file(&settings.logs_socket_path).unwrap();
        }

        let logs_listener = UnixListener::bind(&settings.logs_socket_path).unwrap();
        change_socket_owner_mode(
            &settings.logs_socket_path,
            &settings.logs_socket_owner,
            settings.logs_socket_chmod,
        )
        .unwrap();
        info!("Logs socket on {}", settings.logs_socket_path);
        loop {
            let (mut socket, _) = logs_listener.accept().await.unwrap();
            loop {
                let msg = rx.recv().unwrap();
                let serialized = serde_json::to_vec(&msg.to_serialized().await).unwrap();
                let len = (serialized.len() as u32).to_be_bytes();

                if socket.write_all(&len).await.is_err() {
                    error!("Client disconnected when sending len of message");
                    break;
                }
                if socket.write_all(&serialized).await.is_err() {
                    error!("Client disconnected when sending serialized message");
                    break;
                }
            }
        }
    });
}
