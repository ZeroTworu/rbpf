use crate::control::change_socket_owner;
use crate::rules::get_rule_name;
use crate::settings::Settings;
use aya::maps::{MapData, RingBuf};
use core::net::IpAddr;
use core::str::from_utf8;
use libc::if_indextoname;
use log::{debug, error, info, warn};
use rbpf_common::user::{
    ActionType, LogMessageSerialized, ProtocolType, ProtocolVersionType, TrafficType,
};
use rbpf_common::{LogMessage, DEBUG, INFO, WARN};
use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, LazyLock};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::{watch, RwLock};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::ReverseLookup;
use trust_dns_resolver::TokioAsyncResolver;

pub const LOGS_RING_BUF: &str = "LOGS_RING_BUF";

static DNS_CACHE: LazyLock<Arc<RwLock<HashMap<String, String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

#[derive(Debug)]
pub struct WLogMessage {
    pub msg: LogMessage,
}

impl WLogMessage {
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
        }
    }
    pub fn iface(&self) -> String {
        let mut name_buf = [0u8; libc::IF_NAMESIZE];
        let name_ptr = name_buf.as_mut_ptr() as *mut i8;

        unsafe {
            if if_indextoname(self.msg.ifindex, name_ptr).is_null() {
                String::from("*")
            } else {
                CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
            }
        }
    }
    pub async fn resolve_dst_v4(&self) -> String {
        let store = DNS_CACHE.read().await;
        let dst_addr = self.dest_v4().to_string();

        match store.get(&dst_addr).cloned() {
            Some(addr) => addr,
            None => {
                let resolver =
                    TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
                let response = resolver.reverse_lookup(IpAddr::from(self.dest_v4())).await;
                self.resolver_to_str(response, dst_addr).await
            }
        }
    }

    pub async fn resolve_src_v4(&self) -> String {
        let store = DNS_CACHE.read().await;
        let str_addr = self.src_v4().to_string();

        match store.get(&str_addr).cloned() {
            Some(addr) => addr,
            None => {
                let resolver =
                    TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
                let response = resolver.reverse_lookup(IpAddr::from(self.src_v4())).await;
                self.resolver_to_str(response, str_addr).await
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

    pub async fn log(&self, resolve_ptr_records: bool) -> String {
        let s_ip = if self.msg.v6 {
            self.src_v6().to_string()
        } else {
            self.src_v4().to_string()
        };

        let d_ip = if self.msg.v6 {
            self.dest_v6().to_string()
        } else {
            self.dest_v4().to_string()
        };

        let (src_ptr, dst_ptr) = if resolve_ptr_records {
            (self.resolve_src_v4().await, self.resolve_dst_v4().await)
        } else {
            ("".to_string(), "".to_string())
        };

        let info = if self.msg.input {
            format!(
                "INPUT: ({}) {} {}:{} -> {} {}:{}",
                self.iface(),
                src_ptr,
                s_ip,
                self.msg.source_port,
                dst_ptr,
                d_ip,
                self.msg.destination_port
            )
        } else {
            format!(
                "OUTPUT: ({}) {} {}:{} -> {} {}:{}",
                self.iface(),
                src_ptr,
                s_ip,
                self.msg.source_port,
                dst_ptr,
                d_ip,
                self.msg.destination_port
            )
        };

        let msg = from_utf8(&self.msg.message).unwrap_or_else(|_| "utf-8 decode error");
        if self.msg.rule_id != 0 {
            let rule_name = get_rule_name(self.msg.rule_id).await.unwrap();
            return format!("[{}] {} {}", &msg, &info, &rule_name.name);
        }

        format!("[{}] {}", &msg, &info)
    }

    async fn resolver_to_str(
        &self,
        response: Result<ReverseLookup, ResolveError>,
        key: String,
    ) -> String {
        match response {
            Ok(name) => {
                let mut store = DNS_CACHE.write().await;
                let names: Vec<String> = name
                    .iter()
                    .map(|name| name.to_utf8())
                    .collect::<Vec<String>>();
                let ptr = names.get(0).unwrap().to_string();
                store.insert(key, ptr.clone());
                ptr
            }
            Err(_) => "".to_string(),
        }
    }
}

pub async fn log_listener(
    ring: RingBuf<MapData>,
    resolve_ptr_records: bool,
    tx: mpsc::Sender<WLogMessage>,
) -> anyhow::Result<()> {
    let (_, rx) = watch::channel(false);
    info!("Starting log listener...");
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
                            DEBUG => debug!("{}", msg_wrapper.log(resolve_ptr_records).await),
                            INFO => info!("{}", msg_wrapper.log(resolve_ptr_records).await),
                            WARN => warn!("{}", msg_wrapper.log(resolve_ptr_records).await),
                            _ => error!("{}", msg_wrapper.log(resolve_ptr_records).await),
                        }
                        tx.send(msg_wrapper).unwrap()
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
        if settings.logs_on {
            change_socket_owner(&settings.logs_socket_path, &settings.logs_socket_owner).unwrap();
            info!("Logs sock on {}", settings.logs_socket_path);
        } else {
            info!("Logs server is off.");
            return;
        }
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
