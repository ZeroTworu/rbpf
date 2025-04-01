use crate::rules::get_rule_name;
use aya::maps::RingBuf;
use aya::Ebpf;
use core::net::IpAddr;
use core::str::from_utf8;
use libc::if_indextoname;
use log::{debug, error, info, warn};
use rbpf_common::LogMessage;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::ReverseLookup;
use trust_dns_resolver::TokioAsyncResolver;

const EVENTS: &str = "EVENTS";

pub struct WLogMessage {
    pub msg: LogMessage,
}

impl WLogMessage {
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
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let response = resolver.reverse_lookup(IpAddr::from(self.dest_v4())).await;
        self.resolver_to_str(response)
    }

    pub async fn resolve_src_v4(&self) -> String {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let response = resolver.reverse_lookup(IpAddr::from(self.src_v4())).await;
        self.resolver_to_str(response)
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
        self.resolve_dst_v4().await;

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

        let src_ptr = self.resolve_src_v4().await;
        let dst_ptr = self.resolve_dst_v4().await;

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
            return format!("[{}] {} {}", &msg, &info, &rule_name);
        }

        format!("[{}] {}", &msg, &info)
    }

    fn resolver_to_str(&self, response: Result<ReverseLookup, ResolveError>) -> String {
        if let Some(name) = response.iter().next() {
            let names: Vec<String> = name
                .iter()
                .map(|name| name.to_utf8())
                .collect::<Vec<String>>();
            names.get(0).unwrap().to_string()
        } else {
            "".to_string()
        }
    }
}

// Костыль что бы не заморачиваться с передачей enum eBPF -> userspace
pub const DEBUG: u8 = 0;
pub const INFO: u8 = 1;
pub const WARN: u8 = 2;

pub async fn log_listener(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let ring = RingBuf::try_from(ebpf.take_map(EVENTS).unwrap())?;
    let (_, rx) = watch::channel(false);
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
