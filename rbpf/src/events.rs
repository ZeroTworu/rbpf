use crate::rules::get_rule_name;
use aya::maps::HashMap;
use aya::Ebpf;
use aya::Pod;
use core::net::IpAddr;
use core::str::from_utf8;
use libc::if_indextoname;
use log::{debug, error, info, warn};
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::time::{sleep, Duration};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::ReverseLookup;
use trust_dns_resolver::TokioAsyncResolver;

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

    pub source_addr_v6: u128,
    pub destination_addr_v6: u128,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port: u16,
    pub destination_port: u16,

    pub level: u8,
}

impl LogMessage {
    pub fn iface(&self) -> String {
        let mut name_buf = [0u8; libc::IF_NAMESIZE];
        let name_ptr = name_buf.as_mut_ptr() as *mut i8;

        unsafe {
            if if_indextoname(self.ifindex, name_ptr).is_null() {
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
        Ipv4Addr::from(self.destination_addr_v4)
    }
    pub fn dest_v6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.destination_addr_v6)
    }
    pub fn src_v4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.source_addr_v4)
    }
    pub fn src_v6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.source_addr_v6)
    }

    pub async fn log(&self) -> String {
        self.resolve_dst_v4().await;
        let s_ip = if self.v6 {
            self.src_v6().to_string()
        } else {
            self.src_v4().to_string()
        };

        let d_ip = if self.v6 {
            self.dest_v6().to_string()
        } else {
            self.dest_v4().to_string()
        };

        let src_ptr = self.resolve_src_v4().await;
        let dst_ptr = self.resolve_dst_v4().await;

        let info = if self.input {
            format!(
                "INPUT: ({}) {} {}:{} -> {} {}:{}",
                self.iface(),
                src_ptr,
                s_ip,
                self.source_port,
                dst_ptr,
                d_ip,
                self.destination_port
            )
        } else {
            format!(
                "OUTPUT: ({}) {} {}:{} -> {} {}:{}",
                self.iface(),
                src_ptr,
                s_ip,
                self.source_port,
                dst_ptr,
                d_ip,
                self.destination_port
            )
        };

        let msg = from_utf8(&self.message).unwrap_or_else(|_| "utf-8 decode error");
        if self.rule_id != 0 {
            let rule_name = get_rule_name(self.rule_id).await.unwrap();
            return format!("{} {} by ({})", &info, &msg, &rule_name);
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

unsafe impl Pod for LogMessage {}

// Костыль что бы не заморачиваться с передачей enum eBPF -> userspace
pub const DEBUG: u8 = 0;
pub const INFO: u8 = 1;
pub const WARN: u8 = 2;

pub async fn log_listener(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    // TODO: Переделать на Ring*
    let mut events: HashMap<_, u32, LogMessage> = HashMap::try_from(ebpf.map_mut(EVENTS).unwrap())?;
    loop {
        let data = events.get(&0, 0);
        match data {
            Ok(log) => {
                events.remove(&0)?;
                match log.level {
                    DEBUG => debug!("{}", log.log().await),
                    INFO => info!("{}", log.log().await),
                    WARN => warn!("{}", log.log().await),
                    _ => error!("{}", log.log().await),
                }
            }
            Err(_) => {}
        }
        sleep(Duration::from_millis(5)).await;
    }
}
