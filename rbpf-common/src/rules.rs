#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,
    pub on: bool,
    pub input: bool,
    pub output: bool,

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub _reserved: bool,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub _pad1: [u8; 6],

    #[cfg(target_arch = "arm")]
    pub _pad1: [u8; 5],

    pub source_addr_v6: u128,
    pub destination_addr_v6: u128,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port_start: u16,
    pub source_port_end: u16,
    pub destination_port_start: u16,
    pub destination_port_end: u16,

    pub source_mask_v4: u8,
    pub destination_mask_v4: u8,
    pub source_mask_v6: u8,
    pub destination_mask_v6: u8,

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub _pad2: [u8; 4],
}

#[derive(PartialEq, Eq)]
pub enum Action {
    Drop = 1,
    Ok = 2,
    Pipe = 3,
}

impl Rule {
    pub fn to_action(&self) -> Action {
        if self.drop {
            return Action::Drop;
        }
        if self.ok {
            return Action::Ok;
        }
        Action::Pipe
    }
    pub fn is_source_v4_not_empty(&self) -> bool {
        self.source_addr_v4 != 0 || self.source_port_start != 0 || self.source_port_end != 0
    }
    pub fn is_source_v6_not_empty(&self) -> bool {
        self.source_addr_v6 != 0 || self.source_port_start != 0 || self.source_port_end != 0
    }
    pub fn is_destination_v4_not_empty(&self) -> bool {
        self.destination_addr_v4 != 0
            || self.destination_port_start != 0
            || self.destination_port_end != 0
    }
    pub fn is_destination_v6_not_empty(&self) -> bool {
        self.destination_addr_v6 != 0
            || self.destination_port_start != 0
            || self.destination_port_end != 0
    }
}

#[cfg(feature = "user")]
pub mod rules {
    use crate::rules::Rule;
    use libc::if_nametoindex;
    use poem_openapi::Object;
    use rand::Rng;
    use serde::{Deserialize, Serialize};
    use std::ffi::CString;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use yaml_rust2::Yaml;

    unsafe impl aya::Pod for Rule {}

    #[derive(Clone, Debug, Deserialize, Serialize, Object)]
    pub struct RuleWithName {
        pub name: String,
        pub uindex: u32,

        pub drop: bool,
        pub ok: bool,
        pub v4: bool,
        pub v6: bool,
        pub tcp: bool,
        pub udp: bool,
        pub on: bool,

        pub src_ip_high: u64,
        pub src_ip_low: u64,
        pub dst_ip_high: u64,
        pub dst_ip_low: u64,

        pub source_addr_v4: u32,
        pub destination_addr_v4: u32,
        pub rule_id: u32,
        pub ifindex: u32,

        pub source_port_start: u16,
        pub source_port_end: u16,
        pub destination_port_start: u16,
        pub destination_port_end: u16,

        pub input: bool,
        pub output: bool,

        pub source_mask_v4: u8,
        pub destination_mask_v4: u8,
        pub source_mask_v6: u8,
        pub destination_mask_v6: u8,

        pub from_db: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Control {
        pub action: ControlAction,
        pub rule: RuleWithName,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ControlAction {
        Reload = 0,
        GetRules = 1,
        UpdateRule = 2,
        CreateRule = 3,
    }

    fn parse_network_v4(addr: &str) -> (u32, u8) {
        if addr.is_empty() {
            return (0, 0);
        }
        if addr.contains("/") {
            let parts = addr.split("/").collect::<Vec<&str>>();
            return (
                parts[0].parse::<Ipv4Addr>().unwrap().to_bits(),
                parts[1].parse::<u8>().unwrap(),
            );
        }
        (addr.parse::<Ipv4Addr>().unwrap().to_bits(), 0)
    }

    fn parse_network_v6(addr: &str) -> (u128, u8) {
        if addr.is_empty() {
            return (0, 0);
        }
        if addr.contains("/") {
            let parts = addr.split("/").collect::<Vec<&str>>();
            return (
                parts[0].parse::<Ipv6Addr>().unwrap().to_bits(),
                parts[1].parse::<u8>().unwrap(),
            );
        }
        (addr.parse::<Ipv6Addr>().unwrap().to_bits(), 0)
    }

    fn get_ifindex_by_name(name: &str) -> u32 {
        if name.contains("*") {
            return 0u32;
        }
        let c_iface_name = CString::new(name).unwrap();
        let ifindex: u32 = unsafe { if_nametoindex(c_iface_name.as_ptr()) };
        ifindex
    }

    impl RuleWithName {
        pub fn from_yaml(yaml: &Yaml) -> Self {
            // TODO: А не так страшно можно?
            let name = yaml["name"].as_str().unwrap();

            let tcp = yaml["tcp"].as_bool().unwrap();
            let udp = yaml["udp"].as_bool().unwrap();

            let on = yaml["on"].as_bool().unwrap();

            let ok = yaml["ok"].as_bool().unwrap();
            let drop = yaml["drop"].as_bool().unwrap();

            let input = yaml["input"].as_bool().unwrap();
            let output = yaml["output"].as_bool().unwrap();

            let v4 = yaml["v4"].as_bool().unwrap();
            let v6 = yaml["v6"].as_bool().unwrap();

            let saddrv4_ip = yaml["source_addr_v4"].as_str().unwrap();
            let daddrv4_ip = yaml["destination_addr_v4"].as_str().unwrap();

            let saddrv6_ip = yaml["source_addr_v6"].as_str().unwrap();
            let daddrv6_ip = yaml["destination_addr_v6"].as_str().unwrap();

            let source_port_start: u16 = yaml["source_port_start"].as_i64().unwrap() as u16;
            let source_port_end: u16 = yaml["source_port_end"].as_i64().unwrap() as u16;

            let destination_port_start: u16 =
                yaml["destination_port_start"].as_i64().unwrap() as u16;
            let destination_port_end: u16 = yaml["destination_port_end"].as_i64().unwrap() as u16;

            let iface = yaml["iface"].as_str().unwrap();
            let ifindex = get_ifindex_by_name(iface);

            let (source_addr_v4, source_mask_v4) = parse_network_v4(saddrv4_ip);
            let (destination_addr_v4, destination_mask_v4) = parse_network_v4(daddrv4_ip);

            let (source_addr_v6, source_mask_v6) = parse_network_v6(saddrv6_ip);
            let (destination_addr_v6, destination_mask_v6) = parse_network_v6(daddrv6_ip);

            let rule_id: u32 = rand::rng().random();

            let src_ip_high: u64 = (source_addr_v6 >> 64) as u64;
            let src_ip_low: u64 = source_addr_v6 as u64;

            let dst_ip_high: u64 = (destination_addr_v6 >> 64) as u64;
            let dst_ip_low: u64 = destination_addr_v6 as u64;

            Self {
                name: name.to_string(),
                uindex: 0,

                drop,
                ok,

                v4,
                v6,

                tcp,
                udp,

                on,

                input,
                output,

                source_port_start,
                source_port_end,

                destination_port_start,
                destination_port_end,

                source_addr_v4,
                destination_addr_v4,

                source_mask_v4,
                destination_mask_v4,

                rule_id,

                ifindex,

                src_ip_high,
                src_ip_low,
                dst_ip_high,
                dst_ip_low,

                source_mask_v6,
                destination_mask_v6,
                from_db: false,
            }
        }

        #[cfg(target_arch = "arm")]
        pub fn to_common_rule(&self) -> Rule {
            Rule {
                drop: self.drop,
                ok: self.ok,
                v4: self.v4,
                v6: self.v6,
                tcp: self.tcp,
                udp: self.udp,
                on: self.on,
                input: self.input,
                output: self.output,
                _pad1: [0; 5],

                source_addr_v6: ((self.src_ip_high as u128) << 64) | (self.src_ip_low as u128),
                destination_addr_v6: ((self.dst_ip_high as u128) << 64) | (self.dst_ip_low as u128),

                source_addr_v4: self.source_addr_v4,
                destination_addr_v4: self.destination_addr_v4,
                rule_id: self.rule_id,
                ifindex: self.ifindex,

                source_port_start: self.source_port_start,
                source_port_end: self.source_port_end,
                destination_port_start: self.destination_port_start,
                destination_port_end: self.destination_port_end,

                source_mask_v4: self.source_mask_v4,
                destination_mask_v4: self.destination_mask_v4,
                source_mask_v6: self.source_mask_v6,
                destination_mask_v6: self.destination_mask_v6,
            }
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        pub fn to_common_rule(&self) -> Rule {
            Rule {
                drop: self.drop,
                ok: self.ok,
                v4: self.v4,
                v6: self.v6,
                tcp: self.tcp,
                udp: self.udp,
                on: self.on,
                input: self.input,
                output: self.output,
                _reserved: false,
                _pad1: [0; 6],

                source_addr_v6: ((self.src_ip_high as u128) << 64) | (self.src_ip_low as u128),
                destination_addr_v6: ((self.dst_ip_high as u128) << 64) | (self.dst_ip_low as u128),

                source_addr_v4: self.source_addr_v4,
                destination_addr_v4: self.destination_addr_v4,
                rule_id: self.rule_id,
                ifindex: self.ifindex,

                source_port_start: self.source_port_start,
                source_port_end: self.source_port_end,
                destination_port_start: self.destination_port_start,
                destination_port_end: self.destination_port_end,

                source_mask_v4: self.source_mask_v4,
                destination_mask_v4: self.destination_mask_v4,
                source_mask_v6: self.source_mask_v6,
                destination_mask_v6: self.destination_mask_v6,
                _pad2: [0; 4],
            }
        }

        pub fn from_empty() -> Self {
            Self {
                name: String::from("Empty fake rule!"),
                uindex: 0,

                drop: false,
                ok: false,

                v4: false,
                v6: false,

                tcp: false,
                udp: false,

                on: false,

                input: false,
                output: false,

                source_port_start: 0,
                source_port_end: 0,

                destination_port_start: 0,
                destination_port_end: 0,

                source_addr_v4: 0,
                destination_addr_v4: 0,

                source_mask_v4: 0,
                destination_mask_v4: 0,

                rule_id: 0,

                ifindex: 0,

                src_ip_high: 0,
                src_ip_low: 0,
                dst_ip_high: 0,
                dst_ip_low: 0,

                source_mask_v6: 0,
                destination_mask_v6: 0,
                from_db: false,
            }
        }
    }
}
