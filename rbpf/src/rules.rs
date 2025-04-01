use aya::maps::HashMap;
use aya::Ebpf;
use libc::if_nametoindex;
use log::info;
use poem_openapi::Object;
use rand::Rng;
use rbpf_common::Rule;
use serde::{Deserialize, Serialize};
use std::collections::HashMap as RustHashMap;
use std::ffi::CString;
use std::fs::read_dir;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::LazyLock;
use std::vec::Vec;
use tokio::fs::read_to_string;
use tokio::sync::RwLock;
use yaml_rust2::{Yaml, YamlLoader};

static STORE: LazyLock<Arc<RwLock<RustHashMap<u32, RuleWithName>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(RustHashMap::new())));

async fn set_rule_name(key: u32, value: RuleWithName) {
    let mut store = STORE.write().await;
    store.insert(key, value);
}

pub async fn get_rule_name(key: u32) -> Option<RuleWithName> {
    let store = STORE.read().await;
    store.get(&key).cloned()
}

pub async fn get_rules() -> RustHashMap<u32, RuleWithName> {
    let store = STORE.read().await;
    store.clone()
}

const RULES_IN_V4: &str = "RULES_IN_V4";
const RULES_OUT_V4: &str = "RULES_OUT_V4";
const RULES_IN_V6: &str = "RULES_IN_V6";
const RULES_OUT_V6: &str = "RULES_OUT_V6";

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
    pub fn new(yaml: &Yaml) -> Self {
        // TODO: А не так страшно можно?
        let name = yaml["name"].as_str().unwrap();

        let tcp = yaml["tcp"].as_bool().unwrap();
        let udp = yaml["udp"].as_bool().unwrap();
        let on = yaml["on"].as_bool().unwrap();
        println!("name: {}, on: {}", name, on);
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

        let destination_port_start: u16 = yaml["destination_port_start"].as_i64().unwrap() as u16;
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
        }
    }

    pub fn to_common_rules(&self) -> Rule {
        Rule{
            source_port_end: self.source_port_end,
            source_port_start: self.source_port_start,

            destination_port_end: self.destination_port_end,
            destination_port_start: self.destination_port_start,

            drop: self.drop,

            ok: self.ok,
            on: self.on,

            v4: self.v4,
            v6: self.v6,

            tcp: self.tcp,
            udp: self.udp,

            input: self.input,
            output: self.output,

            destination_mask_v4: self.destination_mask_v4,
            destination_mask_v6: self.destination_mask_v6,

            source_mask_v4: self.source_mask_v4,
            source_mask_v6: self.source_mask_v6,

            destination_addr_v4: self.source_addr_v4,
            destination_addr_v6: ((self.dst_ip_high as u128) << 64) | (self.dst_ip_low as u128),

            source_addr_v4: self.source_addr_v4,
            source_addr_v6: ((self.src_ip_high as u128) << 64) | (self.src_ip_low as u128),

            rule_id: self.rule_id,
            ifindex: self.ifindex,
        }
    }
}

pub async fn load_rules(path: &str, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let paths = read_dir(path)?;
    let mut rules: Vec<RuleWithName> = Vec::new();

    for path in paths {
        let path = path?.path();
        if !path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".yaml")
        {
            continue;
        }
        let srule = read_to_string(path).await?;
        let yrule = &YamlLoader::load_from_str(&srule)?[0];
        let rule = RuleWithName::new(yrule);
        rules.push(rule);
    }
    {
        let mut rules_input: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V4).unwrap())?;
        for (index, rule) in rules
            .iter_mut()
            .filter(|r| r.input && r.v4)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_input.insert(uindex, rule.to_common_rules(), 0)?;
            rule.uindex = uindex;
            set_rule_name(rule.rule_id, rule.clone()).await;
            info!("Loading input rule IPv4: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_output: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V4).unwrap())?;
        for (index, rule) in rules
            .iter_mut()
            .filter(|r| r.output && r.v4)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_output.insert(uindex, rule.to_common_rules(), 0)?;
            rule.uindex = uindex;
            set_rule_name(rule.rule_id, rule.clone()).await;
            info!("Loading output rule IPv4: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_output_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V6).unwrap())?;
        for (index, rule) in rules
            .iter_mut()
            .filter(|r| r.output && r.v6)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_output_v6.insert(uindex, rule.to_common_rules(), 0)?;
            set_rule_name(rule.rule_id, rule.clone()).await;
            rule.uindex = uindex;
            info!("Loading output rule IPv6: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_input_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V6).unwrap())?;
        for (index, rule) in rules
            .iter_mut()
            .filter(|r| r.input && r.v6)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_input_v6.insert(uindex, rule.to_common_rules(), 0)?;
            rule.uindex = uindex;
            set_rule_name(rule.rule_id, rule.clone()).await;
            info!("Loading input rule IPv6: {}, index: {}", rule.name, index);
        }
    }

    Ok(())
}
