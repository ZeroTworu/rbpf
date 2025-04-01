use aya::maps::HashMap;
use aya::Ebpf;
use libc::if_nametoindex;
use log::info;
use rand::Rng;
use rbpf_common::Rule;
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

static STORE: LazyLock<Arc<RwLock<RustHashMap<u32, String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(RustHashMap::new())));

async fn set_rule_name(key: u32, value: String) {
    let mut store = STORE.write().await;
    store.insert(key, value);
}

pub async fn get_rule_name(key: u32) -> Option<String> {
    let store = STORE.read().await;
    store.get(&key).cloned()
}

const RULES_IN_V4: &str = "RULES_IN_V4";
const RULES_OUT_V4: &str = "RULES_OUT_V4";
const RULES_IN_V6: &str = "RULES_IN_V6";
const RULES_OUT_V6: &str = "RULES_OUT_V6";

struct RuleWithName {
    name: String,
    rule: Rule,
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

        Self {
            name: name.to_string(),
            rule: Rule {
                drop,
                ok,

                v4,
                v6,

                tcp,
                udp,

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

                destination_addr_v6,
                source_addr_v6,

                source_mask_v6,
                destination_mask_v6,
            },
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
            .iter()
            .filter(|r| r.rule.input && r.rule.v4)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_input.insert(uindex, rule.rule, 0)?;
            set_rule_name(rule.rule.rule_id, rule.name.to_string()).await;
            info!("Loading input rule IPv4: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_output: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V4).unwrap())?;
        for (index, rule) in rules
            .iter()
            .filter(|r| r.rule.output && r.rule.v4)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_output.insert(uindex, rule.rule, 0)?;
            set_rule_name(rule.rule.rule_id, rule.name.to_string()).await;
            info!("Loading output rule IPv4: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_output_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V6).unwrap())?;
        for (index, rule) in rules
            .iter()
            .filter(|r| r.rule.output && r.rule.v6)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_output_v6.insert(uindex, rule.rule, 0)?;
            set_rule_name(rule.rule.rule_id, rule.name.to_string()).await;
            info!("Loading output rule IPv6: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_input_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V6).unwrap())?;
        for (index, rule) in rules
            .iter()
            .filter(|r| r.rule.input && r.rule.v6)
            .enumerate()
        {
            let uindex = u32::try_from(index)?;
            rules_input_v6.insert(uindex, rule.rule, 0)?;
            set_rule_name(rule.rule.rule_id, rule.name.to_string()).await;
            info!("Loading input rule IPv6: {}, index: {}", rule.name, index);
        }
    }

    Ok(())
}
