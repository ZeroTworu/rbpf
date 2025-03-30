use aya::maps::HashMap;
use aya::{Ebpf, Pod};
use log::info;
use rand::Rng;
use std::collections::HashMap as RustHashMap;
use std::fs::read_dir;
use std::net::Ipv4Addr;
use tokio::fs::read_to_string;
use yaml_rust2::{Yaml, YamlLoader};

//pub static mut RULES: RustHashMap<u32, &str> = RustHashMap::new();

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,

    pub source_port_start: u16,
    pub source_port_end: u16,
    pub destination_port_start: u16,
    pub destination_port_end: u16,

    pub input: bool,
    pub output: bool,

    pub source_mask: u8,
    pub destination_mask: u8,
}
unsafe impl Pod for Rule {}

fn parse_network(addr: &str) -> (u32, u8) {
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

impl Rule {
    pub fn new(yaml: &Yaml) -> Self {
        // TODO: А не так страшно можно?
        let name = String::from(yaml["name"].as_str().unwrap());
        let mut buffer = [0u8; 128];
        buffer[..name.len()].copy_from_slice(name.as_bytes());

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

        let source_port_start: u16 = yaml["source_port_start"].as_i64().unwrap() as u16;
        let source_port_end: u16 = yaml["source_port_end"].as_i64().unwrap() as u16;

        let destination_port_start: u16 = yaml["destination_port_start"].as_i64().unwrap() as u16;
        let destination_port_end: u16 = yaml["destination_port_end"].as_i64().unwrap() as u16;

        let (source_addr_v4, source_mask) = parse_network(saddrv4_ip);

        let (destination_addr_v4, destination_mask) = parse_network(daddrv4_ip);
        let rule_id: u32 = rand::rng().random();

        Self {
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
            source_mask,
            destination_mask,
            rule_id,
        }
    }
}

pub async fn load_rules(path: &str, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut rules: HashMap<_, u32, Rule> = HashMap::try_from(ebpf.map_mut("RULES").unwrap())?;
    let paths = read_dir(path)?;

    for (index, path) in paths.enumerate() {
        let uindex = u32::try_from(index)?;
        let srule = read_to_string(path?.path()).await?;
        let yrule = &YamlLoader::load_from_str(&srule)?[0];
        let name = yrule["name"].as_str().unwrap();
        let rule = Rule::new(yrule);
        rules.insert(uindex, rule, 0)?;
        // unsafe {
        //     RULES.insert(rule.rule_id, name);
        // }
        info!("Loading rule: {}, index: {}", name, index);
    }

    Ok(())
}
