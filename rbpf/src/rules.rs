use aya::Pod;
use aya::maps::Array;
use aya::Ebpf;
use log::warn;
use tokio::fs::read_to_string;
use yaml_rust2::{YamlLoader, Yaml};
use std::fs::read_dir;
use std::net::Ipv4Addr;
use clap::builder::TypedValueParser;

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub port: u16,
    pub addr: u32,
    pub tcp: bool,
    pub udp: bool,
}

impl Rule {
    pub fn new(yaml: &Yaml) -> Self {
        let drop = yaml["drop"].as_bool().unwrap();
        let ok = yaml["ok"].as_bool().unwrap();
        let v4 = yaml["v4"].as_bool().unwrap();
        let v6 = yaml["v6"].as_bool().unwrap();
        let tcp = yaml["v6"].as_bool().unwrap();
        let udp = yaml["v6"].as_bool().unwrap();
        let port = yaml["port"].as_i64().unwrap() as u16;
        let addrv4: Ipv4Addr = yaml["addr"].as_str().unwrap().parse().unwrap();
        Self{
            drop,
            ok,
            v4,
            v6,
            tcp,
            udp,
            port,
            addr: addrv4.to_bits(),
        }
    }
}

unsafe impl Pod for Rule {}

pub async  fn load_rules(path: &str, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut rules: Array<_, Rule> =
        Array::try_from(ebpf.map_mut("RULES").unwrap())?;
    let paths = read_dir(path)?;

    for (index, path) in paths.enumerate() {
        let uindex = u32::try_from(index)?;
        let srule = read_to_string(path?.path()).await?;
        let yrule = &YamlLoader::load_from_str(&srule)?[0];
        let rule = Rule::new(yrule);
        rules.set(uindex, rule, 0)?
    }

    Ok(())
}
