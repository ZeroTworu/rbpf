use crate::loader::helpers::{ports_maker, v4_addresses_maker, v4_ip_port_maker};
use aya::maps::HashMap;
use aya::Ebpf;
use log::warn;
use yaml_rust2::Yaml;

const OUT_BLOCKLIST_V4_PORTS: &str = "OUT_BLOCKLIST_V4_PORTS";

const OUT_BLOCKLIST_V4_ADDRESSES: &str = "OUT_BLOCKLIST_V4_ADDRESSES";

const IN_BLOCKLIST_V4_PORTS: &str = "IN_BLOCKLIST_V4_PORTS";

const IN_BLOCKLIST_V4_ADDRESSES: &str = "IN_BLOCKLIST_V4_ADDRESSES";

const IN_BLOCKLIST_V4_IP_PORT: &str = "IN_BLOCKLIST_V4_IP_PORT";

const OUT_BLOCKLIST_V4_IP_PORT: &str = "OUT_BLOCKLIST_V4_IP_PORT";

fn load_in_addresses(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let mut in_blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut(IN_BLOCKLIST_V4_ADDRESSES).unwrap())?;

    match cfg.as_vec() {
        Some(addresses) => {
            for addr in addresses {
                v4_addresses_maker(&mut in_blocklist, addr)?
            }
        }
        None => warn!("Addresses not found in {}", IN_BLOCKLIST_V4_ADDRESSES),
    }
    Ok(())
}

fn load_in_ports(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let mut in_blocklist: HashMap<_, u16, u16> =
        HashMap::try_from(ebpf.map_mut(IN_BLOCKLIST_V4_PORTS).unwrap())?;

    match cfg.as_vec() {
        Some(ports) => {
            for port in ports {
                ports_maker(&mut in_blocklist, port)?
            }
        }
        None => warn!("Ports not found in {}", IN_BLOCKLIST_V4_PORTS),
    }
    Ok(())
}

fn load_in_ip_port(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let mut in_blocklist: HashMap<_, u32, u16> =
        HashMap::try_from(ebpf.map_mut(IN_BLOCKLIST_V4_IP_PORT).unwrap())?;

    match cfg.as_vec() {
        Some(ports) => {
            for port in ports {
                v4_ip_port_maker(&mut in_blocklist, port)?
            }
        }
        None => warn!("Ports not found in {}", IN_BLOCKLIST_V4_IP_PORT),
    }
    Ok(())
}

fn load_out_blocklist(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let mut out_blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut(OUT_BLOCKLIST_V4_ADDRESSES).unwrap())?;

    match cfg.as_vec() {
        Some(addresses) => {
            for addr in addresses {
                v4_addresses_maker(&mut out_blocklist, addr)?
            }
        }
        None => warn!("Addresses not found in {}", OUT_BLOCKLIST_V4_ADDRESSES),
    }
    Ok(())
}

fn load_out_ports(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let mut out_blocklist: HashMap<_, u16, u16> =
        HashMap::try_from(ebpf.map_mut(OUT_BLOCKLIST_V4_PORTS).unwrap())?;

    match cfg.as_vec() {
        Some(ports) => {
            for port in ports {
                ports_maker(&mut out_blocklist, port)?
            }
        }
        None => warn!("Ports not found in {}", OUT_BLOCKLIST_V4_PORTS),
    }
    Ok(())
}

fn load_out_ip_port(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let mut in_blocklist: HashMap<_, u32, u16> =
        HashMap::try_from(ebpf.map_mut(OUT_BLOCKLIST_V4_IP_PORT).unwrap())?;

    match cfg.as_vec() {
        Some(ports) => {
            for port in ports {
                v4_ip_port_maker(&mut in_blocklist, port)?
            }
        }
        None => warn!("Ports not found in {}", OUT_BLOCKLIST_V4_IP_PORT),
    }
    Ok(())
}

pub fn load_v4(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let v4 = &cfg["v4"];

    load_in_addresses(ebpf, &v4["input"]["addresses"])?;
    load_in_ip_port(ebpf, &v4["input"]["addresses"])?;
    load_in_ports(ebpf, &v4["input"]["ports"])?;

    load_out_blocklist(ebpf, &v4["output"]["addresses"])?;
    load_out_ip_port(ebpf, &v4["output"]["addresses"])?;
    load_out_ports(ebpf, &v4["output"]["ports"])?;

    Ok(())
}
