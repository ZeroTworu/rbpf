use crate::loader::helpers::{ports_maker, v6_addresses_maker};
use aya::maps::HashMap;
use aya::Ebpf;
use log::warn;
use yaml_rust2::Yaml;

const OUT_BLOCKLIST_V6_PORTS: &str = "OUT_BLOCKLIST_V6_PORTS";
const OUT_BLOCKLIST_V6_ADDRESSES: &str = "OUT_BLOCKLIST_V6_ADDRESSES";

const IN_BLOCKLIST_V6_PORTS: &str = "IN_BLOCKLIST_V6_PORTS";

const IN_BLOCKLIST_V6_ADDRESSES: &str = "IN_BLOCKLIST_V6_ADDRESSES";

// const IN_BLOCKLIST_V6_IP_PORT: &str = "IN_BLOCKLIST_V6_IP_PORT";
//
// const OUT_BLOCKLIST_V6_IP_PORT: &str = "OUT_BLOCKLIST_V6_IP_PORT";

fn load_in_addresses(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()>     {
    let mut in_blocklist: HashMap<_, u128, u128> =
        HashMap::try_from(ebpf.map_mut(IN_BLOCKLIST_V6_ADDRESSES).unwrap())?;

    match cfg.as_vec() {
        Some(addresses) => {
            for addr in addresses {
                v6_addresses_maker(&mut in_blocklist, addr)?;
            }
        }
        None => warn!("Addresses not found in {}", IN_BLOCKLIST_V6_ADDRESSES),
    }
    Ok(())
}

fn load_in_ports(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()>  {
    let mut in_blocklist: HashMap<_, u16, u16> =
        HashMap::try_from(ebpf.map_mut(IN_BLOCKLIST_V6_PORTS).unwrap())?;

    match cfg.as_vec() {
        Some(ports) => {
            for port in ports {
                ports_maker(&mut in_blocklist, port)?
            }
        }
        None => warn!("Ports not found in {}", IN_BLOCKLIST_V6_PORTS),
    }
    Ok(())
}

fn load_out_addresses(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()>  {
    let mut out_blocklist: HashMap<_, u128, u128> =
        HashMap::try_from(ebpf.map_mut(OUT_BLOCKLIST_V6_ADDRESSES).unwrap())?;

    match cfg.as_vec() {
        Some(addresses) => {
            for addr in addresses {
                v6_addresses_maker(&mut out_blocklist, addr)?;
            }
        }
        None => warn!("Addresses not found in {}", OUT_BLOCKLIST_V6_ADDRESSES),
    }
    Ok(())
}

fn load_out_ports(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()>  {
    let mut out_blocklist: HashMap<_, u16, u16> =
        HashMap::try_from(ebpf.map_mut(OUT_BLOCKLIST_V6_PORTS).unwrap())?;

    match cfg.as_vec() {
        Some(ports) => {
            for port in ports {
                ports_maker(&mut out_blocklist, port)?
            }
        }
        None => warn!("Ports not found in {}", OUT_BLOCKLIST_V6_PORTS),
    }
    Ok(())
}

pub fn load_v6(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let v6 = &cfg["v6"];

    load_in_addresses(ebpf, &v6["input"]["addresses"])?;
    load_in_ports(ebpf, &v6["input"]["ports"])?;

    load_out_addresses(ebpf, &v6["output"]["addresses"])?;
    load_out_ports(ebpf, &v6["output"]["ports"])?;

    Ok(())
}
