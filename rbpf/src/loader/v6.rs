use aya::maps::HashMap;
use aya::Ebpf;
use log::info;
use std::net::Ipv6Addr;
use yaml_rust2::Yaml;

pub async fn load_v6(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let v6 = &cfg["v6"];

    {
        let mut in_blocklist: HashMap<_, u128, u128> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST_V6_ADDRESSES").unwrap())?;

        for addr in v6["input"]["addresses"].as_vec().unwrap().iter() {
            let v6: Ipv6Addr = String::from(addr.as_str().unwrap()).parse()?;
            info!("address: {} added to IN V6 BLOCKLIST", v6);
            in_blocklist.insert(&v6.to_bits(), 0, 0)?;
        }
    }

    {
        let mut in_blocklist: HashMap<_, u16, u16> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST_V6_PORTS").unwrap())?;

        for port in v6["input"]["ports"].as_vec().unwrap().iter() {
            let port: u16 = String::from(port.as_str().unwrap()).parse()?;
            info!("port: {} added to IN V6 BLOCKLIST", port);
            in_blocklist.insert(&port, 0, 0)?;
        }
    }

    {
        let mut out_blocklist: HashMap<_, u128, u128> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST_V6_ADDRESSES").unwrap())?;

        for addr in v6["output"]["addresses"].as_vec().unwrap().iter() {
            let v6: Ipv6Addr = String::from(addr.as_str().unwrap()).parse()?;
            info!("address: {} added to OUT V6 BLOCKLIST", v6);
            out_blocklist.insert(&v6.to_bits(), 0, 0)?;
        }
    }

    {
        let mut out_blocklist: HashMap<_, u16, u16> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST_V6_PORTS").unwrap())?;

        for port in v6["output"]["ports"].as_vec().unwrap().iter() {
            let port: u16 = String::from(port.as_str().unwrap()).parse()?;
            info!("port: {} added to OUT V6 BLOCKLIST", port);
            out_blocklist.insert(&port, 0, 0)?;
        }
    }
    Ok(())
}
