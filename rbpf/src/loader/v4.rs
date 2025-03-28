use aya::maps::HashMap;
use aya::Ebpf;
use log::info;
use std::net::Ipv4Addr;
use yaml_rust2::Yaml;

pub async fn load_v4(ebpf: &mut Ebpf, cfg: &Yaml) -> anyhow::Result<()> {
    let v4 = &cfg["v4"];

    {
        let mut in_blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST_V4_ADDRESSES").unwrap())?;

        for addr in v4["input"]["addresses"].as_vec().unwrap().iter() {
            let v4: Ipv4Addr = String::from(addr.as_str().unwrap()).parse()?;
            info!("address: {} added to IN V4 BLOCKLIST", v4);
            in_blocklist.insert(&v4.into(), 0, 0)?;
        }
    }

    {
        let mut in_blocklist: HashMap<_, u16, u16> =
            HashMap::try_from(ebpf.map_mut("IN_BLOCKLIST_V4_PORTS").unwrap())?;

        for port in v4["input"]["ports"].as_vec().unwrap().iter() {
            let port: u16 = String::from(port.as_str().unwrap()).parse()?;
            info!("port: {} added to IN V4 BLOCKLIST", port);
            in_blocklist.insert(&port, 0, 0)?;
        }
    }

    {
        let mut out_blocklist: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST_V4_ADDRESSES").unwrap())?;

        for addr in v4["output"]["addresses"].as_vec().unwrap().iter() {
            let v4: Ipv4Addr = String::from(addr.as_str().unwrap()).parse()?;
            info!("address: {} added to OUT V4 BLOCKLIST", v4);
            out_blocklist.insert(&v4.into(), 0, 0)?;
        }
    }

    {
        let mut out_blocklist: HashMap<_, u16, u16> =
            HashMap::try_from(ebpf.map_mut("OUT_BLOCKLIST_V4_PORTS").unwrap())?;

        for port in v4["output"]["ports"].as_vec().unwrap().iter() {
            let port: u16 = String::from(port.as_str().unwrap()).parse()?;
            info!("port: {} added to OUT V4 BLOCKLIST", port);
            out_blocklist.insert(&port, 0, 0)?;
        }
    }
    Ok(())
}
