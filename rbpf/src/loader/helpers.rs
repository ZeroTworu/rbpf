use aya::maps::HashMap;
use aya::maps::MapData;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use yaml_rust2::Yaml;

pub fn ports_maker(
    blocklist: &mut HashMap<&mut MapData, u16, u16>,
    port: &Yaml,
) -> anyhow::Result<()> {
    match port.as_str() {
        Some(port) => {
            if port.contains("-") {
                let parts = port.split("-").collect::<Vec<&str>>();
                let start: u16 = parts[0].parse()?;
                let end: u16 = parts[1].parse()?;
                for port in start..end {
                    blocklist.insert(port, 0, 0)?
                }
                return Ok(());
            }
            let uport: u16 = String::from(port).parse::<u16>()?;
            blocklist.insert(uport, 0, 0)?;
            Ok(())
        }
        None => Ok(()),
    }
}

pub fn v4_addresses_maker(
    blocklist: &mut HashMap<&mut MapData, u32, u32>,
    address: &Yaml,
) -> anyhow::Result<()> {
    match address.as_str() {
        Some(addr) => {
            if !addr.contains("/") {
                let v4: Ipv4Addr = String::from(addr).parse()?;
                blocklist.insert(&v4.into(), 0, 0)?;
                return Ok(());
            }
            let net: Ipv4Net = addr.parse()?;
            for addr in net.hosts().collect::<Vec<Ipv4Addr>>() {
                blocklist.insert(&addr.into(), 0, 0)?;
            }
            Ok(())
        }
        None => Ok(()),
    }
}
