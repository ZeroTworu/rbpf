use aya::maps::HashMap;
use aya::maps::MapData;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
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
        // Понятно, что не размно пологаться просто на наличие "/" или ":" в строке.
        // Но т.к. Предпологается, что настройки заполняет квалифицированный человек
        // Который не будет сознательно вредить - делаем так.
        Some(addr) => {
            // Обрабатываем подсеть
            // Запись вида: 127.0.0.0/24
            if addr.contains("/") {
                let net: Ipv4Net = addr.parse()?;
                for addr in net.hosts() {
                    blocklist.insert(&addr.into(), 0, 0)?;
                }
                return Ok(());
            }
            // Обычный адрес IPv4
            // Запись вида: 127.0.0.1
            let v4: Ipv4Addr = String::from(addr).parse()?;
            blocklist.insert(&v4.to_bits(), 0, 0)?;
            Ok(())
        }
        None => Ok(()),
    }
}

pub fn v6_addresses_maker(
    blocklist: &mut HashMap<&mut MapData, u128, u128>,
    address: &Yaml,
) -> anyhow::Result<()> {
    match address.as_str() {
        // Понятно, что не размно пологаться просто на наличие "/" или ":" в строке.
        // Но т.к. Предпологается, что настройки заполняет квалифицированный человек
        // Который не будет сознательно вредить - делаем так.
        Some(addr) => {
            if addr.contains("/") {
                // Обрабатываем подсеть
                // Запись вида: ::1/24
                let net: Ipv6Net = addr.parse()?;
                for addr in net.hosts() {
                    blocklist.insert(&addr.to_bits(), 0, 0)?;
                }

                return Ok(());
            }
            // Обычный адрес IPv6
            // Запись вида: ::1
            let v6: Ipv6Addr = String::from(addr).parse()?;
            blocklist.insert(&v6.to_bits(), 0, 0)?;
            Ok(())
        }
        None => Ok(()),
    }
}
