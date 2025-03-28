use aya::maps::HashMap;
use aya::maps::MapData;
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
