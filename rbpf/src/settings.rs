use crate::rules;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
use log::{info, warn};
use tokio::fs::read_to_string;
use yaml_rust2::YamlLoader;

pub struct Settings {
    pub http_api_on: bool,
    pub resolve_ptr_records: bool,
    pub http_addr: String,
    pub http_port: u16,
    pub rules_path: String,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./settings.yaml")]
    cfg: String,
    #[clap(short, long, default_value = "./rules/")]
    rules: String,
}

pub async fn read_settings(ebpf: &mut Ebpf) -> anyhow::Result<Settings> {
    let opt = Opt::parse();

    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    rules::load_rules(&opt.rules, ebpf).await?;
    let http = &settings[0]["http_api"];

    let settings_struct = Settings {
        http_api_on: http["on"].as_bool().unwrap(),
        http_addr: http["addr"].as_str().unwrap().to_string(),
        http_port: http["port"].as_i64().unwrap() as u16,
        resolve_ptr_records: (&settings[0])["resolve_ptr_records"].as_bool().unwrap(),
        rules_path: opt.rules,
    };

    // TODO: Придумать как это красиво убрать в отдельный лоадер
    let interfaces = &settings[0]["interfaces"];

    match interfaces["output"].as_vec() {
        Some(interfaces) => {
            let program_egress: &mut SchedClassifier =
                ebpf.program_mut("tc_egress").unwrap().try_into()?;
            program_egress.load()?;
            for iface in interfaces {
                let iface = iface.as_str().unwrap();
                program_egress.attach(&iface, TcAttachType::Egress)?;
                info!("Append output listener to: {}", iface);
            }
        }
        None => warn!("No output interfaces found"),
    }

    match interfaces["input"].as_vec() {
        Some(interfaces) => {
            let program_ingress: &mut Xdp = ebpf.program_mut("tc_ingress").unwrap().try_into()?;
            program_ingress.load()?;

            for iface in interfaces {
                let iface = iface.as_str().unwrap();
                program_ingress.attach(&iface, XdpFlags::default())?;
                info!("Append input listener to: {}", iface);
            }
        }
        None => warn!("No input interfaces found"),
    }

    Ok(settings_struct)
}
