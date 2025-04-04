use crate::rules;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
use log::{info, warn};
use tokio::fs::read_to_string;
use yaml_rust2::YamlLoader;

#[derive(Debug, Clone)]
pub struct Settings {
    pub resolve_ptr_records: bool,
    pub rules_path: String,

    pub control_on: bool,
    pub control_socket_path: String,
    pub control_socket_owner: String,
    pub control_socket_chmod: u32,

    pub logs_on: bool,
    pub logs_socket_path: String,
    pub logs_socket_owner: String,
    pub logs_socket_chmod: u32,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./settings/main.yaml")]
    cfg: String,
    #[clap(short, long, default_value = "./rules/")]
    rules: String,
}

pub async fn read_settings(ebpf: &mut Ebpf) -> anyhow::Result<Settings> {
    let opt = Opt::parse();

    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    rules::load_rules(&opt.rules, ebpf).await?;
    let control = &settings[0]["control"];
    let logs = &settings[0]["logs"];

    let settings_struct = Settings {
        resolve_ptr_records: (&settings[0])["resolve_ptr_records"].as_bool().unwrap(),
        rules_path: opt.rules,
        control_socket_path: control["control_socket_path"].as_str().unwrap().to_string(),
        control_socket_owner: control["control_socket_owner"]
            .as_str()
            .unwrap()
            .to_string(),
        control_on: control["on"].as_bool().unwrap(),
        control_socket_chmod: control["control_socket_chmod"].as_i64().unwrap() as u32,

        logs_on: logs["on"].as_bool().unwrap(),
        logs_socket_path: logs["logs_socket_path"].as_str().unwrap().to_string(),
        logs_socket_owner: logs["logs_socket_owner"].as_str().unwrap().to_string(),
        logs_socket_chmod: logs["logs_socket_chmod"].as_i64().unwrap() as u32,
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
