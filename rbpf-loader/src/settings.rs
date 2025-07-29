use crate::database;
use crate::rules;
use aya::Ebpf;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use clap::Parser;
use log::{info, warn};
use tokio::fs::read_to_string;
use tokio::process::Command;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Clone)]
pub struct Settings {
    pub rules_path: String,

    pub control_on: bool,
    pub control_socket_path: String,
    pub control_socket_owner: String,
    pub control_socket_chmod: u32,

    pub logs_on: bool,
    pub logs_socket_path: String,
    pub logs_socket_owner: String,
    pub logs_socket_chmod: u32,

    pub db_on: bool,
    pub db_path: String,

    pub elk_on: bool,
    pub elastic_url: String,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./settings/main.yaml")]
    cfg: String,

    #[clap(short, long, default_value = "./rules/")]
    rules: String,

    #[clap(short, long, default_value = "./migrations/")]
    pub migrations: String,

    #[clap(long)]
    pub fi: bool,

    #[clap(long)]
    pub fo: bool,
}

pub async fn read_settings(ebpf: &mut Ebpf) -> anyhow::Result<Settings> {
    let opt = Opt::parse();

    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    let control = &settings[0]["control"];
    let logs = &settings[0]["logs"];
    let db = &settings[0]["db"];
    let elk = &settings[0]["elk"];

    rules::load_rules_from_dir(&opt.rules).await?;

    let settings_struct = Settings {
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

        db_on: db["on"].as_bool().unwrap(),
        db_path: db["path"].as_str().unwrap().to_string(),

        elk_on: elk["on"].as_bool().unwrap(),
        elastic_url: elk["elastic_host"].as_str().unwrap().to_string(),
    };

    if settings_struct.db_on {
        info!("Database on.");
        database::init_db(&settings_struct.db_path).await?;
        database::migrate(&opt.migrations).await?;
        rules::load_rules_from_db().await?;
    } else {
        info!("Database off.")
    }

    rules::make_bpf_maps(ebpf).await?;
    init_ifaces(settings, ebpf, opt.fi, opt.fo).await?;

    Ok(settings_struct)
}

async fn init_ifaces(
    settings: Vec<Yaml>,
    ebpf: &mut Ebpf,
    fi: bool,
    fo: bool,
) -> anyhow::Result<()> {
    let interfaces = &settings[0]["interfaces"];

    match interfaces["output"].as_vec() {
        Some(interfaces) => {
            let program_egress: &mut SchedClassifier =
                ebpf.program_mut("tc_egress").unwrap().try_into()?;
            program_egress.load()?;
            for iface in interfaces {
                let iface = iface.as_str().unwrap();
                if fo {
                    force_out(iface).await
                }
                let res = program_egress.attach(&iface, TcAttachType::Egress);
                match res {
                    Ok(_) => info!("Append output listener to: {}", iface),
                    Err(e) => warn!("Failed to attach output: {}, iface: {}", e, iface),
                }
            }
        }
        None => warn!("No output interfaces found"),
    }

    match interfaces["input"].as_vec() {
        Some(interfaces) => {
            let program_ingress: &mut Xdp = ebpf.program_mut("xdp_ingress").unwrap().try_into()?;
            program_ingress.load()?;

            for iface in interfaces {
                let iface = iface.as_str().unwrap();

                if fi {
                    force_in(iface).await;
                }

                let res = program_ingress.attach(&iface, XdpFlags::default());
                match res {
                    Ok(_) => info!("Append input listener to: {}", iface),
                    Err(e) => warn!("Failed to attach input: {}, iface: {}", e, iface),
                }
            }
        }
        None => warn!("No input interfaces found"),
    }
    Ok(())
}

async fn force_in(ifname: &str) {
    let res = Command::new("ip")
        .args(["link", "set", "dev", ifname, "xdp", "off"])
        .output()
        .await;
    match res {
        Ok(_) => info!("Force INPUT for {} successful", ifname),
        Err(e) => warn!("Failed to force input for {}: {}", ifname, e),
    }
}

async fn force_out(ifname: &str) {
    let res = Command::new("tc")
        .args(["qdisc", "add", "dev", ifname, "clsact"])
        .output()
        .await;

    match res {
        Ok(_) => info!("Force OUTPUT for {} successful", ifname),
        Err(e) => warn!("Failed to force output: {}, if: {}", e, ifname),
    }
}
