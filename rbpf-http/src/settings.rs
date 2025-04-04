use clap::Parser;
use tokio::fs::read_to_string;
use yaml_rust2::YamlLoader;

#[derive(Debug, Clone)]
pub struct Settings {
    pub http_addr: String,
    pub http_port: u16,

    pub control_socket_path: String,
    pub logs_socket_path: String,
    pub listen_logs: bool,
    pub swagger_ui: bool,
    pub cors: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./settings/http.yaml")]
    cfg: String,
}

pub async fn read_settings() -> anyhow::Result<Settings> {
    let opt = Opt::parse();
    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    let http = &settings[0]["http_api"];

    let cors = http["cors"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|cor| cor.as_str().unwrap().to_string())
        .collect::<Vec<String>>();

    let settings_struct = Settings {
        http_addr: http["addr"].as_str().unwrap().to_string(),
        http_port: http["port"].as_i64().unwrap() as u16,
        control_socket_path: http["control_socket_path"].as_str().unwrap().to_string(),
        logs_socket_path: http["logs_socket_path"].as_str().unwrap().to_string(),
        listen_logs: http["listen_logs"].as_bool().unwrap(),
        swagger_ui: http["swagger_ui"].as_bool().unwrap(),
        cors,
    };
    Ok(settings_struct)
}
