use clap::Parser;
use tokio::fs::read_to_string;
use yaml_rust2::YamlLoader;

pub struct Settings {
    pub http_addr: String,
    pub control_socket_path: String,
    pub http_port: u16,
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

    let settings_struct = Settings {
        http_addr: http["addr"].as_str().unwrap().to_string(),
        http_port: http["port"].as_i64().unwrap() as u16,
        control_socket_path: http["control_socket_path"].as_str().unwrap().to_string(),
    };
    Ok(settings_struct)
}
