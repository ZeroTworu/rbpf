use log::info;
use rbpf_http::http;
use rbpf_http::settings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let settings = settings::read_settings().await?;
    info!("Starting http server...");
    http::api_server(settings).await?;
    info!("Exiting...");
    Ok(())
}
