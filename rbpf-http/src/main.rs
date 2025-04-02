use log::info;
use rbpf_http::http;
use rbpf_http::settings;
use tokio::task;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let settings = settings::read_settings().await?;
    info!("Starting http server...");
    task::spawn(http::api_server(settings.clone()));
    task::spawn(http::logs_server(settings.clone()));
    loop {}
}
