use crate::settings::Settings;
use log::{info, warn};
use poem::middleware::AddData;
use poem::web::Data;
use poem::{listener::TcpListener, EndpointExt, Route, Server};
use poem_openapi::{param::Path, payload::Json, OpenApi, OpenApiService};
use rbpf_common::user::{Control, ControlAction, LogMessageSerialized};
use rbpf_loader::rules::RuleWithName;
use serde_json::from_slice;
use std::collections::HashMap;
use std::path::Path as FSPath;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Clone)]
struct Api;

#[derive(Clone)]
struct ApiState {
    control_socket_path: String,
}

#[OpenApi]
impl Api {
    #[oai(path = "/rules/reload", method = "post")]
    async fn reload_rules(&self, state: Data<&ApiState>) -> Json<String> {
        let con = Control {
            action: ControlAction::Reload,
        };
        match self.send_command(state, con).await {
            Ok(_) => Json("Reload signal sent".to_string()),
            Err(e) => Json(e.to_string()),
        }
    }

    #[oai(path = "/rules", method = "get")]
    async fn get_rules(&self, state: Data<&ApiState>) -> Json<HashMap<u32, RuleWithName>> {
        let con = Control {
            action: ControlAction::GetRules,
        };
        match self.send_command(state, con).await {
            Ok(mut socket) => {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];

                while let Ok(n) = socket.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                }

                match from_slice::<HashMap<u32, RuleWithName>>(&buffer) {
                    Ok(rules) => Json(rules),
                    Err(_) => Json(HashMap::new()),
                }
            }
            Err(_) => Json(HashMap::new()),
        }
    }

    #[oai(path = "/rules", method = "post")]
    async fn create_rule(&self, _state: Data<&ApiState>, rule: Json<RuleWithName>) -> Json<String> {
        println!("Create rule: {:?}", rule);
        Json("Rule successfully created".to_string())
    }

    #[oai(path = "/rules/:id", method = "put")]
    async fn update_rule(&self, id: Path<u32>, rule: Json<RuleWithName>) -> Json<String> {
        println!("Create rule: {:?} {}", rule, id.to_be());
        Json("Rule successfully updated".to_string())
    }

    async fn send_command(
        &self,
        state: Data<&ApiState>,
        command: Control,
    ) -> anyhow::Result<UnixStream> {
        let mut stream = UnixStream::connect(&state.control_socket_path).await?;
        let serialized = serde_json::to_vec(&command)?;
        stream.write_all(&serialized).await?;
        Ok(stream)
    }
}

pub async fn logs_server(settings: Settings) -> anyhow::Result<()> {
    if !FSPath::new(&settings.logs_socket_path).exists() {
        warn!(
            "Logs socket path {} does not exist",
            settings.logs_socket_path
        );
        return Ok(());
    }
    let mut stream = UnixStream::connect(settings.logs_socket_path).await?;
    info!("Connected to logs server.");

    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            warn!("Server closed connection.1");
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut msg_buf).await.is_err() {
            warn!("Server closed connection.2");
        }

        let message: LogMessageSerialized = from_slice(&msg_buf)?;

    }
}

pub async fn api_server(settings: Settings) -> anyhow::Result<()> {
    let api_service = OpenApiService::new(Api, "ReBPF API", "1.0").server("/api");
    let swagger = api_service.clone().swagger_ui();
    let state = ApiState {
        control_socket_path: settings.control_socket_path.clone(),
    };
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/docs", swagger)
        .with(AddData::new(state));
    info!(
        "HTTP server started on http://{}:{}",
        &settings.http_addr, &settings.http_port
    );
    Server::new(TcpListener::bind(format!(
        "{}:{}",
        &settings.http_addr, &settings.http_port
    )))
    .run(app)
    .await?;
    Ok(())
}
