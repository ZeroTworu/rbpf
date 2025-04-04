use crate::settings::Settings;
use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use poem::middleware::AddData;
use poem::{
    get, handler,
    listener::TcpListener,
    middleware::Cors,
    web::{
        websocket::{Message, WebSocket},
        Data, Path,
    },
    EndpointExt, IntoResponse, Route, Server,
};
use poem_openapi::{payload::Json, OpenApi, OpenApiService};
use rbpf_common::user::LogMessageSerialized;
use rbpf_loader::rules::{Control, ControlAction, RuleWithName};
use serde_json::from_slice;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::Path as FSPath;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::broadcast;

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
            rule: RuleWithName::from_empty(),
        };
        match self.send_command(state, con).await {
            Ok(_) => Json("Reload signal sent".to_string()),
            Err(e) => Json(e.to_string()),
        }
    }

    #[oai(path = "/rules", method = "get")]
    async fn get_rules(&self, state: Data<&ApiState>) -> Json<Vec<RuleWithName>> {
        let con = Control {
            action: ControlAction::GetRules,
            rule: RuleWithName::from_empty(),
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
                    Ok(rules) => Json(rules.into_values().collect::<Vec<RuleWithName>>()),
                    Err(_) => Json(Vec::new()),
                }
            }
            Err(_) => Json(Vec::new()),
        }
    }

    #[oai(path = "/rules", method = "post")]
    async fn create_rule(&self, _state: Data<&ApiState>, rule: Json<RuleWithName>) -> Json<String> {
        println!("Create rule: {:?}", rule);
        Json("Rule successfully created".to_string())
    }

    #[oai(path = "/rules/:id", method = "put")]
    async fn update_rule(
        &self,
        state: Data<&ApiState>,
        _id: Path<u32>,
        rule: Json<RuleWithName>,
    ) -> Json<Vec<RuleWithName>> {
        let wrule: &RuleWithName = rule.deref();
        let con = Control {
            action: ControlAction::UpdateRule,
            rule: wrule.clone(),
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
                    Ok(rules) => Json(rules.into_values().collect::<Vec<RuleWithName>>()),
                    Err(_) => Json(Vec::new()),
                }
            }
            Err(_) => Json(Vec::new()),
        }
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

#[handler]
pub async fn ws_logs(
    ws: WebSocket,
    data: Data<&broadcast::Sender<LogMessageSerialized>>,
) -> impl IntoResponse {
    let mut receiver = data.subscribe();
    ws.on_upgrade(move |socket| async move {
        let (mut sink, _) = socket.split();
        while let Ok(msg) = receiver.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    if let Err(_) = sink.send(Message::Text(json)).await {
                        break;
                    }
                }
                Err(e) => println!("JSON serialization error: {:?}", e),
            }
        }
    })
}

pub async fn logs_server(
    logs_socket_path: &String,
    sender: broadcast::Sender<LogMessageSerialized>,
) -> anyhow::Result<()> {
    if !FSPath::new(logs_socket_path).exists() {
        warn!("Logs socket path {} does not exist", logs_socket_path);
        return Ok(());
    }
    let stream = UnixStream::connect(logs_socket_path).await;

    match stream {
        Ok(mut stream) => {
            info!("Connected to logs server.");
            loop {
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    break Ok(());
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;

                let mut msg_buf = vec![0u8; msg_len];
                if stream.read_exact(&mut msg_buf).await.is_err() {
                    break Ok(());
                }

                let message: LogMessageSerialized = from_slice(&msg_buf)?;
                if message.rule_id != 0 {
                    match sender.send(message) {
                        Ok(_) => {}
                        Err(e) => warn!("Broadcast error: {}", e),
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(e) => {
            error!("Logs server error: {}", e);
            Err(anyhow::Error::msg(e))
        }
    }
}

pub async fn api_server(settings: Settings) -> anyhow::Result<()> {
    let api_service = OpenApiService::new(Api, "ReBPF API", "1.0").server("/api/v1");
    let swagger = api_service.clone().swagger_ui();

    let state = ApiState {
        control_socket_path: settings.control_socket_path.clone(),
    };

    let mut cors = Cors::new()
        .allow_methods(["GET", "POST", "OPTIONS", "PUT", "DELETE"])
        .allow_headers(["Content-Type", "Authorization"]);

    for cor in settings.cors {
        info!("Allow CORS: {:?}", cor);
        cors = cors.allow_origin(cor);
    }

    let mut app = Route::new().nest("/api/v1", api_service);

    if settings.swagger_ui {
        info!("Swagger UI on /docs");
        app = app.nest("/docs", swagger);
    } else {
        info!("Swagger UI off.");
    }

    if settings.listen_logs {
        let tx = broadcast::channel::<LogMessageSerialized>(2048 * 10).0;
        let tx_clone = tx.clone();

        app = app.at("/ws/logs", get(ws_logs.data(tx_clone)));

        tokio::spawn(async move {
            let _ = logs_server(&settings.logs_socket_path, tx).await;
        });

        let app = app.with(AddData::new(state)).with(cors);

        info!(
            "HTTP server started on http://{}:{}",
            &settings.http_addr, &settings.http_port
        );

        Server::new(TcpListener::bind(format!(
            "{}:{}",
            &settings.http_addr, &settings.http_port
        )))
        .run(Arc::new(app))
        .await?;
    } else {
        let app = app.with(cors);

        info!(
            "HTTP server started on http://{}:{}",
            &settings.http_addr, &settings.http_port
        );

        Server::new(TcpListener::bind(format!(
            "{}:{}",
            &settings.http_addr, &settings.http_port
        )))
        .run(Arc::new(app))
        .await?;
    }
    Ok(())
}
