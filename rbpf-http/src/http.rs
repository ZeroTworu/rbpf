use crate::settings::Settings;
use crate::websocket;
use log::info;
use poem::middleware::AddData;
use poem::{
    get,
    listener::TcpListener,
    middleware::Cors,
    web::{Data, Path},
    EndpointExt, Route, Server,
    endpoint::StaticFilesEndpoint,
};
use poem_openapi::{payload::Json, OpenApi, OpenApiService};
use rbpf_common::logs::logs::LogMessageSerialized;
use rbpf_common::rules::rules::{Control, ControlAction, RuleWithName};
use serde_json::from_slice;
use std::collections::HashMap;
use std::ops::Deref;
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
        self.send_and_read(state, con).await
    }

    #[oai(path = "/rules", method = "post")]
    async fn create_rule(
        &self,
        state: Data<&ApiState>,
        rule: Json<RuleWithName>,
    ) -> Json<Vec<RuleWithName>> {
        let wrule: &RuleWithName = rule.deref();
        let con = Control {
            action: ControlAction::CreateRule,
            rule: wrule.clone(),
        };
        self.send_and_read(state, con).await
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
        self.send_and_read(state, con).await
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

    async fn send_and_read(
        &self,
        state: Data<&ApiState>,
        command: Control,
    ) -> Json<Vec<RuleWithName>> {
        match self.send_command(state, command).await {
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
}

pub async fn http_ws_server(settings: Settings) -> anyhow::Result<()> {
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

    let vue_root = settings.vue_dist_path.clone();
    info!("Serving static frontend from: {}", vue_root);

    if settings.vue_app_on {
        app = app.nest_no_strip("/", StaticFilesEndpoint::new(vue_root.clone()).index_file("index.html"));
    }

    if settings.swagger_ui {
        info!("Swagger UI on /docs");
        app = app.nest("/docs", swagger);
    } else {
        info!("Swagger UI off.");
    }

    if settings.listen_logs {
        let tx = broadcast::channel::<LogMessageSerialized>(2048 * 10).0;
        let tx_clone = tx.clone();

        app = app.at("/ws/logs", get(websocket::ws_logs.data(tx_clone)));

        tokio::spawn(async move {
            let _ = websocket::logs_server(&settings.logs_socket_path, tx).await;
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
