use crate::control::Control;
use crate::rules::{get_rules, RuleWithName};
use crate::settings::Settings;
use poem::middleware::AddData;
use poem::web::Data;
use poem::{listener::TcpListener, EndpointExt, Route, Server};
use poem_openapi::{payload::Json, OpenApi, OpenApiService};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Clone)]
struct Api;

#[derive(Clone)]
struct ApiState {
    tx: Arc<Mutex<mpsc::Sender<Control>>>,
    rules_path: String,
}

#[OpenApi]
impl Api {
    #[oai(path = "/rules/reload", method = "post")]
    async fn reload_rules(&self, state: Data<&ApiState>) -> Json<String> {
        let tx = state.tx.lock().await;
        let con = Control {
            reload: true,
            rules_path: state.rules_path.clone(),
        };
        if tx.send(con).await.is_err() {
            return Json("Failed to send reload signal".to_string());
        }
        Json("Reload signal sent".to_string())
    }

    #[oai(path = "/rules", method = "get")]
    async fn get_rules(&self) -> Json<Vec<RuleWithName>> {
        Json(get_rules().await.values().cloned().collect::<Vec<_>>())
    }

    #[oai(path = "/rules", method = "post")]
    async fn create_rule(&self, state: Data<&ApiState>, rule: Json<RuleWithName>) -> Json<String> {
        println!("Create rule: {:?}", rule);
        Json("Rule successfully created".to_string())
    }
}

pub async fn api_server(tx: mpsc::Sender<Control>, settings: Settings) -> anyhow::Result<()> {
    let api_service = OpenApiService::new(Api, "Rules API", "1.0").server("/api");
    let swagger = api_service.clone().swagger_ui();
    let state = ApiState {
        tx: Arc::new(Mutex::new(tx)),
        rules_path: settings.rules_path.clone(),
    };
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/docs", swagger)
        .with(AddData::new(state));

    Server::new(TcpListener::bind(format!(
        "{}:{}",
        &settings.http_addr, &settings.http_port
    )))
    .run(app)
    .await?;
    Ok(())
}
