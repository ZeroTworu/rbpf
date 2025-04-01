use crate::rules::{get_rules, RuleWithName};
use poem::{listener::TcpListener, Route, Server};
use poem_openapi::{payload::Json, OpenApi, OpenApiService};

#[derive(Clone)]
struct Api;

#[OpenApi]
impl Api {
    #[oai(path = "/rules/reload", method = "post")]
    async fn reload_rules(&self) -> Json<String> {
        Json("Reload signal sended".to_string())
    }

    #[oai(path = "/rules", method = "get")]
    async fn get_rules(&self) -> Json<Vec<RuleWithName>> {
        Json(get_rules().await.values().cloned().collect().await)
    }
}

pub async fn api_server() {
    let api_service = OpenApiService::new(Api, "Rules API", "1.0").server("/api");
    let swagger = api_service.clone().swagger_ui();
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/docs", swagger);

    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(app)
        .await
        .unwrap();
}
