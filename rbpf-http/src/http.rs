use crate::settings::Settings;
use futures::{SinkExt, StreamExt};
use log::{info, warn};
use poem::middleware::AddData;
use poem::{
    get, handler,
    listener::TcpListener,
    web::{
        websocket::{Message, WebSocket},
        Data, Html, Path,
    },
    EndpointExt, IntoResponse, Route, Server,
};
use poem_openapi::{payload::Json, OpenApi, OpenApiService};
use rbpf_common::user::{Control, ControlAction, LogMessageSerialized};
use rbpf_loader::rules::RuleWithName;
use serde_json::from_slice;
use std::collections::HashMap;
use std::path::Path as FSPath;
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

pub async fn logs_server(
    logs_socket_path: &String,
    sender: broadcast::Sender<LogMessageSerialized>,
) -> anyhow::Result<()> {
    if !FSPath::new(logs_socket_path).exists() {
        warn!("Logs socket path {} does not exist", logs_socket_path);
        return Ok(());
    }
    let mut stream = UnixStream::connect(logs_socket_path).await?;
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
        if sender.receiver_count() > 0 {
            let _ = sender.send(message);
        }
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
            if let Err(e) = sink.send(Message::Text(serde_json::to_string(&msg).unwrap())).await {
                println!("ERR WS closed connection.3: {:?}", e);
                break;
            }
        }
        println!("WS closed connection.4");
    })
}

#[handler]
fn index() -> Html<&'static str> {
    Html(
        r###"
    <body>
        <form id="loginForm">
            Name: <input id="nameInput" type="text" />
            <button type="submit">Login</button>
        </form>

        <form id="sendForm" hidden>
            Text: <input id="msgInput" type="text" />
            <button type="submit">Send</button>
        </form>

        <textarea id="msgsArea" cols="50" rows="30" hidden></textarea>
    </body>
    <script>
        let ws;
        const loginForm = document.querySelector("#loginForm");
        const sendForm = document.querySelector("#sendForm");
        const nameInput = document.querySelector("#nameInput");
        const msgInput = document.querySelector("#msgInput");
        const msgsArea = document.querySelector("#msgsArea");

        nameInput.focus();

        loginForm.addEventListener("submit", function(event) {
            event.preventDefault();
            loginForm.hidden = true;
            sendForm.hidden = false;
            msgsArea.hidden = false;
            msgInput.focus();
            ws = new WebSocket("ws://127.0.0.1:8080/ws");
            ws.onmessage = function(event) {
                msgsArea.value += event.data + "\r\n";
            }
        });

        sendForm.addEventListener("submit", function(event) {
            event.preventDefault();
            ws.send(msgInput.value);
            msgInput.value = "";
        });

    </script>
    "###,
    )
}

pub async fn api_server(settings: Settings) -> anyhow::Result<()> {
    let api_service = OpenApiService::new(Api, "ReBPF API", "1.0").server("/api");
    let swagger = api_service.clone().swagger_ui();
    let state = ApiState {
        control_socket_path: settings.control_socket_path.clone(),
    };
    let tx = broadcast::channel::<LogMessageSerialized>(100).0;
    let tx_clone = tx.clone();
    let app = Route::new()
        .nest("/api", api_service)
        .nest("/docs", swagger)
        .at("/ws", get(ws_logs.data(tx_clone)))
        .at("/", get(index))
        .with(AddData::new(state));

    tokio::spawn(async move {
        let _ = logs_server(&settings.logs_socket_path, tx).await;
    });

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
