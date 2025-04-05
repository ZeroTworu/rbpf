use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use poem::web::websocket::{Message, WebSocket};
use poem::web::Data;
use poem::{handler, IntoResponse};
use rbpf_common::logs::logs::LogMessageSerialized;
use serde_json::from_slice;
use std::path::Path as FSPath;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};

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
    loop {
        match UnixStream::connect(logs_socket_path).await {
            Ok(mut stream) => {
                info!("Connected to logs server.");
                loop {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        warn!("Connection closed while reading length. Reconnecting...");
                        break;
                    }

                    let msg_len = u32::from_be_bytes(len_buf) as usize;
                    let mut msg_buf = vec![0u8; msg_len];

                    if stream.read_exact(&mut msg_buf).await.is_err() {
                        warn!("Connection closed while reading message. Reconnecting...");
                        break;
                    }

                    match from_slice::<LogMessageSerialized>(&msg_buf) {
                        Ok(message) if message.rule_id != 0 => {
                            if let Err(e) = sender.send(message) {
                                warn!("Broadcast error: {}", e);
                            }
                            sleep(Duration::from_millis(100)).await;
                        }
                        Ok(_) => {}
                        Err(e) => warn!("Failed to deserialize message: {}", e),
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to connect to logs server: {}. Retrying in 5 seconds...",
                    e
                );
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
