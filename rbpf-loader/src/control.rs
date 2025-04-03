use crate::rules;
use crate::rules::{Control, ControlAction};
use crate::settings::Settings;
use aya::Ebpf;
use log::info;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

pub fn change_socket_owner(socket_path: &str, username: &str) -> std::io::Result<()> {
    let user = nix::unistd::User::from_name(username)?.expect("User not found");

    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();

    let c_socket_path = std::ffi::CString::new(socket_path).unwrap();

    unsafe {
        if libc::chown(c_socket_path.as_ptr(), uid, gid) != 0 {
            println!("change socket owner for {} to {}", socket_path, username);
            eprintln!("Cannot chown: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

pub async fn control_loop(settings: Arc<Settings>, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    info!("Starting control loop...");
    if Path::new(&settings.control_socket_path).exists() {
        fs::remove_file(&settings.control_socket_path)?;
    }

    let control_listener = UnixListener::bind(&settings.control_socket_path)?;
    info!("Control socket on {}", &settings.control_socket_path);
    change_socket_owner(
        &settings.control_socket_path,
        &settings.control_socket_owner,
    )?;

    loop {
        let (mut socket, _) = control_listener.accept().await?;

        let mut buffer = vec![0; 1024];
        match socket.read(&mut buffer).await {
            Ok(n) if n > 0 => {
                let received_data = &buffer[..n];
                let control = serde_json::from_slice::<Control>(received_data)?;
                match control.action {
                    ControlAction::Reload => {
                        rules::load_rules(&settings.rules_path, ebpf).await?;
                        socket.flush().await?;
                    }
                    ControlAction::GetRules => {
                        let rules = rules::get_rules().await;
                        let json_data = serde_json::to_vec(&rules)?;
                        socket.write_all(&json_data).await?;
                        socket.flush().await?;
                    }
                    ControlAction::UpdateRule => {
                        rules::change_rule(control.rule.rule_id, control.rule).await;
                        rules::reload_rules(ebpf).await?;
                        let rules = rules::get_rules().await;
                        let json_data = serde_json::to_vec(&rules)?;
                        socket.write_all(&json_data).await?;
                        socket.flush().await?;
                    }
                }
            }
            _ => {}
        }
    }
}
