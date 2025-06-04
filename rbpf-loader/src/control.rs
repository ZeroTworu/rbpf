use crate::database;
use crate::rules;
use crate::settings::Settings;
use aya::Ebpf;
use log::info;
use rbpf_common::rules::rules::{Control, ControlAction};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

pub fn change_socket_owner_mode(
    socket_path: &str,
    username: &str,
    chmod: u32,
) -> std::io::Result<()> {
    let user = nix::unistd::User::from_name(username)?.expect("User not found");

    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();
    let mode: libc::mode_t = libc::mode_t::from_le(chmod);

    let c_socket_path = std::ffi::CString::new(socket_path)?;

    unsafe {
        if libc::chown(c_socket_path.as_ptr(), uid, gid) != 0 {
            eprintln!("Cannot chown: {}", std::io::Error::last_os_error());
        }
        if libc::chmod(c_socket_path.as_ptr(), mode) != 0 {
            eprintln!("Cannot chmod: {}", std::io::Error::last_os_error());
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
    change_socket_owner_mode(
        &settings.control_socket_path,
        &settings.control_socket_owner,
        settings.control_socket_chmod,
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
                        rules::load_rules_from_dir(&settings.rules_path, ebpf).await?;
                    }
                    ControlAction::GetRules => {
                        let rules = rules::get_rules().await;
                        let json_data = serde_json::to_vec(&rules)?;
                        socket.write_all(&json_data).await?;
                    }
                    ControlAction::UpdateRule => {
                        rules::change_rule(control.rule.clone()).await;
                        rules::reload_rules(ebpf).await?;
                        let rules = rules::get_rules().await;
                        let json_data = serde_json::to_vec(&rules)?;
                        socket.write_all(&json_data).await?;
                      }
                    ControlAction::CreateRule => {
                        let mut new_rule = control.rule.clone();
                        new_rule.uindex = rules::get_rules_len().await;
                        let rule_id = u32::try_from(database::insert_rule(&new_rule).await)?;
                        if rule_id != 0 {
                            new_rule.rule_id = rule_id;
                            rules::set_rule(new_rule.clone()).await;
                            rules::reload_rules(ebpf).await?;
                            let rules = rules::get_rules().await;
                            let json_data = serde_json::to_vec(&rules)?;
                            socket.write_all(&json_data).await?;
                        }
                        socket.flush().await?;
                    }
                }
            }
            _ => {}
        }
    }
}
