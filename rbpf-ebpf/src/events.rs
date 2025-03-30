use crate::rules::Rule;
use aya_ebpf::{macros::map, maps::HashMap};
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LogMessage {
    pub message: [u8; 128],
    pub level: u8,
    pub rule_id: u32,
    pub by_rule: bool,
}

impl LogMessage {
    pub fn send(message: &str) -> Self {
        let msg = Self {
            message: Self::str_to_u8(message),
            rule_id: 0,
            level: 0,
            by_rule: false,
        };
        send_log(&msg);
        msg
    }

    pub fn send_from_rule(message: &str, rule_id: u32) -> Self {
        let msg = Self {
            message: Self::str_to_u8(message),
            rule_id,
            level: 0,
            by_rule: true,
        };
        send_log(&msg);
        msg
    }

    fn str_to_u8(msg: &str) -> [u8; 128] {
        let mut message = [0u8; 128];
        message[..msg.len()].copy_from_slice(msg.as_bytes());
        message
    }
}

#[map]
static mut EVENTS: HashMap<u32, LogMessage> = HashMap::with_max_entries(65535, 0);

pub fn send_log(msg: &LogMessage) -> i32 {
    let i: &u32 = &0;
    unsafe {
        if EVENTS.insert(&i, msg, 0).is_err() {
            return 1;
        }
        0
    }
}
