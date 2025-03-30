pub mod v4;
pub mod v6;
use core::cmp::PartialEq;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub source_addr_v6: u128,
    pub destination_addr_v6: u128,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,

    pub source_port_start: u16,
    pub source_port_end: u16,
    pub destination_port_start: u16,
    pub destination_port_end: u16,

    pub input: bool,
    pub output: bool,

    pub source_mask: u8,
    pub destination_mask: u8,
    pub source_mask_v6: u8,
    pub destination_mask_v6: u8,
}

impl Rule {
    pub fn to_action(&self) -> Action {
        if self.drop {
            return Action::Drop;
        }
        if self.ok {
            return Action::Ok;
        }
        Action::Pipe
    }
}

#[derive(PartialEq, Eq)]
pub enum Action {
    Drop = 1,
    Ok = 2,
    Pipe = 3,
}
