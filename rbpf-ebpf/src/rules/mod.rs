pub mod rule;

use core::cmp::PartialEq;
use rbpf_common::Rule;

pub struct WRule {
    pub rule: &'static Rule,
}

impl WRule {
    pub fn to_action(&self) -> Action {
        if self.rule.drop {
            return Action::Drop;
        }
        if self.rule.ok {
            return Action::Ok;
        }
        Action::Pipe
    }
    pub fn is_source_v4_not_empty(&self) -> bool {
        self.rule.source_addr_v4 != 0
            || self.rule.source_port_start != 0
            || self.rule.source_port_end != 0
    }
    pub fn is_source_v6_not_empty(&self) -> bool {
        self.rule.source_addr_v6 != 0
            || self.rule.source_port_start != 0
            || self.rule.source_port_end != 0
    }
    pub fn is_destination_v4_not_empty(&self) -> bool {
        self.rule.destination_addr_v4 != 0
            || self.rule.destination_port_start != 0
            || self.rule.destination_port_end != 0
    }
    pub fn is_destination_v6_not_empty(&self) -> bool {
        self.rule.destination_addr_v6 != 0
            || self.rule.destination_port_start != 0
            || self.rule.destination_port_end != 0
    }
}

#[derive(PartialEq, Eq)]
pub enum Action {
    Drop = 1,
    Ok = 2,
    Pipe = 3,
}
