use crate::ip::v4::ParseResultV4;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{debug, info, warn};
use core::cmp::PartialEq;
use core::num::NonZeroUsize;
use core::str::from_utf8;
use network_types::ip::IpProto;

const MAX_ENTRIES: u32 = 32;

#[map]
static RULES: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

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
}

trait RuleCheck {
    fn check(&self, rule: &Rule) -> Action;
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

#[inline(always)]
pub fn check_rule_v4(pac: &ParseResultV4) -> (Action, u32) {
    for index in 0..MAX_ENTRIES {
        let rule = unsafe { RULES.get(&index) };
        match rule {
            Some(rule) => {
                if !rule.v4 || (pac.input && !rule.input) || (pac.output && !rule.output) {
                    continue;
                }

                let is_tcp = rule.tcp && pac.proto == IpProto::Tcp;
                let is_udp = rule.udp && pac.proto == IpProto::Udp;
                if is_tcp || is_udp {
                    let res = match_rule(pac, rule);
                    if res == Action::Pipe {
                        continue;
                    }
                    return (res, rule.rule_id);
                }
            }
            None => return (Action::Ok, 0),
        };
    }
    (Action::Pipe, 0)
}

#[inline(always)]
fn match_rule(pac: &ParseResultV4, rule: &Rule) -> Action {
    let full_s_match = (pac.source_addr == rule.source_addr_v4)
        && (rule.source_port_start..rule.source_port_end).contains(&pac.source_port);
    let full_d_match = (pac.destination_addr == rule.destination_addr_v4)
        && (rule.destination_port_start..rule.destination_port_end).contains(&pac.destination_port);

    let addr_d_match = pac.destination_addr == rule.destination_addr_v4;
    let addr_s_match = pac.source_addr == rule.source_addr_v4;

    let port_s_match = (rule.source_port_start..rule.source_port_end).contains(&pac.source_port);
    let port_d_match =
        (rule.destination_port_start..rule.destination_port_end).contains(&pac.destination_port);

    if full_s_match || full_d_match || addr_d_match || addr_s_match || port_s_match || port_d_match
    {
        return rule.to_action();
    }
    Action::Pipe
}
