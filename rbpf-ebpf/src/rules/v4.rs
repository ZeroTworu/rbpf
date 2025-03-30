use crate::ip::ParseResult;
use crate::rules::{Action, Rule};
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use network_types::ip::IpProto;

const MAX_ENTRIES: u32 = 32;

#[map]
static RULES_IN_V4: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static RULES_OUT_V4: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
pub fn check_rule_v4(pac: &ParseResult) -> (Action, u32) {
    let rules = if pac.input {
        &RULES_IN_V4
    } else {
        &RULES_OUT_V4
    };
    for index in 0..=MAX_ENTRIES {
        let rule = unsafe { rules.get(&index) };
        match rule {
            Some(rule) => {
                if !rule.v4
                    || (!rule.input && pac.input)
                    || (!rule.output && pac.output)
                    || (!rule.tcp && pac.proto == IpProto::Tcp)
                    || (!rule.udp && pac.proto == IpProto::Udp)
                {
                    return (Action::Ok, 0);
                }
                let res = match_rule_v4(pac, rule);
                if res == Action::Pipe {
                    continue;
                }
                return (res, rule.rule_id);
            }
            None => return (Action::Ok, 0),
        }
    }
    (Action::Pipe, 0)
}

#[inline(always)]
fn match_rule_v4(pac: &ParseResult, rule: &Rule) -> Action {
    let source_match = (rule.source_addr_v4 == 0)
        || (pac.source_addr_v4 == rule.source_addr_v4)
        || (rule.source_mask != 0
            && is_ip_in_subnet_v4(pac.source_addr_v4, rule.source_addr_v4, rule.source_mask));

    let source_not_empty =
        rule.source_addr_v4 != 0 || rule.source_port_start != 0 || rule.source_port_end != 0;

    let destination_match = (rule.destination_addr_v4 == 0)
        || (pac.destination_addr_v4 == rule.destination_addr_v4)
        || (rule.destination_mask != 0
            && is_ip_in_subnet_v4(
                pac.destination_addr_v4,
                rule.destination_addr_v4,
                rule.destination_mask,
            ));

    let destination_not_empty = rule.destination_addr_v4 != 0
        || rule.destination_port_start != 0
        || rule.destination_port_end != 0;

    let in_source_port_range =
        pac.source_port >= rule.source_port_start && pac.source_port <= rule.source_port_end;

    let is_any_source_port = rule.source_port_start == 0 && rule.source_port_end == 0;

    let in_destination_port_range = pac.destination_port >= rule.destination_port_start
        && pac.destination_port <= rule.destination_port_end;

    let is_any_destination_port =
        rule.destination_port_start == 0 && rule.destination_port_end == 0;

    let destination_port_match = in_destination_port_range || is_any_destination_port;
    let source_port_match = in_source_port_range || is_any_source_port;

    if (source_match && source_port_match && source_not_empty)
        || (destination_match && destination_port_match && destination_not_empty)
    {
        return rule.to_action();
    }

    Action::Pipe
}

fn is_ip_in_subnet_v4(ip: u32, network: u32, prefix_len: u8) -> bool {
    let shift = 32 - prefix_len as u32;
    let mask = (!0u32).wrapping_shl(shift);
    (ip & mask) == (network & mask)
}
