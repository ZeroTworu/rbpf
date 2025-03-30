use crate::ip::v6::ParseResultV6;
use crate::rules::{Action, Rule};
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use network_types::ip::IpProto;

const MAX_ENTRIES: u32 = 256;

#[map]
static RULES_IN_V6: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static RULES_OUT_V6: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
pub fn check_rule_v6(pac: &ParseResultV6) -> (Action, u32) {
    for index in 0..=MAX_ENTRIES {
        let rule = if pac.input {
            unsafe { RULES_IN_V6.get(&index) }
        } else {
            unsafe { RULES_OUT_V6.get(&index) }
        };
        match rule {
            Some(rule) => {
                if !rule.v6
                    || (pac.input && !rule.input)
                    || (pac.output && !rule.output)
                    || (rule.tcp && pac.proto != IpProto::Tcp)
                    || (rule.udp && pac.proto != IpProto::Udp)
                {
                    continue;
                }

                let res = match_rule_v6(pac, rule);
                if res == Action::Pipe {
                    continue;
                }
                return (res, rule.rule_id);
            }
            None => return (Action::Ok, 0),
        };
    }
    (Action::Pipe, 0)
}

#[inline(always)]
fn match_rule_v6(pac: &ParseResultV6, rule: &Rule) -> Action {
    let source_match = (rule.source_addr_v6 == 0)
        || (pac.source_addr.to_bits() == rule.source_addr_v6)
        || (rule.source_mask != 0
            && is_ip_in_subnet_v6(
                pac.source_addr.to_bits(),
                rule.source_addr_v6,
                rule.source_mask,
            ));

    let source_port_match = (rule.source_port_start..=rule.source_port_end)
        .contains(&pac.source_port)
        || (rule.source_port_start == 0 && rule.source_port_end == 0);

    let source_not_empty =
        rule.source_addr_v6 != 0 || rule.source_port_start != 0 || rule.source_port_end != 0;

    let destination_match = (rule.destination_addr_v4 == 0)
        || (pac.destination_addr.to_bits() == rule.destination_addr_v6)
        || (rule.destination_mask != 0
            && is_ip_in_subnet_v6(
                pac.destination_addr.to_bits(),
                rule.destination_addr_v6,
                rule.destination_mask,
            ));

    let destination_port_match = (rule.destination_port_start..=rule.destination_port_end)
        .contains(&pac.destination_port)
        || (rule.destination_port_start == 0 && rule.destination_port_end == 0);

    let destination_not_empty = rule.destination_addr_v6 != 0
        || rule.destination_port_start != 0
        || rule.destination_port_end != 0;

    if (source_match && source_port_match && source_not_empty)
        || (destination_match && destination_port_match && destination_not_empty)
    {
        return rule.to_action();
    }

    Action::Pipe
}

#[inline(always)]
fn is_ip_in_subnet_v6(ip: u128, network: u128, prefix_len: u8) -> bool {
    let ip_high = (ip >> 64) as u64;
    let ip_low = ip as u64;
    let net_high = (network >> 64) as u64;
    let net_low = network as u64;

    if prefix_len == 0 {
        return true;
    } else if prefix_len <= 64 {
        let mask = !0u64 << (64 - prefix_len);
        (ip_high & mask) == (net_high & mask)
    } else {
        let mask_low = !0u64 << (128 - prefix_len);
        (ip_high == net_high) && ((ip_low & mask_low) == (net_low & mask_low))
    }
}
