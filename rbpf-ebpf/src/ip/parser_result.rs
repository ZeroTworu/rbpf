use network_types::ip::IpProto;
use rbpf_common::rules::{Action, Rule};

pub struct ParseResult {
    pub source_port: u16,
    pub destination_port: u16,

    pub destination_addr_v4: u32,
    pub source_addr_v4: u32,

    pub destination_addr_v6: u128,
    pub source_addr_v6: u128,

    pub proto: IpProto,

    pub input: bool,
    pub output: bool,

    pub v4: bool,
    pub ifindex: u32,
}

impl ParseResult {
    pub fn is_tcp(&self) -> bool {
        self.proto == IpProto::Tcp
    }
    pub fn is_udp(&self) -> bool {
        self.proto == IpProto::Udp
    }

    pub fn is_source_port(&self, rule: &Rule) -> bool {
        let in_source_port_range =
            self.source_port >= rule.source_port_start && self.source_port <= rule.source_port_end;

        let is_any_source_port = rule.source_port_start == 0 && rule.source_port_end == 0;
        is_any_source_port || in_source_port_range
    }

    pub fn is_destination_port(&self, rule: &Rule) -> bool {
        let in_destination_port_range = self.destination_port >= rule.destination_port_start
            && self.destination_port <= rule.destination_port_end;

        let is_any_destination_port =
            rule.destination_port_start == 0 && rule.destination_port_end == 0;

        in_destination_port_range || is_any_destination_port
    }

    pub fn is_source_v4_addr(&self, rule: &Rule) -> bool {
        (rule.source_addr_v4 == 0)
            || ((self.source_addr_v4 == rule.source_addr_v4)
                || (rule.source_mask_v4 != 0
                    && is_ip_in_subnet_v4(
                        self.source_addr_v4,
                        rule.source_addr_v4,
                        rule.source_mask_v4,
                    )))
    }

    pub fn is_source_v6_addr(&self, rule: &Rule) -> bool {
        (rule.source_addr_v6 == 0)
            || ((self.source_addr_v6 == rule.source_addr_v6)
                || (rule.source_mask_v6 != 0
                    && is_ip_in_subnet_v6(
                        self.source_addr_v6,
                        rule.source_addr_v6,
                        rule.source_mask_v6,
                    )))
    }

    pub fn is_destination_v4_addr(&self, rule: &Rule) -> bool {
        (rule.destination_addr_v4 == 0)
            || ((self.destination_addr_v4 == rule.destination_addr_v4)
                || (rule.destination_mask_v4 != 0
                    && is_ip_in_subnet_v4(
                        self.destination_addr_v4,
                        rule.destination_addr_v4,
                        rule.destination_mask_v4,
                    )))
    }

    pub fn is_destination_v6_addr(&self, rule: &Rule) -> bool {
        (rule.destination_addr_v6 == 0)
            || ((self.destination_addr_v6 == rule.destination_addr_v6)
                || (rule.destination_mask_v4 != 0
                    && is_ip_in_subnet_v6(
                        self.destination_addr_v6,
                        rule.destination_addr_v6,
                        rule.destination_mask_v6,
                    )))
    }

    pub fn to_action(&self, rule: &Rule) -> Action {
        if rule.ifindex != 0 && self.ifindex != rule.ifindex {
            return Action::Pipe;
        }

        if self.v4 && rule.v4 {
            if self.input
                && self.is_source_v4_addr(rule)
                && self.is_source_port(rule)
                && rule.is_source_v4_not_empty()
            {
                return rule.to_action();
            }
            if self.output
                && self.is_destination_v4_addr(rule)
                && self.is_destination_port(rule)
                && rule.is_destination_v4_not_empty()
            {
                return rule.to_action();
            }
        }

        if !self.v4 && rule.v6 {
            if self.input
                && self.is_source_v6_addr(rule)
                && self.is_source_port(rule)
                && rule.is_source_v6_not_empty()
            {
                return rule.to_action();
            }
            if self.output
                && self.is_destination_v6_addr(rule)
                && self.is_destination_port(rule)
                && rule.is_destination_v6_not_empty()
            {
                return rule.to_action();
            }
        }
        Action::Pipe
    }

    #[inline(always)]
    pub fn not_my_rule(&self, rule: &Rule) -> bool {
        if !rule.on {
            return true;
        }
        if self.v4 && !rule.v4 {
            return true;
        }
        if !self.v4 && !rule.v6 {
            return true;
        }
        if self.input && !rule.input {
            return true;
        }
        if self.output && !rule.output {
            return true;
        }
        if (self.proto == IpProto::Tcp) && !rule.tcp {
            return true;
        }
        if (self.proto == IpProto::Udp) && !rule.udp {
            return true;
        }
        false
    }
}

#[inline(always)]
fn is_ip_in_subnet_v4(ip: u32, network: u32, prefix_len: u8) -> bool {
    let shift = 32 - prefix_len as u32;
    let mask = (!0u32).wrapping_shl(shift);
    (ip & mask) == (network & mask)
}

#[inline(always)]
fn is_ip_in_subnet_v6(ip: u128, network: u128, prefix_len: u8) -> bool {
    let ip_high = (ip >> 64) as u64;
    let ip_low = ip as u64;
    let net_high = (network >> 64) as u64;
    let net_low = network as u64;

    if prefix_len == 0 {
        true
    } else if prefix_len <= 64 {
        let mask = !0u64 << (64 - prefix_len);
        (ip_high & mask) == (net_high & mask)
    } else {
        let mask_low = !0u64 << (128 - prefix_len);
        (ip_high == net_high) && ((ip_low & mask_low) == (net_low & mask_low))
    }
}
