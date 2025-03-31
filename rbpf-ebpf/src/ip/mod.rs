pub mod v4;
pub mod v6;

use crate::rules::{Action, Rule};
use aya_ebpf::programs::{TcContext, XdpContext};
use core::net::Ipv6Addr;
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use crate::ip::v4::{handle_egress_v4, handle_ingress_v4};
use crate::ip::v6::{handle_egress_v6, handle_ingress_v6};

#[inline(always)]
pub fn ptr_at_u<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

pub struct ContextWrapper {
    pub data: usize,
    pub data_end: usize,
    pub ifindex: u32,
}

impl ContextWrapper {
    #[inline(always)]
    pub fn from_xdp(ctx: &XdpContext) -> Self {
        let ifindex: u32 = unsafe { (*ctx.ctx).ingress_ifindex };
        Self::from_usize(ctx.data(), ctx.data_end(), ifindex)
    }
    #[inline(always)]
    pub fn from_tc(ctx: &TcContext) -> Self {
        let ifindex: u32 = unsafe { (*ctx.skb.skb).ifindex };
        Self::from_usize(ctx.data(), ctx.data_end(), ifindex)
    }

    #[inline(always)]
    pub fn from_usize(data: usize, data_end: usize, ifindex: u32) -> Self {
        Self {
            data,
            data_end,
            ifindex,
        }
    }

    pub fn to_parse_result(&self, v4: bool, input: bool) -> Result<ParseResult, ()> {
        let (proto, destination_addr_v4, source_addr_v4, destination_addr_v6, source_addr_v6) =
            if v4 {
                let ipv4hdr: Ipv4Hdr = unsafe { *ptr_at_u(self.data, self.data_end, EthHdr::LEN)? };
                (
                    ipv4hdr.proto,
                    u32::from_be(ipv4hdr.dst_addr),
                    u32::from_be(ipv4hdr.src_addr),
                    0u128,
                    0u128,
                )
            } else {
                let ipv6hdr: Ipv6Hdr = unsafe { *ptr_at_u(self.data, self.data_end, EthHdr::LEN)? };

                (
                    ipv6hdr.next_hdr,
                    0u32,
                    0u32,
                    Ipv6Addr::from(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }).to_bits(),
                    Ipv6Addr::from(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }).to_bits(),
                )
            };

        let len = if v4 { Ipv4Hdr::LEN } else { Ipv6Hdr::LEN };

        let (source_port, destination_port) = match proto {
            IpProto::Tcp => {
                let tcphdr: TcpHdr =
                    unsafe { *ptr_at_u(self.data, self.data_end, EthHdr::LEN + len)? };
                (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
            }
            IpProto::Udp => {
                let udphdr: UdpHdr =
                    unsafe { *ptr_at_u(self.data, self.data_end, EthHdr::LEN + len)? };
                (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
            }
            _ => return Err(()),
        };

        Ok(ParseResult {
            source_port,
            destination_port,
            source_addr_v4,
            destination_addr_v4,
            proto,
            input,
            destination_addr_v6,
            source_addr_v6,
            output: !input,
            v4,
            v6: !v4,
            ifindex: self.ifindex,
        })
    }

    pub fn handle_as_tc(&self) ->  Result<i32, ()> {
        let ethhdr: EthHdr = unsafe { *ptr_at_u(self.data, self.data_end, 0)? };
        match ethhdr.ether_type {
            EtherType::Ipv4 => handle_egress_v4(&self),
            EtherType::Ipv6 => handle_egress_v6(&self),
            _ => Ok(TC_ACT_PIPE),
        }
    }
    pub fn handle_as_xdp(&self) -> Result<u32, ()> {
        let ethhdr: EthHdr = unsafe { *ptr_at_u(self.data, self.data_end, 0)? };

        match ethhdr.ether_type {
            EtherType::Ipv4 => handle_ingress_v4(&self),
            EtherType::Ipv6 => handle_ingress_v6(&self),
            _ => Ok(xdp_action::XDP_PASS),
        }
    }
}

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
    pub v6: bool,
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
                || (rule.source_mask != 0
                    && is_ip_in_subnet_v4(
                        self.source_addr_v4,
                        rule.source_addr_v4,
                        rule.source_mask,
                    )))
    }

    pub fn is_source_v6_addr(&self, rule: &Rule) -> bool {
        (rule.source_addr_v6 == 0)
            || ((self.source_addr_v6 == rule.source_addr_v6)
                || (rule.source_mask != 0
                    && is_ip_in_subnet_v6(
                        self.source_addr_v6,
                        rule.source_addr_v6,
                        rule.source_mask,
                    )))
    }

    pub fn is_destination_v4_addr(&self, rule: &Rule) -> bool {
        (rule.destination_addr_v4 == 0)
            || ((self.destination_addr_v4 == rule.destination_addr_v4)
                || (rule.destination_mask != 0
                    && is_ip_in_subnet_v4(
                        self.destination_addr_v4,
                        rule.destination_addr_v4,
                        rule.destination_mask,
                    )))
    }

    pub fn is_destination_v6_addr(&self, rule: &Rule) -> bool {
        (rule.destination_addr_v6 == 0)
            || ((self.destination_addr_v6 == rule.destination_addr_v6)
                || (rule.destination_mask != 0
                    && is_ip_in_subnet_v6(
                        self.destination_addr_v6,
                        rule.destination_addr_v6,
                        rule.destination_mask,
                    )))
    }

    pub fn to_action(&self, rule: &Rule) -> Action {
        if rule.ifindex != 0 && self.ifindex != rule.ifindex {
            return Action::Pipe;
        }
        if (self.v4 && rule.v4)
            && (self.is_source_v4_addr(rule)
                && self.is_source_port(rule)
                && rule.is_source_v4_not_empty())
            || (self.is_destination_v4_addr(rule)
                && self.is_destination_port(rule)
                && rule.is_destination_v4_not_empty())
        {
            return rule.to_action();
        }
        if (self.v6 && rule.v6)
            && (self.is_source_v6_addr(rule)
                && self.is_source_port(rule)
                && rule.is_source_v6_not_empty())
            || (self.is_destination_v6_addr(rule)
                && self.is_destination_port(rule)
                && rule.is_destination_v6_not_empty())
        {
            return rule.to_action();
        }
        Action::Pipe
    }

    pub fn not_my_rule(&self, rule: &Rule) -> bool {
        (self.v4 && !rule.v4)
            || (self.v6 && !rule.v6)
            || (self.input && !rule.input)
            || (self.output && !rule.output)
            || (rule.tcp && self.proto != IpProto::Tcp)
            || (rule.udp && self.proto != IpProto::Udp)
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
