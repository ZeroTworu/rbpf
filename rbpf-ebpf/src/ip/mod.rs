pub mod ipproto;
pub mod parser_result;
pub mod v4;
pub mod v6;

use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT, xdp_action};
use aya_ebpf::programs::{TcContext, XdpContext};
use core::net::Ipv6Addr;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use parser_result::ParseResult;

pub struct UnhandledProtocolError {
    pub proto: IpProto,

    pub dst_v4: u32,
    pub src_v4: u32,

    pub dst_v6: u128,
    pub src_v6: u128,

    pub ifindex: u32,
    pub input: bool,
    pub v4: bool,
}

impl UnhandledProtocolError {
    pub fn empty() -> Self {
        Self {
            proto: IpProto::Reserved,
            dst_v4: 0u32,
            src_v4: 0u32,
            dst_v6: 0u128,
            src_v6: 0u128,
            ifindex: 0u32,
            input: false,
            v4: false,
        }
    }

    pub fn proto_as_u8(&self) -> u8 {
        return ipproto::as_u8(&self.proto);
    }
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

    #[inline(always)]
    pub fn ptr_at_u<T>(&self, offset: usize) -> Result<*const T, UnhandledProtocolError> {
        let len = size_of::<T>();
        if self.data + offset + len > self.data_end {
            return Err(UnhandledProtocolError::empty());
        }
        Ok((self.data + offset) as *const T)
    }

    pub fn to_parse_result(
        &self,
        v4: bool,
        input: bool,
    ) -> Result<ParseResult, UnhandledProtocolError> {
        let (proto, destination_addr_v4, source_addr_v4, destination_addr_v6, source_addr_v6) =
            if v4 {
                let ipv4hdr: Ipv4Hdr = unsafe { *self.ptr_at_u(EthHdr::LEN)? };
                (
                    ipv4hdr.proto,
                    u32::from_be(ipv4hdr.dst_addr),
                    u32::from_be(ipv4hdr.src_addr),
                    0u128,
                    0u128,
                )
            } else {
                let ipv6hdr: Ipv6Hdr = unsafe { *self.ptr_at_u(EthHdr::LEN)? };

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
                let tcphdr: TcpHdr = unsafe { *self.ptr_at_u(EthHdr::LEN + len)? };
                (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
            }
            IpProto::Udp => {
                let udphdr: UdpHdr = unsafe { *self.ptr_at_u(EthHdr::LEN + len)? };
                (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
            }
            _ => {
                return Err(UnhandledProtocolError {
                    proto,
                    dst_v4: destination_addr_v4,
                    src_v4: source_addr_v4,
                    dst_v6: destination_addr_v6,
                    src_v6: source_addr_v6,
                    ifindex: self.ifindex,
                    input,
                    v4,
                });
            }
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

    pub fn handle_as_tc(&self) -> i32 {
        let ethhdr: EthHdr = unsafe {
            let res = self.ptr_at_u(0);
            match res {
                Err(_) => return TC_ACT_SHOT,
                Ok(t) => *t,
            }
        };
        match ethhdr.ether_type {
            EtherType::Ipv4 => self.handle_egress_v4(),
            EtherType::Ipv6 => self.handle_egress_v6(),
            _ => TC_ACT_PIPE,
        }
    }
    pub fn handle_as_xdp(&self) -> u32 {
        let ethhdr: EthHdr = unsafe {
            let res = self.ptr_at_u(0);
            match res {
                Err(_) => return xdp_action::XDP_DROP,
                Ok(t) => *t,
            }
        };

        match ethhdr.ether_type {
            EtherType::Ipv4 => self.handle_ingress_v4(),
            EtherType::Ipv6 => self.handle_ingress_v6(),
            _ => xdp_action::XDP_PASS,
        }
    }
}
