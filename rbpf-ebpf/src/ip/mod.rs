pub mod v4;
pub mod v6;

use aya_ebpf::programs::{TcContext, XdpContext};
use core::net::Ipv6Addr;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn ptr_at_u<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
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
}

impl ParseResult {
    #[inline(always)]
    pub fn from_usize(data: usize, data_end: usize, input: bool, v4: bool) -> Result<Self, ()> {
        let (proto, destination_addr_v4, source_addr_v4, destination_addr_v6, source_addr_v6) =
            if v4 {
                let ipv4hdr: Ipv4Hdr = unsafe { *ptr_at_u(data, data_end, EthHdr::LEN)? };
                (
                    ipv4hdr.proto,
                    u32::from_be(ipv4hdr.dst_addr),
                    u32::from_be(ipv4hdr.src_addr),
                    0u128,
                    0u128,
                )
            } else {
                let ipv6hdr: Ipv6Hdr = unsafe { *ptr_at_u(data, data_end, EthHdr::LEN)? };

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
                let tcphdr: TcpHdr = unsafe { *ptr_at_u(data, data_end, EthHdr::LEN + len)? };
                (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
            }
            IpProto::Udp => {
                let udphdr: UdpHdr = unsafe { *ptr_at_u(data, data_end, EthHdr::LEN + len)? };
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
        })
    }
    #[inline(always)]
    pub fn from_xdp(ctx: &XdpContext, v4: bool) -> Result<Self, ()> {
        Self::from_usize(ctx.data(), ctx.data_end(), true, v4)
    }
    #[inline(always)]
    pub fn from_tc(ctx: &TcContext, v4: bool) -> Result<Self, ()> {
        Self::from_usize(ctx.data(), ctx.data_end(), false, v4)
    }
}
