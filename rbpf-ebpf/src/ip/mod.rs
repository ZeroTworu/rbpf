pub mod v4;
pub mod v6;

use aya_ebpf::programs::{TcContext, XdpContext};
use core::net::Ipv6Addr;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_xdp<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
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

#[inline(always)]
pub fn parse_tc(ctx: &TcContext, input: bool, v4: bool) -> Result<ParseResult, ()> {
    let (proto, destination_addr_v4, source_addr_v4, destination_addr_v6, source_addr_v6) = if v4 {
        let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
        (
            ipv4hdr.proto,
            u32::from_be(ipv4hdr.src_addr),
            u32::from_be(ipv4hdr.dst_addr),
            0u128,
            0u128,
        )
    } else {
        let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

        (
            ipv6hdr.next_hdr,
            0u32,
            0u32,
            Ipv6Addr::from(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }).to_bits(),
            Ipv6Addr::from(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }).to_bits(),
        )
    };

    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Err(()),
    };

    Ok(ParseResult {
        source_port,
        destination_port,
        proto,
        destination_addr_v4,
        source_addr_v4,
        destination_addr_v6,
        source_addr_v6,
        input,
        output: !input,
        v4,
        v6: !v4,
    })
}

#[inline(always)]
pub fn parse_xdp(ctx: &XdpContext, input: bool, v4: bool) -> Result<ParseResult, ()> {
    let (proto, destination_addr_v4, source_addr_v4, destination_addr_v6, source_addr_v6) = if v4 {
        let ipv4hdr: Ipv4Hdr = unsafe { *ptr_at_xdp(&ctx, EthHdr::LEN)? };
        (
            ipv4hdr.proto,
            u32::from_be(ipv4hdr.src_addr),
            u32::from_be(ipv4hdr.dst_addr),
            0u128,
            0u128,
        )
    } else {
        let ipv6hdr: Ipv6Hdr = unsafe { *ptr_at_xdp(&ctx, EthHdr::LEN)? };

        (
            ipv6hdr.next_hdr,
            0u32,
            0u32,
            Ipv6Addr::from(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }).to_bits(),
            Ipv6Addr::from(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }).to_bits(),
        )
    };

    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ptr_at_xdp(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ptr_at_xdp(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
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
