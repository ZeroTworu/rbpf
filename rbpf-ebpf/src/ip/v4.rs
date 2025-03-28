use crate::filter::v4::{is_in_v4_block, is_out_v4_block};
use crate::ip::{ptr_at, TcContext};
use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_log_ebpf::{info, warn};
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub struct ParseResultV4 {
    pub source_port: u16,
    pub destination_port: u16,

    pub destination_addr: u32,
    pub source_addr: u32,

    pub proto: IpProto,
}

pub fn parse_v4(ctx: &TcContext) -> Result<ParseResultV4, ()> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination_addr = u32::from_be(ipv4hdr.dst_addr);
    let source_addr = u32::from_be(ipv4hdr.src_addr);
    let proto = ipv4hdr.proto;

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

    Ok(ParseResultV4 {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
    })
}

pub fn handle_ingress_v4(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v4(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_in_v4_block(&ret) {
        warn!(
            ctx,
            "V4 [BLOCK] {:i}:{} as INPUT RULE", ret.source_addr, ret.source_port
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(
        ctx,
        "V4 INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}

pub fn handle_egress_v4(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v4(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_out_v4_block(&ret) {
        warn!(
            ctx,
            "V4 [BLOCK] {:i}:{} as OUTPUT RULE", ret.destination_addr, ret.destination_port
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(
        ctx,
        "V4 OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}
