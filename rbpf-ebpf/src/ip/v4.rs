use crate::filter::v4::{
    is_in_v4_block, is_in_v4_block_ip_port, is_out_v4_block, is_out_v4_block_ip_port,
};
use crate::ip::{ptr_at, ptr_at_xdp, TcContext};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{debug, warn};
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

pub fn parse_v4_xdp(ctx: &XdpContext) -> Result<ParseResultV4, ()> {
    let ipv4hdr: Ipv4Hdr = unsafe { *ptr_at_xdp(&ctx, EthHdr::LEN)? };
    let destination_addr = u32::from_be(ipv4hdr.dst_addr);
    let source_addr = u32::from_be(ipv4hdr.src_addr);
    let proto = ipv4hdr.proto;
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

    Ok(ParseResultV4 {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
    })
}

pub fn handle_ingress_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match parse_v4_xdp(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    if is_in_v4_block(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as INPUT RULE", ret.source_addr, ret.source_port
        );
        return Ok(xdp_action::XDP_DROP);
    }

    if is_in_v4_block_ip_port(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as INPUT RULE (IP:PORT)", ret.source_addr, ret.source_port
        );
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(
        ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(xdp_action::XDP_PASS)
}

pub fn handle_egress_v4(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v4(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_out_v4_block(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as OUTPUT RULE", ret.destination_addr, ret.destination_port
        );
        return Ok(TC_ACT_SHOT);
    }

    if is_out_v4_block_ip_port(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as OUTPUT RULE (IP:PORT)", ret.destination_addr, ret.destination_port
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}
