#![no_std]

pub mod filter;

use aya_ebpf::programs::TcContext;
use core::mem;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub struct ParseResult {
    pub source_port: u16,
    pub destination_port: u16,

    pub destination_addr: u32,
    pub source_addr: u32,

    pub proto: IpProto,
}

trait ContextPtr {
    fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()>;
}

impl ContextPtr for TcContext {
    #[inline(always)] //
    fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }

        Ok((start + offset) as *const T)
    }
}

pub fn parse(ctx: &TcContext) -> Result<ParseResult, ()> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination_addr = u32::from_be(ipv4hdr.dst_addr);
    let source_addr = u32::from_be(ipv4hdr.src_addr);
    let proto = ipv4hdr.proto;

    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ctx.ptr_at(EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ctx.ptr_at(EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Err(()),
    };

    Ok(ParseResult {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
    })
}
