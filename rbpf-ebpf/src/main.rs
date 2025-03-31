#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use network_types::eth::{EthHdr, EtherType};
use rbpf_ebpf::ip::ptr_at_u;
use rbpf_ebpf::ip::v4::{handle_egress_v4, handle_ingress_v4};
use rbpf_ebpf::ip::v6::{handle_egress_v6, handle_ingress_v6};

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    try_tc_egress(ctx).unwrap_or_else(|_| TC_ACT_SHOT)
}

#[xdp]
pub fn tc_ingress(ctx: XdpContext) -> u32 {
    try_tc_ingress(ctx).unwrap_or_else(|_| xdp_action::XDP_DROP)
}

fn try_tc_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: EthHdr = unsafe { *ptr_at_u(ctx.data(), ctx.data_end(), 0)? };

    match ethhdr.ether_type {
        EtherType::Ipv4 => handle_ingress_v4(&ctx),
        EtherType::Ipv6 => handle_ingress_v6(&ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => handle_egress_v4(&ctx),
        EtherType::Ipv6 => handle_egress_v6(&ctx),
        _ => Ok(TC_ACT_PIPE),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
