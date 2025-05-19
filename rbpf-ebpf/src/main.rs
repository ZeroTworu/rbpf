#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_SHOT, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use rbpf_ebpf::ip::{ContextWrapper, UnhandledProtocolError};

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    try_tc_egress(ctx).unwrap_or_else(|_| TC_ACT_SHOT)
}

#[xdp]
pub fn tc_ingress(ctx: XdpContext) -> u32 {
    try_tc_ingress(ctx).unwrap_or_else(|_| xdp_action::XDP_DROP)
}

fn try_tc_ingress(ctx: XdpContext) -> Result<u32, UnhandledProtocolError> {
    let wctx = ContextWrapper::from_xdp(&ctx);
    wctx.handle_as_xdp()
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, UnhandledProtocolError> {
    let wctx = ContextWrapper::from_tc(&ctx);
    wctx.handle_as_tc()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
