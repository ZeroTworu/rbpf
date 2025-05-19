#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use rbpf_ebpf::ip::ContextWrapper;

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let wctx = ContextWrapper::from_tc(&ctx);
    wctx.handle_as_tc()
}

#[xdp]
pub fn tc_ingress(ctx: XdpContext) -> u32 {
    let wctx = ContextWrapper::from_xdp(&ctx);
    wctx.handle_as_xdp()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
