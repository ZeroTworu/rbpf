#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{info, warn};
use network_types::eth::{EthHdr, EtherType};
use rbpf_ebpf::{parse, ParseResult};

#[map]
static IN_BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static OUT_BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    try_tc_egress(ctx).unwrap_or_else(|_| TC_ACT_SHOT)
}

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    try_tc_ingress(ctx).unwrap_or_else(|_| TC_ACT_SHOT)
}

fn try_tc_ingress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ret = match parse(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_in_block(&ret) {
        warn!(&ctx, "[BLOCK] {:i} as INPUT RULE", ret.source_addr);
        return Ok(TC_ACT_SHOT);
    }

    info!(
        &ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ret = match parse(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_out_block(&ret) {
        warn!(&ctx, "[BLOCK] {:i} as OUTPUT RULE", ret.destination_addr);
        return Ok(TC_ACT_SHOT);
    }

    info!(
        &ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}

fn is_in_block(pac: &ParseResult) -> bool {
    unsafe { IN_BLOCKLIST.get(&pac.source_addr).is_some() }
}

fn is_out_block(pac: &ParseResult) -> bool {
    unsafe { OUT_BLOCKLIST.get(&pac.destination_addr).is_some() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
