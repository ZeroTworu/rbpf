use crate::events::LogMessage;
use crate::ip::ParseResult;
use crate::rules::v6;
use crate::{events, rules};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::{TcContext, XdpContext};
use aya_log_ebpf::debug;
use core::net::Ipv6Addr;

pub fn handle_ingress_v6(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match ParseResult::from_xdp(ctx, false) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    debug!(
        ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        Ipv6Addr::from(ret.source_addr_v6),
        ret.source_port,
        Ipv6Addr::from(ret.destination_addr_v6),
        ret.destination_port
    );

    let (action, rule_id) = v6::check_rule_v6(&ret);
    match action {
        rules::Action::Ok => Ok(xdp_action::XDP_PASS),
        rules::Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(xdp_action::XDP_DROP)
        }
        rules::Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v6(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match ParseResult::from_tc(ctx, false) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    debug!(
        ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        Ipv6Addr::from(ret.source_addr_v6),
        ret.source_port,
        Ipv6Addr::from(ret.destination_addr_v6),
        ret.destination_port
    );

    let (action, rule_id) = v6::check_rule_v6(&ret);
    match action {
        rules::Action::Ok => Ok(TC_ACT_PIPE),
        rules::Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(TC_ACT_SHOT)
        }
        rules::Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
