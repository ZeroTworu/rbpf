use crate::events;
use crate::events::LogMessage;
use crate::ip::{parse_tc, parse_xdp, TcContext};
use crate::rules::v4;
use crate::rules::Action;
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::debug;

pub fn handle_ingress_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match parse_xdp(&ctx, true, true) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    debug!(
        ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr_v4,
        ret.source_port,
        ret.destination_addr_v4,
        ret.destination_port
    );

    let (action, rule_id) = v4::check_rule_v4(&ret);
    match action {
        Action::Ok => Ok(xdp_action::XDP_PASS),
        Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(xdp_action::XDP_DROP)
        }
        Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v4(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_tc(&ctx, false, true) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };
    debug!(
        ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr_v4,
        ret.source_port,
        ret.destination_addr_v4,
        ret.destination_port
    );

    let (action, rule_id) = v4::check_rule_v4(&ret);
    match action {
        Action::Ok => Ok(TC_ACT_PIPE),
        Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(TC_ACT_SHOT)
        }
        Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
