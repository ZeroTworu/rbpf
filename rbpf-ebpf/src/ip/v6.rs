use crate::events::{LogMessage, DEBUG};
use crate::ip::ContextWrapper;
use crate::rules::rule;
use crate::{events, rules};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};

pub fn handle_ingress_v6(ctx: &ContextWrapper) -> Result<u32, ()> {
    let ret = match ctx.to_parse_result(false, false) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    LogMessage::send_from("IN v6", &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        rules::Action::Ok => Ok(xdp_action::XDP_PASS),
        rules::Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(xdp_action::XDP_DROP)
        }
        rules::Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v6(ctx: &ContextWrapper) -> Result<i32, ()> {
    let ret = match ctx.to_parse_result(false, false) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    LogMessage::send_from("OUT v6", &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        rules::Action::Ok => Ok(TC_ACT_PIPE),
        rules::Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(TC_ACT_SHOT)
        }
        rules::Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
