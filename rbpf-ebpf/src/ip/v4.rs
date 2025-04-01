use crate::ip::ContextWrapper;
use crate::logs::{WLogMessage, DEBUG, WARN};
use crate::rules::rule;
use crate::rules::Action;
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};

pub fn handle_ingress_v4(ctx: &ContextWrapper) -> Result<u32, ()> {
    let ret = match ctx.to_parse_result(true, true) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_DROP),
    };

    WLogMessage::send_from_rule("IN v4", 0, &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        Action::Ok => Ok(xdp_action::XDP_PASS),
        Action::Drop => {
            WLogMessage::send_from_rule("BAN v4", rule_id, &ret, WARN);
            Ok(xdp_action::XDP_DROP)
        }
        Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v4(ctx: &ContextWrapper) -> Result<i32, ()> {
    let ret = match ctx.to_parse_result(true, false) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_SHOT),
    };

    WLogMessage::send_from_rule("OUT v4", 0, &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        Action::Ok => Ok(TC_ACT_PIPE),
        Action::Drop => {
            WLogMessage::send_from_rule("BAN v4", rule_id, &ret, WARN);
            Ok(TC_ACT_SHOT)
        }
        Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
