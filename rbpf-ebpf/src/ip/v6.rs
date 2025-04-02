use crate::ip::ContextWrapper;
use crate::logs::WLogMessage;
use crate::rules::rule;
use crate::{logs, rules};
use rbpf_common::{DEBUG, ERROR, INFO, WARN};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};

pub fn handle_ingress_v6(ctx: &ContextWrapper) -> Result<u32, ()> {
    let ret = match ctx.to_parse_result(false, true) {
        Ok(ret) => ret,
        Err(_) => return {
            // WLogMessage::send_from("ERR IN v6", ERROR);
            Ok(xdp_action::XDP_PASS)
        },
    };

    // WLogMessage::send_from_rule("IN v6", 0, &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        rules::Action::Ok => {
            // WLogMessage::send_from_rule("OK IN v6", rule_id, &ret, INFO);
            Ok(xdp_action::XDP_PASS)
        },
        rules::Action::Drop => {
            // WLogMessage::send_from_rule("BAN IN v6", rule_id, &ret, WARN);
            Ok(xdp_action::XDP_DROP)
        }
        rules::Action::Pipe => {
            // WLogMessage::send_from("PIPE IN v6", DEBUG);
            Ok(xdp_action::XDP_PASS)
        },
    }
}

pub fn handle_egress_v6(ctx: &ContextWrapper) -> Result<i32, ()> {
    let ret = match ctx.to_parse_result(false, false) {
        Ok(ret) => ret,
        Err(_) => return {
            // WLogMessage::send_from("ERR v6",  ERROR);
            Ok(TC_ACT_PIPE)
        },
    };

    // WLogMessage::send_from_rule("OUT v6", 0, &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        rules::Action::Ok => {
            // WLogMessage::send_from_rule("OK v6", rule_id, &ret, INFO);
            Ok(TC_ACT_PIPE)
        },
        rules::Action::Drop => {
            // WLogMessage::send_from_rule("BAN OUT v6", rule_id, &ret, WARN);
            Ok(TC_ACT_SHOT)
        }
        rules::Action::Pipe => {
            // WLogMessage::send_from_rule("PIPE OUT v6", rule_id, &ret, DEBUG);
            Ok(TC_ACT_PIPE)
        },
    }
}
