use crate::ip::ContextWrapper;
use crate::{logs, rules::rule};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use crate::ip::ipproto;
use rbpf_common::logs::{DEBUG, INFO, WARN};
use rbpf_common::rules::Action;

pub fn handle_ingress_v6(ctx: &ContextWrapper) -> u32 {
    let ret = match ctx.to_parse_result(false, true) {
        Ok(ret) => ret,
        Err(proto) => {
            return {
                let proto = ipproto::as_u8(&proto);
                logs::send_err_unhandled_protocol("UNKNOWN IN v6", proto);
                xdp_action::XDP_DROP
            };
        }
    };

    logs::send_from_rule("IN v6", 0, &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        Action::Ok => {
            logs::send_from_rule("OK IN v6", rule_id, &ret, INFO);
            xdp_action::XDP_PASS
        }
        Action::Drop => {
            logs::send_from_rule("BAN IN v6", rule_id, &ret, WARN);
            xdp_action::XDP_DROP
        }
        Action::Pipe => {
            logs::send_from("PIPE IN v6", DEBUG);
            xdp_action::XDP_PASS
        }
    }
}

pub fn handle_egress_v6(ctx: &ContextWrapper) -> i32 {
    let ret = match ctx.to_parse_result(false, false) {
        Ok(ret) => ret,
        Err(proto) => {
            return {
                let proto = ipproto::as_u8(&proto);
                logs::send_err_unhandled_protocol("UNKNOWN OUT v6", proto);
                TC_ACT_SHOT
            };
        }
    };

    logs::send_from_rule("OUT v6", 0, &ret, DEBUG);

    let (action, rule_id) = rule::check_rule(&ret);
    match action {
        Action::Ok => {
            logs::send_from_rule("OK v6", rule_id, &ret, INFO);
            TC_ACT_PIPE
        }
        Action::Drop => {
            logs::send_from_rule("BAN OUT v6", rule_id, &ret, WARN);
            TC_ACT_SHOT
        }
        Action::Pipe => {
            logs::send_from_rule("PIPE OUT v6", rule_id, &ret, DEBUG);
            TC_ACT_PIPE
        }
    }
}
