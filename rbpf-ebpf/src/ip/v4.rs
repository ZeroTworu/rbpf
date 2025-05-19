use crate::ip::ContextWrapper;
use crate::{logs, rules::rule};
use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT, xdp_action};
use rbpf_common::logs::{DEBUG, INFO, WARN};
use rbpf_common::rules::Action;

impl ContextWrapper {
    pub fn handle_ingress_v4(&self) -> u32 {
        let ret = match self.to_parse_result(true, true) {
            Ok(ret) => ret,
            Err(proto) => {
                return {
                    logs::send_err_unhandled_protocol("UNHANDLED IN v4", proto);
                    xdp_action::XDP_DROP
                };
            }
        };

        logs::send_from_rule("IN v4", 0, &ret, DEBUG);

        let (action, rule_id) = rule::check_rule(&ret);
        match action {
            Action::Ok => {
                logs::send_from_rule("OK IN v4", rule_id, &ret, INFO);
                xdp_action::XDP_PASS
            }
            Action::Drop => {
                logs::send_from_rule("BAN IN v4", rule_id, &ret, WARN);
                xdp_action::XDP_DROP
            }
            Action::Pipe => {
                logs::send_from_rule("PIPE IN v4", rule_id, &ret, DEBUG);
                xdp_action::XDP_PASS
            }
        }
    }

    pub fn handle_egress_v4(&self) -> i32 {
        let ret = match self.to_parse_result(true, false) {
            Ok(ret) => ret,
            Err(proto) => {
                return {
                    logs::send_err_unhandled_protocol("UNHANDLED OUT v4", proto);
                    TC_ACT_SHOT
                };
            }
        };

        logs::send_from_rule("OUT v4", 0, &ret, DEBUG);

        let (action, rule_id) = rule::check_rule(&ret);
        match action {
            Action::Ok => {
                logs::send_from_rule("OK OUT v4", rule_id, &ret, INFO);
                TC_ACT_PIPE
            }
            Action::Drop => {
                logs::send_from_rule("BAN OUT v4", rule_id, &ret, WARN);
                TC_ACT_SHOT
            }
            Action::Pipe => {
                logs::send_from_rule("PIPE OUT v4", rule_id, &ret, DEBUG);
                TC_ACT_PIPE
            }
        }
    }
}
