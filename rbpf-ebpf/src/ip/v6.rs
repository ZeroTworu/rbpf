use crate::ip::ContextWrapper;
use crate::{logs, rules};
use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT, xdp_action};
use rbpf_common::logs::{DEBUG, INFO, WARN};
use rbpf_common::rules::Action;

impl ContextWrapper {
    #[inline(always)]
    pub fn handle_ingress_v6(&self) -> u32 {
        let ret = match self.to_parse_result(false, true) {
            Ok(ret) => ret,
            Err(proto) => {
                return {
                    logs::send_err_unhandled_protocol("UNHANDLED IN v6", proto);
                    xdp_action::XDP_DROP
                };
            }
        };

        let (action, rule_id) = rules::check_rule(&ret);

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
                logs::send_from_rule("PIPE IN v6", 0, &ret, DEBUG);
                xdp_action::XDP_PASS
            }
        }
    }

    #[inline(always)]
    pub fn handle_egress_v6(&self) -> i32 {
        let ret = match self.to_parse_result(false, false) {
            Ok(ret) => ret,
            Err(proto) => {
                return {
                    logs::send_err_unhandled_protocol("UNHANDLED OUT v6", proto);
                    TC_ACT_SHOT
                };
            }
        };

        let (action, rule_id) = rules::check_rule(&ret);

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
                logs::send_from_rule("PIPE OUT v6", 0, &ret, DEBUG);
                TC_ACT_PIPE
            }
        }
    }
}
