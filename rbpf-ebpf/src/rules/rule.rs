use crate::ip::ParseResult;
use crate::rules::{Action, WRule};
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use rbpf_common::Rule;

const MAX_ENTRIES: u32 = 128;

#[map]
static RULES_IN_V6: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static RULES_OUT_V6: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static RULES_IN_V4: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static RULES_OUT_V4: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
pub fn check_rule(pac: &ParseResult) -> (Action, u32) {
    let rules = if pac.input {
        if pac.v6 {
            &RULES_IN_V6
        } else {
            &RULES_OUT_V4
        }
    } else {
        if pac.v6 {
            &RULES_OUT_V6
        } else {
            &RULES_OUT_V4
        }
    };
    for index in 0..=MAX_ENTRIES {
        let rule = unsafe { rules.get(&index) };
        return match rule {
            Some(rule) => {
                let wrule = &WRule { rule };
                if pac.not_my_rule(wrule) {
                    continue;
                }

                let res = pac.to_action(wrule);
                if res == Action::Pipe {
                    continue;
                }
                (res, rule.rule_id)
            }
            None => (Action::Pipe, 0),
        };
    }
    (Action::Pipe, 0)
}
