use crate::ip::parser_result::ParseResult;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use rbpf_common::rules::Action;
use rbpf_common::rules::Rule;

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
        if pac.v6 { &RULES_IN_V6 } else { &RULES_OUT_V4 }
    } else {
        if pac.v6 { &RULES_OUT_V6 } else { &RULES_OUT_V4 }
    };
    for index in 0..=MAX_ENTRIES {
        let rule = unsafe { rules.get(&index) };
        return match rule {
            Some(rule) => {
                if pac.not_my_rule(rule) {
                    continue;
                }

                let res = pac.to_action(rule);
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
