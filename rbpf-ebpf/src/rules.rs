use crate::ip::parser_result::ParseResult;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use rbpf_common::rules::Action;
use rbpf_common::rules::Rule;

const MAX_ENTRIES: u32 = 512;

#[map]
static RULES: HashMap<u32, Rule> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[inline(always)]
pub fn check_rule(pac: &ParseResult) -> (Action, u32) {
    for index in 0..=MAX_ENTRIES {
        let rule = unsafe { RULES.get(&index) };
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
