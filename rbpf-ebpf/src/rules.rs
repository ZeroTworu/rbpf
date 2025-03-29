use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;
use crate::ip::v4::ParseResultV4;

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub port: u16,
    pub addr: u32,
    pub tcp: bool,
    pub udp: bool,
}

const MAX_ENTRIES: u32 = 65535;

#[map]
static RULES: Array<Rule> = Array::with_max_entries(MAX_ENTRIES, 0);

pub fn check_rule(pac: &ParseResultV4){
    let mut index: u32 = 0;
    loop {
        let rule = RULES.get(index);
        match rule {
            Some(rule) => {

            }
            None => {}
        }
        index += 1;
    }
}