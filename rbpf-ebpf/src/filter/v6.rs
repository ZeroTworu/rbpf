use crate::ip::v6::ParseResultV6;
use aya_ebpf::{macros::map, maps::HashMap};

const MAX_ENTRIES: u32 = 65535;

#[map]
static IN_BLOCKLIST_V6_ADDRESSES: HashMap<u128, u128> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IN_BLOCKLIST_V6_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static OUT_BLOCKLIST_V6_ADDRESSES: HashMap<u128, u128> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static OUT_BLOCKLIST_V6_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IN_BLOCKLIST_V6_IP_PORT: HashMap<u128, u16> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static OUT_BLOCKLIST_V6_IP_PORT: HashMap<u128, u16> = HashMap::with_max_entries(MAX_ENTRIES, 0);

// Такое извращение с || нужно, что бы когда программа загружена как eBPF не происходил сегфол
#[inline(always)]
pub fn is_in_v6_block(pac: &ParseResultV6) -> bool {
    let res: bool = unsafe {
        IN_BLOCKLIST_V6_ADDRESSES
            .get(&pac.source_addr.to_bits())
            .is_some()
    } || unsafe { IN_BLOCKLIST_V6_PORTS.get(&pac.source_port).is_some() };
    res
}

#[inline(always)]
pub fn is_out_v6_block(pac: &ParseResultV6) -> bool {
    let res: bool = unsafe {
        OUT_BLOCKLIST_V6_ADDRESSES
            .get(&pac.destination_addr.to_bits())
            .is_some()
    } || unsafe { OUT_BLOCKLIST_V6_PORTS.get(&pac.destination_port).is_some() };
    res
}
