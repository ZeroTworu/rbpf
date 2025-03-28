use crate::ip::v4::ParseResultV4;
use aya_ebpf::{macros::map, maps::HashMap};

#[map]
static IN_BLOCKLIST_ADDRESSES: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static IN_BLOCKLIST_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(1024, 0);

#[map]
static OUT_BLOCKLIST_ADDRESSES: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static OUT_BLOCKLIST_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(1024, 0);

// Такое извращение с || нужно, что бы когда программа загружена как eBPF не происходил сегфол

pub fn is_in_block(pac: &ParseResultV4) -> bool {
    let res: bool = unsafe { IN_BLOCKLIST_ADDRESSES.get(&pac.source_addr).is_some() }
        || unsafe { IN_BLOCKLIST_PORTS.get(&pac.source_port).is_some() };
    res
}

pub fn is_out_block(pac: &ParseResultV4) -> bool {
    let res: bool = unsafe { OUT_BLOCKLIST_ADDRESSES.get(&pac.destination_addr).is_some() }
        || unsafe { OUT_BLOCKLIST_PORTS.get(&pac.destination_port).is_some() };
    res
}
