use crate::ip::v6::ParseResultV6;
use aya_ebpf::{macros::map, maps::Array, maps::HashMap};
use core::net::Ipv6Addr;

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

#[map]
static OUT_BLOCK_LIST_V6_SUBNETS: Array<u128> = Array::with_max_entries(MAX_ENTRIES, 0);

#[map]
static IN_BLOCK_LIST_V6_SUBNETS: Array<u128> = Array::with_max_entries(MAX_ENTRIES, 0);

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


pub fn is_in_v6_subnet_block(pac: &ParseResultV6) -> bool {
    is_in_subnet_block_for_v6(pac, true)
}

pub fn is_out_v6_subnet_block(pac: &ParseResultV6) -> bool {
    is_in_subnet_block_for_v6(pac, false)
}

pub fn is_in_subnet_block_for_v6(pac: &ParseResultV6, is_input: bool) -> bool {
    let index: u32 = 0;
    loop {

        let item = if is_input {
            IN_BLOCK_LIST_V6_SUBNETS.get(index)
        } else {
            OUT_BLOCK_LIST_V6_SUBNETS.get(index)
        };

        let res = match item {
            Some(item) => {
                let (v6, prefix_len) = (item >> 8, (item & 0xFF) as u8);

                if prefix_len == 0 {
                    return false;
                }

                is_ipv6_in_subnet(pac.source_addr, v6, prefix_len)
            }
            None => false,
        };
        return res;
    }
}

// Порождение чятгопоты. Как ЭТО работает - я не знаю.
struct Ipv6Parts {
    high: u64, // Старшие 64 бита
    low: u64,  // Младшие 64 бита
}

/// Преобразует `Ipv6Addr` в `Ipv6Parts` с двумя `u64`.
fn ipv6_to_parts(ip: Ipv6Addr) -> Ipv6Parts {
    let segments = ip.segments();
    Ipv6Parts {
        high: ((segments[0] as u64) << 48)
            | ((segments[1] as u64) << 32)
            | ((segments[2] as u64) << 16)
            | (segments[3] as u64),
        low: ((segments[4] as u64) << 48)
            | ((segments[5] as u64) << 32)
            | ((segments[6] as u64) << 16)
            | (segments[7] as u64),
    }
}

/// Преобразует `u128` в структуру `Ipv6Parts` с двумя `u64`.
fn u128_to_parts(addr: u128) -> Ipv6Parts {
    Ipv6Parts {
        high: (addr >> 64) as u64, // Старшие 64 бита
        low: addr as u64,          // Младшие 64 бита
    }
}

/// Проверяет, попадает ли IPv6-адрес `ip` в подсеть с адресом `network` и длиной префикса `prefix_len`.
fn is_ipv6_in_subnet(ip: Ipv6Addr, network: u128, prefix_len: u8) -> bool {
    let ip_parts = ipv6_to_parts(ip);
    let network_parts = u128_to_parts(network);

    if prefix_len == 0 {
        return true; // Префикс длиной 0 включает все адреса.
    } else if prefix_len <= 64 {
        // Маска только для старших 64 бит.
        let mask = (!0u64) << (64 - prefix_len);
        return (ip_parts.high & mask) == (network_parts.high & mask);
    } else {
        // Префикс захватывает оба `u64` (старшие и младшие биты).
        let low_mask = (!0u64) << (128 - prefix_len); // Маска для младших бит
        return (ip_parts.high == network_parts.high)
            && ((ip_parts.low & low_mask) == (network_parts.low & low_mask));
    }
}
