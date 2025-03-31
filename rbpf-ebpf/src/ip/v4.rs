use crate::events;
use crate::events::LogMessage;
use crate::ip::ParseResult;
use crate::rules::v4;
use crate::rules::Action;
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::{TcContext, XdpContext};
use aya_log_ebpf::{debug, warn};
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub fn handle_ingress_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match ParseResult::from_xdp(ctx, true) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    debug!(
        ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr_v4,
        ret.source_port,
        ret.destination_addr_v4,
        ret.destination_port
    );

    let (action, rule_id) = v4::check_rule_v4(&ret);
    match action {
        Action::Ok => Ok(xdp_action::XDP_PASS),
        Action::Drop => {
            warn!(
                ctx,
                "INPUT: {:i}:{} -> {:i}:{}",
                ret.source_addr_v4,
                ret.source_port,
                ret.destination_addr_v4,
                ret.destination_port
            );
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(xdp_action::XDP_DROP)
        }
        Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v4(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match ParseResult::from_tc(ctx, true) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    debug!(
        ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr_v4,
        ret.source_port,
        ret.destination_addr_v4,
        ret.destination_port
    );

    let (action, rule_id) = v4::check_rule_v4(&ret);
    match action {
        Action::Ok => Ok(TC_ACT_PIPE),
        Action::Drop => {
            LogMessage::send_from_rule("BAN", rule_id, &ret, events::WARN);
            Ok(TC_ACT_SHOT)
        }
        Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
