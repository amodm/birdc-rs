//! Module for bird protocol objects

use crate::Message;

/// Represents one of the BIRD protocol instances. Note that this isn't the same
/// as, say BGP, or OSPF. That is represented by the field [Protocol::proto]
///
/// Details related to this are captured in a separate struct [ProtocolDetail],
/// and routing statistics are maintained inside various [Channel]s through the
/// [ProtocolDetail::channels] field.
#[derive(Debug, Clone)]
pub struct Protocol {
    /// Name of this protocol instance
    pub name: String,
    /// The underlying protocol, e.g. BGP, BFD, Kernel etc.
    pub proto: String,
    /// Routing table, in case of proto == Kernel
    pub table: Option<String>,
    /// State - up or down
    pub state: String,
    /// Last state since
    pub since: String,
    /// Additional status info, e.g. in case of BGP, this could be `Established`,
    /// `OpenSent` etc.
    pub info: Option<String>,
}

impl Protocol {
    /// Parse the response of a 1002 response. Returns None if `message` isn't a
    /// [Message::ProtocolList], or if we encounter an unrecoverable error during
    /// parsing.
    ///
    /// Details [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/proto.c)
    pub fn from_enum(message: &Message) -> Option<Vec<Protocol>> {
        if let Message::ProtocolList(content) = message {
            let mut result = vec![];
            for line in content.lines() {
                let mut it = line.split_ascii_whitespace();
                result.push(Protocol {
                    name: it.next()?.to_owned(),
                    proto: it.next()?.to_owned(),
                    table: filler_to_option(it.next()?),
                    state: it.next()?.to_owned(),
                    since: it.next()?.to_owned(),
                    info: it.next().map(|x| x.to_owned()),
                })
            }
            Some(result)
        } else {
            None
        }
    }
}

/// Detailed information for a [Protocol]
#[derive(Debug)]
pub struct ProtocolDetail {
    pub description: Option<String>,
    pub message: Option<String>,
    pub router_id: Option<String>,
    pub vrf: Option<String>,
    pub proto_info: Option<ProtoSpecificInfo>,
    pub channels: Vec<Channel>,
}

impl ProtocolDetail {
    /// Parse the response of a 1006 response. Returns None if `message` isn't a
    /// [Message::ProtocolDetails], or if we encounter an unrecoverable error during
    /// parsing.
    ///
    /// Details [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/proto.c)
    pub fn from_enum(message: &Message) -> Option<ProtocolDetail> {
        if let Message::ProtocolDetails(content) = message {
            // we convert the content into lines
            let lines: Vec<&str> = content.lines().filter(|x| !x.is_empty()).collect();
            if lines.is_empty() {
                return None;
            }

            let mut description: Option<&str> = None;
            let mut message: Option<&str> = None;
            let mut router_id: Option<&str> = None;
            let mut vrf: Option<&str> = None;
            let mut proto_info: Option<ProtoSpecificInfo> = None;
            let mut channels: Vec<Channel> = vec![];

            let base_indent = indent_level(lines[0]);
            let mut idx = 0_usize;
            while idx < lines.len() {
                let line = &lines[idx][base_indent..];
                if let Some(s) = line.strip_prefix("Description:") {
                    description = Some(s.trim());
                } else if let Some(s) = line.strip_prefix("Message:") {
                    message = Some(s.trim());
                } else if let Some(s) = line.strip_prefix("Router ID:") {
                    router_id = Some(s.trim());
                } else if let Some(s) = line.strip_prefix("VRF:") {
                    vrf = Some(s.trim());
                } else if line.starts_with("Channel") {
                    let start_idx = idx;
                    idx = lines
                        .iter()
                        .skip(idx + 1)
                        .position(|it| indent_level(it) == base_indent)
                        .unwrap_or(lines.len() - (idx + 1))
                        + (idx + 1);
                    if let Some(channel) = Channel::from_lines(&lines[start_idx..idx]) {
                        channels.push(channel);
                    }
                    idx -= 1; // as we do an increment at the end of the loop
                } else if line.starts_with("BGP") {
                    let start_idx = idx;
                    idx = lines
                        .iter()
                        .skip(idx + 1)
                        .position(|it| indent_level(it) == base_indent)
                        .unwrap_or(lines.len() - (idx + 1))
                        + (idx + 1);
                    if let Some(bgp_info) = BgpInfo::from_lines(&lines[start_idx..idx]) {
                        proto_info = Some(ProtoSpecificInfo::Bgp(bgp_info));
                    }
                    idx -= 1; // as we do an increment at the end of the loop
                }
                idx += 1;
            }

            Some(ProtocolDetail {
                description: description.map(|x| x.to_owned()),
                message: message.map(|x| x.to_owned()),
                router_id: router_id.map(|x| x.to_owned()),
                vrf: vrf.map(|x| x.to_owned()),
                proto_info,
                channels,
            })
        } else {
            None
        }
    }
}

/// Contains routing protocol specific details, e.g. BGP etc.
#[derive(Debug)]
pub enum ProtoSpecificInfo {
    /// BGP specific details about this protocol instance
    Bgp(BgpInfo),
}

/// Protocol channel details
#[derive(Debug)]
pub struct Channel {
    pub name: String,
    pub state: String,
    pub table: String,
    pub preference: u16,
    pub input_filter: String,
    pub output_filter: String,
    pub route_stats: Option<RouteStats>,
    pub bgp_next_hop: Option<String>,
}

impl Channel {
    fn from_lines(lines: &[&str]) -> Option<Channel> {
        let base_indent = indent_level(lines[0]);
        if let Some(name) = lines[0][base_indent..].strip_prefix("Channel ") {
            let mut state: Option<&str> = None;
            let mut table: Option<&str> = None;
            let mut preference = 0_u16;
            let mut input_filter: Option<&str> = None;
            let mut output_filter: Option<&str> = None;
            let mut bgp_next_hop: Option<&str> = None;
            let mut rcs_recvd_pos = 0_usize;
            let mut rcs_rejct_pos = 0_usize;
            let mut rcs_filtr_pos = 0_usize;
            let mut rcs_ignrd_pos = 0_usize;
            let mut rcs_accpt_pos = 0_usize;
            let mut route_stats = RouteStats::default();
            let mut has_route_stats = false;
            for line in &lines[1..] {
                if let Some(cpos) = line.find(':') {
                    let key = line[..cpos].trim();
                    let val = line[(cpos + 1)..].trim();
                    match key {
                        "State" => state = Some(val),
                        "Table" => table = Some(val),
                        "Preference" => preference = val.parse().unwrap_or(0),
                        "Input filter" => input_filter = Some(val),
                        "Output filter" => output_filter = Some(val),
                        "Routes" => {
                            has_route_stats = true;
                            for pair in val.split(',') {
                                if let Some(u) = pair.strip_suffix("imported") {
                                    route_stats.imported = u.trim().parse().unwrap_or(0);
                                } else if let Some(u) = pair.strip_suffix("exported") {
                                    route_stats.exported = u.trim().parse().unwrap_or(0);
                                } else if let Some(u) = pair.strip_suffix("preferred") {
                                    route_stats.preferred = u.trim().parse().unwrap_or(0);
                                } else if let Some(u) = pair.strip_suffix("filtered") {
                                    route_stats.filtered = u.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                        "Route change stats" => {
                            has_route_stats = true;
                            for (rcs_idx, it) in val.split_ascii_whitespace().enumerate() {
                                match it {
                                    "received" => rcs_recvd_pos = rcs_idx,
                                    "rejected" => rcs_rejct_pos = rcs_idx,
                                    "filtered" => rcs_filtr_pos = rcs_idx,
                                    "ignored" => rcs_ignrd_pos = rcs_idx,
                                    "accepted" => rcs_accpt_pos = rcs_idx,
                                    _ => {}
                                }
                            }
                        }
                        "Import updates" => {
                            route_stats.import_updates = rcs_from_line(
                                val,
                                rcs_recvd_pos,
                                rcs_rejct_pos,
                                rcs_filtr_pos,
                                rcs_ignrd_pos,
                                rcs_accpt_pos,
                            )
                        }
                        "Import withdraws" => {
                            route_stats.import_withdraws = rcs_from_line(
                                val,
                                rcs_recvd_pos,
                                rcs_rejct_pos,
                                rcs_filtr_pos,
                                rcs_ignrd_pos,
                                rcs_accpt_pos,
                            )
                        }
                        "Export updates" => {
                            route_stats.export_updates = rcs_from_line(
                                val,
                                rcs_recvd_pos,
                                rcs_rejct_pos,
                                rcs_filtr_pos,
                                rcs_ignrd_pos,
                                rcs_accpt_pos,
                            )
                        }
                        "Export withdraws" => {
                            route_stats.export_withdraws = rcs_from_line(
                                val,
                                rcs_recvd_pos,
                                rcs_rejct_pos,
                                rcs_filtr_pos,
                                rcs_ignrd_pos,
                                rcs_accpt_pos,
                            )
                        }
                        "BGP Next hop" => bgp_next_hop = Some(val),
                        _ => {}
                    }
                }
            }
            Some(Channel {
                name: name.to_owned(),
                state: state.unwrap_or("unknown").to_owned(),
                table: table.unwrap_or("unknown").to_owned(),
                preference,
                input_filter: input_filter.unwrap_or("unknown").to_owned(),
                output_filter: output_filter.unwrap_or("unknown").to_owned(),
                route_stats: if has_route_stats {
                    Some(route_stats)
                } else {
                    None
                },
                bgp_next_hop: bgp_next_hop.map(|x| x.to_owned()),
            })
        } else {
            None
        }
    }
}

/// Routing statistics for a [Channel]
#[derive(Debug, Default)]
pub struct RouteStats {
    pub imported: u32,
    pub exported: u32,
    pub preferred: u32,
    pub filtered: u32,
    pub import_updates: RouteChangeStats,
    pub import_withdraws: RouteChangeStats,
    pub export_updates: RouteChangeStats,
    pub export_withdraws: RouteChangeStats,
}

/// Statistics related to number of route change events in import/export
/// inside a [Channel]
#[derive(Debug, Default)]
pub struct RouteChangeStats {
    pub received: u32,
    pub rejected: u32,
    pub filtered: u32,
    pub ignored: u32,
    pub accepted: u32,
}

/// Details of BGP protocol related information for a [ProtocolDetail].
///
/// More information at Bird's website
/// [here](https://gitlab.nic.cz/labs/bird/-/blob/master/proto/bgp/bgp.c)
#[derive(Debug)]
pub struct BgpInfo {
    pub state: String,
    pub neighbor: BgpNeighbor,
    pub neighbor_as: u32,
    pub local_as: u32,
    pub graceful_restart_active: bool,
    pub session: Option<BgpSession>,
}

impl BgpInfo {
    fn from_lines(lines: &[&str]) -> Option<BgpInfo> {
        let mut state: Option<&str> = None;
        let mut neighbor: Option<BgpNeighbor> = None;
        let mut neighbor_as = 0_u32;
        let mut local_as = 0_u32;
        let mut neighbor_id: Option<&str> = None;
        let mut attributes: Vec<String> = vec![];
        let mut source_address: Option<&str> = None;
        let mut hold_time = 0_u64;
        let mut hold_time_remaining = 0_f64;
        let mut keepalive_time = 0_u64;
        let mut keepalive_time_remaining = 0_f64;

        for (key, val) in lines.iter().map(|x| {
            if let Some(pos) = x.find(':') {
                (x[..pos].trim(), x[(pos + 1)..].trim())
            } else {
                ("", "")
            }
        }) {
            match key {
                "BGP state" => state = Some(val),
                "Neighbor address" => neighbor = Some(BgpNeighbor::Address(val.to_owned())),
                "Neighbor range" => neighbor = Some(BgpNeighbor::Range(val.to_owned())),
                "Neighbor AS" => neighbor_as = val.parse().unwrap_or(0),
                "Local AS" => local_as = val.parse().unwrap_or(0),
                "Neighbor ID" => neighbor_id = Some(val),
                "Session" => {
                    attributes = val.split_ascii_whitespace().map(|x| x.to_owned()).collect()
                }
                "Source address" => source_address = Some(val),
                "Hold timer" => {
                    if let Some(pos) = val.find('/') {
                        hold_time_remaining = val[..pos].parse().unwrap_or(0.0);
                        hold_time = val[(pos + 1)..].parse().unwrap_or(0);
                    }
                }
                "Keepalive timer" => {
                    if let Some(pos) = val.find('/') {
                        keepalive_time_remaining = val[..pos].parse().unwrap_or(0.0);
                        keepalive_time = val[(pos + 1)..].parse().unwrap_or(0);
                    }
                }
                _ => {}
            }
        }

        if let Some(state) = state {
            neighbor.map(|neighbor| BgpInfo {
                state: state.to_owned(),
                neighbor,
                neighbor_as,
                local_as,
                graceful_restart_active: lines
                    .iter()
                    .any(|x| x.contains("Neighbor graceful restart active")),
                session: neighbor_id.map(|nid| BgpSession {
                    neighbor_id: nid.to_owned(),
                    attributes,
                    source_address: source_address.unwrap_or("").to_owned(),
                    hold_time,
                    hold_time_remaining,
                    keepalive_time,
                    keepalive_time_remaining,
                }),
            })
        } else {
            None
        }
    }
}

/// BGP neighbor address information
#[derive(Debug)]
pub enum BgpNeighbor {
    /// It's a specific IP address, usually suffixed with `%<interface>`
    Address(String),
    /// An IP address range, when BGP is configured in passive mode
    Range(String),
}

/// BGP session related information, which show up only if the session is up
#[derive(Debug)]
pub struct BgpSession {
    /// Neighbor's router id
    pub neighbor_id: String,
    /// Session attributes, e.g. internal/external, AS4, multihop etc.
    pub attributes: Vec<String>,
    /// Source IP address used by the bird instance to connect to this neighbor
    pub source_address: String,
    /// Hold time configured for this session
    pub hold_time: u64,
    /// Hold time remaining
    pub hold_time_remaining: f64,
    /// Keepalive time configured for this session
    pub keepalive_time: u64,
    /// Keepalive time remaining
    pub keepalive_time_remaining: f64,
}

/// Simple helper to conver a filler `---` into a None
#[inline]
fn filler_to_option(s: &str) -> Option<String> {
    if s.trim_matches('-').is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

/// Simple function to get the indent level of a line
#[inline]
fn indent_level(line: &str) -> usize {
    line.find(|c: char| !c.is_ascii_whitespace()).unwrap_or(0)
}

/// Returns a [RouteChangeStats] from the `line` provided
#[inline]
fn rcs_from_line(
    line: &str,
    recvd_pos: usize,
    rejct_pos: usize,
    filtrd_pos: usize,
    ignrd_pos: usize,
    accpt_pos: usize,
) -> RouteChangeStats {
    let mut idx = 0;
    let mut rcs = RouteChangeStats {
        received: 0,
        rejected: 0,
        filtered: 0,
        ignored: 0,
        accepted: 0,
    };
    for v in line.split_ascii_whitespace() {
        if v.contains('-') {
            idx += 1;
        } else {
            let u = v.parse::<u32>().unwrap_or(0);
            if idx == recvd_pos {
                rcs.received = u;
            } else if idx == rejct_pos {
                rcs.rejected = u;
            } else if idx == filtrd_pos {
                rcs.filtered = u;
            } else if idx == ignrd_pos {
                rcs.ignored = u;
            } else if idx == accpt_pos {
                rcs.accepted = u;
            }
            idx += 1;
        }
    }
    rcs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn test_protocol_parse() {
        let _ = env_logger::try_init();
        let content = "device1    Device     ---        up     2022-04-14    
        direct_eth0 Direct     ---        up     2022-04-14    
        kernel_v4  Kernel     master4    up     2022-04-14    
        kernel_v6  Kernel     master6    up     2022-04-14    
        bfd1       BFD        ---        up     2022-04-14    
        bgp_local4 BGP        ---        up     2022-04-16    Established   
        bgp_local6 BGP        ---        up     2022-04-16    Established"
            .lines()
            .map(|x| x.trim_start())
            .collect::<Vec<&str>>()
            .join("\n");
        let protocol =
            Protocol::from_enum(&Message::ProtocolList(content)).expect("failed to parse");
        assert_eq!(protocol.len(), 7);

        assert_eq!(protocol[0].name, "device1");
        assert_eq!(protocol[0].proto, "Device");
        assert!(protocol[0].table.is_none());
        assert_eq!(protocol[0].state, "up");
        assert_eq!(protocol[0].since, "2022-04-14");
        assert!(protocol[0].info.is_none());

        assert_eq!(protocol[1].name, "direct_eth0");
        assert_eq!(protocol[1].proto, "Direct");
        assert!(protocol[1].table.is_none());
        assert_eq!(protocol[1].state, "up");
        assert_eq!(protocol[1].since, "2022-04-14");
        assert!(protocol[1].info.is_none());

        assert_eq!(protocol[2].name, "kernel_v4");
        assert_eq!(protocol[2].proto, "Kernel");
        assert_eq!(protocol[2].table.as_ref().unwrap(), "master4");
        assert_eq!(protocol[2].state, "up");
        assert_eq!(protocol[2].since, "2022-04-14");
        assert!(protocol[2].info.is_none());

        assert_eq!(protocol[3].name, "kernel_v6");
        assert_eq!(protocol[3].proto, "Kernel");
        assert_eq!(protocol[3].table.as_ref().unwrap(), "master6");
        assert_eq!(protocol[3].state, "up");
        assert_eq!(protocol[3].since, "2022-04-14");
        assert!(protocol[3].info.is_none());

        assert_eq!(protocol[4].name, "bfd1");
        assert_eq!(protocol[4].proto, "BFD");
        assert!(protocol[4].table.is_none());
        assert_eq!(protocol[4].state, "up");
        assert_eq!(protocol[4].since, "2022-04-14");
        assert!(protocol[4].info.is_none());

        assert_eq!(protocol[5].name, "bgp_local4");
        assert_eq!(protocol[5].proto, "BGP");
        assert!(protocol[5].table.is_none());
        assert_eq!(protocol[5].state, "up");
        assert_eq!(protocol[5].since, "2022-04-16");
        assert_eq!(protocol[5].info.as_ref().unwrap(), "Established");

        assert_eq!(protocol[6].name, "bgp_local6");
        assert_eq!(protocol[6].proto, "BGP");
        assert!(protocol[6].table.is_none());
        assert_eq!(protocol[6].state, "up");
        assert_eq!(protocol[6].since, "2022-04-16");
        assert_eq!(protocol[6].info.as_ref().unwrap(), "Established");
    }

    #[test]
    fn test_bgp_info_parse() {
        let _ = env_logger::try_init();
        let lines = "
            BGP state:          Established
              Neighbor address: 172.29.0.1
              Neighbor AS:      64561
              Local AS:         64560
              Neighbor ID:      172.29.0.1
              Local capabilities
                Multiprotocol
                  AF announced: ipv4
                Route refresh
                Graceful restart
                4-octet AS numbers
                Enhanced refresh
                Long-lived graceful restart
              Neighbor capabilities
                Multiprotocol
                  AF announced: ipv4
                Route refresh
                Graceful restart
                  Restart time: 10
                  AF supported: ipv4
                  AF preserved: ipv4
                4-octet AS numbers
                Long-lived graceful restart
              Session:          external AS4
              Source address:   172.29.0.12
              Hold timer:       45.058/90
              Keepalive timer:  25.940/30"
            .lines()
            .filter(|x| !x.trim().is_empty())
            .collect::<Vec<&str>>();
        let bgp_info = BgpInfo::from_lines(&lines).expect("failed to parse bgp info");
        assert_eq!(bgp_info.state, "Established");
        assert!(matches!(bgp_info.neighbor, BgpNeighbor::Address(x) if x == "172.29.0.1"));
        assert_eq!(bgp_info.neighbor_as, 64561);
        assert_eq!(bgp_info.local_as, 64560);

        let session = bgp_info
            .session
            .expect("expected bgp session to be defined");
        assert_eq!(session.neighbor_id, "172.29.0.1");
        assert_eq!(session.attributes, vec!["external", "AS4"]);
        assert_eq!(session.source_address, "172.29.0.12");
        assert_eq!(session.hold_time_remaining, 45.058);
        assert_eq!(session.hold_time, 90);
        assert_eq!(session.keepalive_time_remaining, 25.940);
        assert_eq!(session.keepalive_time, 30);
    }

    #[test]
    fn test_channel_parse() {
        let _ = env_logger::try_init();
        let lines = "
            Channel ipv4
              State:          UP
              Table:          master4
              Preference:     100
              Input filter:   ACCEPT
              Output filter:  (unnamed)
              Routes:         1 imported, 10 exported, 1 preferred
              Route change stats:     received   rejected   filtered    ignored   accepted
                Import updates:              7          1          2          3          1
                Import withdraws:            2          0        ---          0          2
                Export updates:             12          1          1        ---         10
                Export withdraws:            4        ---        ---        ---          4
              BGP Next hop:   172.29.0.1"
            .lines()
            .filter(|x| !x.trim().is_empty())
            .collect::<Vec<&str>>();
        let channel = Channel::from_lines(&lines).expect("failed to parse bgp info");
        assert_eq!(channel.name, "ipv4");
        assert_eq!(channel.table, "master4");
        assert_eq!(channel.preference, 100);
        assert_eq!(channel.input_filter, "ACCEPT");
        assert_eq!(channel.output_filter, "(unnamed)");

        let route_stats = &channel.route_stats.expect("route stats not defined");
        assert_eq!(route_stats.imported, 1);
        assert_eq!(route_stats.exported, 10);
        assert_eq!(route_stats.preferred, 1);
        assert_eq!(route_stats.filtered, 0);

        assert_eq!(route_stats.import_updates.received, 7);
        assert_eq!(route_stats.import_updates.rejected, 1);
        assert_eq!(route_stats.import_updates.filtered, 2);
        assert_eq!(route_stats.import_updates.ignored, 3);
        assert_eq!(route_stats.import_updates.accepted, 1);

        assert_eq!(route_stats.import_withdraws.received, 2);
        assert_eq!(route_stats.import_withdraws.rejected, 0);
        assert_eq!(route_stats.import_withdraws.ignored, 0);
        assert_eq!(route_stats.import_withdraws.accepted, 2);

        assert_eq!(route_stats.export_updates.received, 12);
        assert_eq!(route_stats.export_updates.rejected, 1);
        assert_eq!(route_stats.export_updates.filtered, 1);
        assert_eq!(route_stats.export_updates.accepted, 10);

        assert_eq!(route_stats.export_withdraws.received, 4);
        assert_eq!(route_stats.export_withdraws.accepted, 4);
    }

    #[test]
    fn test_proto_detail_parse() {
        let lines = "
            Description: BGP with internal router
            BGP state:          Established
              Neighbor address: 172.29.0.1
              Neighbor AS:      64561
              Local AS:         64560
              Neighbor ID:      172.29.0.1
              Local capabilities
                Multiprotocol
                  AF announced: ipv4
                Route refresh
                Graceful restart
                4-octet AS numbers
                Enhanced refresh
                Long-lived graceful restart
              Neighbor capabilities
                Multiprotocol
                  AF announced: ipv4
                Route refresh
                Graceful restart
                  Restart time: 10
                  AF supported: ipv4
                  AF preserved: ipv4
                4-octet AS numbers
                Long-lived graceful restart
              Session:          external AS4
              Source address:   172.29.0.12
              Hold timer:       45.058/90
              Keepalive timer:  25.940/30
            Channel ipv4
              State:          UP
              Table:          master4
              Preference:     100
              Input filter:   ACCEPT
              Output filter:  (unnamed)
              Routes:         1 imported, 10 exported, 1 preferred
              Route change stats:     received   rejected   filtered    ignored   accepted
                Import updates:              7          1          2          3          1
                Import withdraws:            2          0        ---          0          2
                Export updates:             12          1          1        ---         10
                Export withdraws:            4        ---        ---        ---          4
              BGP Next hop:   172.29.0.1"
            .lines()
            .filter(|x| !x.trim().is_empty())
            .collect::<Vec<&str>>();
        let base_indent = indent_level(lines[0]);
        let content = lines
            .iter()
            .map(|x| &x[(base_indent - 2)..])
            .collect::<Vec<&str>>()
            .join("\n");
        let pd = ProtocolDetail::from_enum(&Message::ProtocolDetails(content))
            .expect("parsing for protocol details failed");
        assert!(matches!(pd.description, Some(x) if x == "BGP with internal router"));
        assert!(pd.message.is_none());
        assert!(pd.router_id.is_none());
        assert!(pd.vrf.is_none());

        if let Some(ProtoSpecificInfo::Bgp(bgp_info)) = pd.proto_info {
            assert_eq!(bgp_info.state, "Established");
            assert!(matches!(bgp_info.neighbor, BgpNeighbor::Address(x) if x == "172.29.0.1"));
            assert_eq!(bgp_info.neighbor_as, 64561);
            assert_eq!(bgp_info.local_as, 64560);

            let session = bgp_info
                .session
                .expect("expected bgp session to be defined");
            assert_eq!(session.neighbor_id, "172.29.0.1");
            assert_eq!(session.attributes, vec!["external", "AS4"]);
            assert_eq!(session.source_address, "172.29.0.12");
            assert_eq!(session.hold_time_remaining, 45.058);
            assert_eq!(session.hold_time, 90);
            assert_eq!(session.keepalive_time_remaining, 25.940);
            assert_eq!(session.keepalive_time, 30);
        } else {
            panic!("bgp info parsing failed");
        }

        assert_eq!(pd.channels.len(), 1);

        let channel = &pd.channels[0];
        assert_eq!(channel.name, "ipv4");
        assert_eq!(channel.table, "master4");
        assert_eq!(channel.preference, 100);
        assert_eq!(channel.input_filter, "ACCEPT");
        assert_eq!(channel.output_filter, "(unnamed)");

        let route_stats = channel
            .route_stats
            .as_ref()
            .expect("route stats not defined");
        assert_eq!(route_stats.imported, 1);
        assert_eq!(route_stats.exported, 10);
        assert_eq!(route_stats.preferred, 1);
        assert_eq!(route_stats.filtered, 0);

        assert_eq!(route_stats.import_updates.received, 7);
        assert_eq!(route_stats.import_updates.rejected, 1);
        assert_eq!(route_stats.import_updates.filtered, 2);
        assert_eq!(route_stats.import_updates.ignored, 3);
        assert_eq!(route_stats.import_updates.accepted, 1);

        assert_eq!(route_stats.import_withdraws.received, 2);
        assert_eq!(route_stats.import_withdraws.rejected, 0);
        assert_eq!(route_stats.import_withdraws.ignored, 0);
        assert_eq!(route_stats.import_withdraws.accepted, 2);

        assert_eq!(route_stats.export_updates.received, 12);
        assert_eq!(route_stats.export_updates.rejected, 1);
        assert_eq!(route_stats.export_updates.filtered, 1);
        assert_eq!(route_stats.export_updates.accepted, 10);

        assert_eq!(route_stats.export_withdraws.received, 4);
        assert_eq!(route_stats.export_withdraws.accepted, 4);
    }
}
