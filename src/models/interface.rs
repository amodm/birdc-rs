use crate::Message;

/// A network interface, as seen by Bird
#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub is_up: bool,
    pub index: u32,
    pub master: Option<String>,
}

impl Interface {
    /// Parse the response of a 1001 response. Returns None if `message` isn't a
    /// [Message::InterfaceList], or if we encounter an unrecoverable error during
    /// parsing.
    ///
    /// Details [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/iface.c)
    pub fn from_enum(message: &Message) -> Option<Self> {
        if let Message::InterfaceList(content) = message {
            let mut it = content.split_ascii_whitespace();

            // parse name - we eat up any failures
            let name = if let Some(s) = it.next() {
                s
            } else {
                log::error!("ifc: unable to determine name in {}", content);
                return None;
            };

            // parse state - we eat up any failures
            let is_up = if let Some(s) = it.next() {
                match s {
                    "up" => true,
                    "down" => false,
                    _ => {
                        log::error!("ifc: unknown state {}", s);
                        return None;
                    }
                }
            } else {
                log::error!("ifc: unable to determine state in {}", content);
                return None;
            };

            let mut index = -1_i32;
            let mut master: Option<String> = None;
            // parse things inside the brackets
            for s in it {
                let s = s.trim_matches(|c: char| c == '(' || c == ')' || c == ' ');
                if let Some(_idx) = s.strip_prefix("index=") {
                    index = _idx.parse().unwrap_or(-1);
                } else if let Some(ms) = s.strip_prefix("master=") {
                    master = Some(ms.to_owned());
                }
            }
            if index < 0 {
                log::error!("ifc: did not find an appropriate index in {}", content);
                return None;
            }

            Some(Self {
                name: name.into(),
                is_up,
                index: index as u32,
                master,
            })
        } else {
            log::error!("ifc: invoked Interface::from_enum on wrong message");
            None
        }
    }
}

/// Properties of an interface (flags, MTU) as seen by Bird
#[derive(Debug)]
pub struct InterfaceProperties {
    pub iftype: InterfaceType,
    flags: u32,
    pub mtu: u32,
}

impl InterfaceProperties {
    /// Parse the response of a 1004 response. Returns None if `message` isn't a
    /// [Message::InterfaceFlags], or if we encounter an unrecoverable error during
    /// parsing.
    ///
    /// Details [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/iface.c)
    pub fn from_enum(message: &Message) -> Option<Self> {
        if let Message::InterfaceFlags(content) = message {
            let mut it = content.split_ascii_whitespace();
            let mut flags = 0_u32;
            let mut mtu = 0;

            let iftype = if let Some(s) = it.next() {
                match s {
                    "PtP" => InterfaceType::PointToPoint,
                    "MultiAccess" => InterfaceType::MultiAccess,
                    _ => InterfaceType::Unknown(s.to_owned()),
                }
            } else {
                log::error!("ifc: did not find any iftype in {}", content);
                return None;
            };
            for token in content.split_ascii_whitespace() {
                if let Some(_mtu) = token.strip_prefix("MTU=") {
                    if let Ok(m) = _mtu.parse::<u32>() {
                        mtu = m;
                    } else {
                        log::error!("ifc: found invalid mtu in line {}", content);
                        return None;
                    }
                } else {
                    match token {
                        "Broadcast" => flags |= IF_FLAG_BROADCAST,
                        "Multicast" => flags |= IF_FLAG_MULTICAST,
                        "AdminUp" => flags |= IF_FLAG_ADMIN_UP,
                        "AdminDown" => flags &= !IF_FLAG_ADMIN_UP,
                        "LinkUp" => flags |= IF_FLAG_LINK_UP,
                        "LinkDown" => flags &= !IF_FLAG_LINK_UP,
                        "Loopback" => flags |= IF_FLAG_LOOPBACK,
                        "Ignored" => flags |= IF_FLAG_IGNORED,
                        _ => {}
                    }
                }
            }

            if mtu == 0 {
                log::error!("ifc: did not find any iftype in {}", content);
            }

            Some(InterfaceProperties { iftype, flags, mtu })
        } else {
            log::error!("ifc: invoked InterfaceProperties::from_enum on wrong message");
            None
        }
    }

    /// Interface has broadcast address set
    #[inline]
    pub fn is_broadcast_set(&self) -> bool {
        (self.flags & IF_FLAG_BROADCAST) != 0
    }

    /// Interface supports multicast
    #[inline]
    pub fn is_multicast_set(&self) -> bool {
        (self.flags & IF_FLAG_MULTICAST) != 0
    }

    /// Interface is up & running
    #[inline]
    pub fn is_admin_up(&self) -> bool {
        (self.flags & IF_FLAG_ADMIN_UP) != 0
    }

    /// Interface has its lower link up
    #[inline]
    pub fn is_link_up(&self) -> bool {
        (self.flags & IF_FLAG_LINK_UP) != 0
    }

    /// Interface is a loopback device
    #[inline]
    pub fn is_loopback(&self) -> bool {
        (self.flags & IF_FLAG_LOOPBACK) != 0
    }

    /// Interface is ignored by routing protocols
    #[inline]
    pub fn is_ignored_for_routing(&self) -> bool {
        (self.flags & IF_FLAG_IGNORED) != 0
    }
}

/// Type of interface
#[derive(Debug, PartialEq, Eq)]
pub enum InterfaceType {
    PointToPoint,
    MultiAccess,
    Unknown(String),
}

/// IP addresses assigned to an [Interface]
#[derive(Debug)]
pub struct InterfaceAddress {
    /// IP address, in address/prefix format
    pub ip: String,
    pub scope: String,
    /// Any extra information
    pub extra_info: Option<String>,
}

impl InterfaceAddress {
    /// Parse the response of a 1003 response. Returns None if `message` isn't a
    /// [Message::InterfaceAddress], or if we encounter an unrecoverable error during
    /// parsing.
    ///
    /// Details [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/iface.c)
    pub fn from_enum(message: &Message) -> Option<Vec<Self>> {
        let mut addresses = vec![];
        if let Message::InterfaceAddress(content) = message {
            for line in content.lines() {
                let mut it = line.split_ascii_whitespace();

                let mut scope = "undef";
                let mut extras = String::with_capacity(32);
                // process ip address and prefix length
                let ip = if let Some(s) = it.next() {
                    s
                } else {
                    log::error!("ifc: failed to find ip address in {}", line);
                    return None;
                };

                // process scope and extra info
                let bc = |c| c == '(' || c == ')' || c == ' ';
                while let Some(mut s) = it.next() {
                    s = s.trim_matches(bc);
                    if s == "scope" {
                        if let Some(sc) = it.next() {
                            scope = sc.trim_matches(bc).trim_matches(',');
                        } else {
                            log::error!("ifc: encountered scope but not value in {}", line);
                            return None;
                        }
                    } else {
                        if !extras.is_empty() {
                            extras.push(' ');
                        }
                        extras.push_str(s);
                    }
                }

                if !extras.is_empty() {
                    extras = extras.trim_matches(',').into();
                }

                addresses.push(InterfaceAddress {
                    ip: ip.into(),
                    scope: scope.into(),
                    extra_info: if extras.is_empty() {
                        None
                    } else {
                        Some(extras)
                    },
                })
            }

            Some(addresses)
        } else {
            log::error!("ifc: invoked InterfaceAddress::from_enum on wrong message");
            None
        }
    }
}

pub struct InterfaceSummary {
    pub name: String,
    pub state: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
}

impl InterfaceSummary {
    /// Parse the response of a 1005 response. Returns None if `message` isn't a
    /// [Message::InterfaceAddress], or if we encounter an unrecoverable error during
    /// parsing.
    ///
    /// Details [here](https://gitlab.nic.cz/labs/bird/-/blob/master/nest/iface.c)
    pub fn from_enum(message: &Message) -> Option<Vec<Self>> {
        if let Message::InterfaceSummary(content) = message {
            let mut entries: Vec<Self> = vec![];
            for line in content.lines() {
                let mut it = line.split_ascii_whitespace();
                let name: String = it.next()?.into();
                let state: String = it.next()?.into();
                let mut ipv4_address = None;
                let mut ipv6_address = None;

                for addr in it {
                    if addr.contains(':') {
                        ipv6_address = Some(addr.to_owned());
                    } else {
                        ipv4_address = Some(addr.to_owned());
                    }
                }

                entries.push(InterfaceSummary {
                    name,
                    state,
                    ipv4_address,
                    ipv6_address,
                })
            }
            Some(entries)
        } else {
            log::error!("ifc: invoked InterfaceSummary::from_enum on wrong message");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Message;

    #[test]
    #[ignore]
    fn test_invalid() {
        let _ = env_logger::try_init();
        assert!(
            Interface::from_enum(&Message::Ok).is_none(),
            "expected None from parsing invalid message type",
        );
    }

    #[test]
    fn test_interface_parsing_without_master() {
        let _ = env_logger::try_init();
        let message = Message::InterfaceList("eth0 up (index=2)".into());
        let ifc = Interface::from_enum(&message).expect("failed to parse");
        assert_eq!(ifc.name, "eth0");
        assert!(ifc.is_up);
        assert_eq!(ifc.index, 2);
        assert!(ifc.master.is_none(), "was not expecting master");
    }

    #[test]
    fn test_interface_parsing_with_master() {
        let _ = env_logger::try_init();
        let message = Message::InterfaceList("eth1 down (index=3 master=#2)".into());
        let ifc = Interface::from_enum(&message).expect("failed to parse");
        assert_eq!(ifc.name, "eth1");
        assert!(!ifc.is_up);
        assert_eq!(ifc.index, 3);
        assert_eq!(ifc.master.expect("was expecting master"), "#2");
    }

    #[test]
    fn test_interface_properties() {
        let _ = env_logger::try_init();
        let message = Message::InterfaceFlags(
            "MultiAccess Broadcast Multicast AdminDown LinkUp MTU=9000".into(),
        );
        let props = InterfaceProperties::from_enum(&message).expect("failed to parse");
        assert_eq!(props.iftype, InterfaceType::MultiAccess);
        assert_eq!(props.mtu, 9000);
        assert!(props.is_broadcast_set());
        assert!(props.is_multicast_set());
        assert!(!props.is_admin_up());
        assert!(props.is_link_up());
    }

    #[test]
    fn test_interface_address() {
        let _ = env_logger::try_init();
        let content = "\t172.30.0.12/16 (Preferred, scope site)\n\t172.29.1.15/32 (scope univ)\n\t172.29.1.16/32 (scope univ)\n\t172.29.1.17/32 (scope univ)\n\tfe80::4495:80ff:fe71:a791/64 (Preferred, scope link)\n\tfe80::4490::72/64 (scope univ)";
        let message = Message::InterfaceAddress(content.into());
        let addresses = InterfaceAddress::from_enum(&message).expect("failed to parse");
        validate_address(&addresses[0], "172.30.0.12/16", "site", "Preferred");
        validate_address(&addresses[1], "172.29.1.15/32", "univ", "");
        validate_address(&addresses[2], "172.29.1.16/32", "univ", "");
        validate_address(&addresses[3], "172.29.1.17/32", "univ", "");
        validate_address(
            &addresses[4],
            "fe80::4495:80ff:fe71:a791/64",
            "link",
            "Preferred",
        );
        validate_address(&addresses[5], "fe80::4490::72/64", "univ", "");
    }

    #[test]
    fn test_interface_summary() {
        let _ = env_logger::try_init();
        let content = "lo         up     127.0.0.1/8        ::1/128\neth0       up     172.30.0.12/16     fe80::4495:80ff:fe71:a791/64\neth1       up     169.254.199.2/30";
        let message = Message::InterfaceSummary(content.into());
        let summaries = InterfaceSummary::from_enum(&message).expect("failed to parse");

        assert_eq!(summaries[0].name, "lo");
        assert_eq!(summaries[0].state, "up");
        assert_eq!(summaries[0].ipv4_address.as_ref().unwrap(), "127.0.0.1/8");
        assert_eq!(summaries[0].ipv6_address.as_ref().unwrap(), "::1/128");

        assert_eq!(summaries[1].name, "eth0");
        assert_eq!(summaries[1].state, "up");
        assert_eq!(
            summaries[1].ipv4_address.as_ref().unwrap(),
            "172.30.0.12/16",
        );
        assert_eq!(
            summaries[1].ipv6_address.as_ref().unwrap(),
            "fe80::4495:80ff:fe71:a791/64",
        );

        assert_eq!(summaries[2].name, "eth1");
        assert_eq!(summaries[2].state, "up");
        assert_eq!(
            summaries[2].ipv4_address.as_ref().unwrap(),
            "169.254.199.2/30",
        );
        assert!(summaries[2].ipv6_address.is_none());
    }

    fn validate_address(address: &InterfaceAddress, ip: &str, scope: &str, extras: &str) {
        assert_eq!(address.ip, ip);
        assert_eq!(address.scope, scope);
        if let Some(ref ei) = address.extra_info {
            assert_eq!(ei, extras)
        } else {
            assert_eq!(extras, "", "expected empty extra_info");
        }
    }
}

/// Valid broadcast address set
const IF_FLAG_BROADCAST: u32 = 1 << 2;
/// Supports multicast
const IF_FLAG_MULTICAST: u32 = 1 << 3;
/// Is a loopback device
const IF_FLAG_LOOPBACK: u32 = 1 << 5;
/// Not to be used by routing protocols (loopbacks etc.)
const IF_FLAG_IGNORED: u32 = 1 << 6;
/// Interface is running
const IF_FLAG_ADMIN_UP: u32 = 1 << 7;
/// L1 layer is up
const IF_FLAG_LINK_UP: u32 = 1 << 8;
