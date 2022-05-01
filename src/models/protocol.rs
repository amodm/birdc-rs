//! Module for bird protocol objects

use crate::Message;

/// Represents one of the BIRD protocol instances. Note that this isn't the same
/// as, say BGP, or OSPF. That is represented by the field [Protocol::proto]
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

/// Simple helper to conver a filler `---` into a None
#[inline]
fn filler_to_option(s: &str) -> Option<String> {
    if s.trim_matches('-').is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
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
}
