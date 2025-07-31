use chrono::NaiveDateTime;

use crate::Message;

pub struct ShowStatusMessage {
    /// Server version
    pub version_line: String,
    /// Router ID configured on this BIRD instance
    pub router_id: String,
    /// Current server time
    pub server_time: NaiveDateTime,
    /// Last reboot time
    pub last_reboot_on: NaiveDateTime,
    /// Last reconfiguration time
    pub last_reconfigured_on: NaiveDateTime,
    /// Status message
    pub status: String,
}

impl ShowStatusMessage {
    /// Parses `messages` to create a [ShowStatusMessage] object. Returns `None` if
    /// the parsing failed for any reason
    pub(crate) fn from_messages(messages: &Vec<Message>) -> Option<ShowStatusMessage> {
        let mut version_line: Option<String> = None;
        let mut router_id: Option<String> = None;
        let mut server_time: Option<NaiveDateTime> = None;
        let mut last_reboot_on: Option<NaiveDateTime> = None;
        let mut last_reconfigured_on: Option<NaiveDateTime> = None;
        let mut status: Option<String> = None;
        for msg in messages {
            match msg {
                Message::BirdVersion(v) => version_line = Some(v.clone()),
                Message::StatusReport(s) => status = Some(s.clone()),
                Message::Uptime(s) => {
                    let tfmt = "%Y-%m-%d %H:%M:%S%.3f";
                    for line in s.lines() {
                        if let Some(x) = line.strip_prefix("Router ID is ") {
                            router_id = Some(String::from(x));
                        } else if let Some(x) = line.strip_prefix("Current server time is ") {
                            if let Ok(dt) = NaiveDateTime::parse_from_str(x.trim(), tfmt) {
                                server_time = Some(dt);
                            } else {
                                log::error!("failed to parse timestamp {x}");
                                return None;
                            }
                        } else if let Some(x) = line.strip_prefix("Last reboot on ") {
                            if let Ok(dt) = NaiveDateTime::parse_from_str(x.trim(), tfmt) {
                                last_reboot_on = Some(dt);
                            } else {
                                log::error!("failed to parse timestamp {x}");
                                return None;
                            }
                        } else if let Some(x) = line.strip_prefix("Last reconfiguration on ") {
                            if let Ok(dt) = NaiveDateTime::parse_from_str(x.trim(), tfmt) {
                                last_reconfigured_on = Some(dt);
                            } else {
                                log::error!("failed to parse timestamp {x}");
                                return None;
                            }
                        }
                    }
                }
                _ => continue,
            }
        }
        if let Some(version_line) = version_line {
            if let Some(router_id) = router_id {
                if let Some(server_time) = server_time {
                    if let Some(last_reboot_on) = last_reboot_on {
                        if let Some(last_reconfigured_on) = last_reconfigured_on {
                            if let Some(status) = status {
                                return Some(ShowStatusMessage {
                                    version_line,
                                    router_id,
                                    server_time,
                                    last_reboot_on,
                                    last_reconfigured_on,
                                    status,
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status() {
        let _ = env_logger::try_init();
        let messages = vec![
            Message::BirdVersion("BIRD 2.0.7".into()),
            Message::Uptime("Router ID is 172.29.0.12\nCurrent server time is 2022-05-08 10:14:23.381\nLast reboot on 2022-04-14 22:23:28.096\nLast reconfiguration on 2022-04-15 00:00:46.707".into()),
            Message::StatusReport("Daemon is up and running".into()),
        ];
        if let Some(status) = ShowStatusMessage::from_messages(&messages) {
            assert_eq!(status.version_line, "BIRD 2.0.7");
            assert_eq!(status.router_id, "172.29.0.12");
            assert_eq!(status.server_time.to_string(), "2022-05-08 10:14:23.381");
            assert_eq!(status.last_reboot_on.to_string(), "2022-04-14 22:23:28.096");
            assert_eq!(
                status.last_reconfigured_on.to_string(),
                "2022-04-15 00:00:46.707",
            );
            assert_eq!(status.status, "Daemon is up and running");
        } else {
            panic!("failed to parse status");
        }
    }
}
