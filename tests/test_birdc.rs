//! Integration tests for birdc.
//!
//! For each test, we start a [MockServer], and exchange protocol data
//! with it to test

use birdc::*;

mod server;
use server::*;

macro_rules! test_sync_async_request {
    ($id:ident($mock:expr, $cmd:ident($( $params:expr ),*), $response:ident, $delay:literal) $test:block) => {
        #[tokio::test(flavor = "multi_thread")]
        async fn $id() {
            let _ = env_logger::try_init();
            let server = MockServer::start_server($mock, $delay)
                .await
                .expect("failed to start server");
            let client = Client::for_unix_socket(&server.unix_socket);
            let mut async_conn = client.connect().await.expect("failed to connect client");
            let $response = async_conn.$cmd($($params),*).await.expect("failed to send request");
            $test;

            let mut sync_conn = client.connect_sync().expect("failed to connect sync client");
            let $response = sync_conn.$cmd($($params),*).expect("failed to send sync request");
            $test;

            server.wait_until(1, 3).await;
        }
    };

    ($id:ident($mock:expr, $cmd:ident($( $params:expr ),*), $response:ident) $test:block) => {
        test_sync_async_request!($id($mock, $cmd($($params),*), $response, 0) $test);
    };

    ($id:ident($mock:expr, $request:literal, $response:ident, $delay:literal) $test:block) => {
        test_sync_async_request!($id($mock, send_request($request), $response, $delay) $test);
    };

    ($id:ident($mock:expr, $request:literal, $response:ident) $test:block) => {
        test_sync_async_request!($id($mock, $request, $response, 0) $test);
    }
}

/// This tests if the client open, and the greeting exchange works correctly
/// for a single client.
#[tokio::test(flavor = "multi_thread")]
async fn test_single_client_open() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server("", 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    client.connect().await.expect("failed to connect client");
    client
        .connect_sync()
        .expect("failed to connect sync client");
    server.wait_until(1, 3).await;
}

/// This tests if the client open, and the greeting exchange works correctly
/// for multiple clients simultaneously.
#[tokio::test]
async fn test_multiple_client_open() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server("", 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let results = tokio::join!(client.connect(), client.connect(), client.connect());
    assert!(results.0.is_ok());
    assert!(results.1.is_ok());
    assert!(results.2.is_ok());
    server.wait_until(1, 3).await;
}

// This tests if we receive the right sequence of response [Message]s from the
// server, upon a `show interfaces` command
test_sync_async_request!(
    test_raw_protocol(&get_test_text(), "show interfaces", response) {
        validate_show_interfaces_response(&response);
    }
);

// Tests for raw protocol, just like [test_raw_protocol], but the server
// sends response in delayed batches, to test buffering.
test_sync_async_request!(
    test_raw_protocol_with_delays(&get_test_text(), "show interfaces", response, 100) {
        validate_show_interfaces_response(&response);
    }
);

test_sync_async_request!(
    test_show_interfaces(&get_test_text(), show_interfaces(), response, 0) {
        assert_eq!(response.len(), 3);
    }
);

test_sync_async_request!(
    test_show_interfaces_summary(&get_interfaces_summary(), show_interfaces_summary(), response, 0) {
        assert_eq!(response.len(), 3);

        assert_eq!(response[0].name, "lo");
        assert_eq!(response[0].state, "up");
        assert!(matches!(&response[0].ipv4_address, Some(x) if x == "127.0.0.1/8"));
        assert!(matches!(&response[0].ipv6_address, Some(x) if x == "::1/128"));

        assert_eq!(response[1].name, "eth0");
        assert_eq!(response[1].state, "up");
        assert!(matches!(&response[1].ipv4_address, Some(x) if x == "172.30.0.12/16"));
        assert!(matches!(&response[1].ipv6_address, Some(x) if x == "fe80::4495:80ff:fe71:a791/64"));

        assert_eq!(response[2].name, "eth1");
        assert_eq!(response[2].state, "up");
        assert!(matches!(&response[2].ipv4_address, Some(x) if x == "169.254.199.2/30"));
        assert!(matches!(&response[2].ipv6_address, Some(x) if x == "fe80::a06f:7ff:fea7:c662/64"));
    }
);

test_sync_async_request!(
    test_show_protocols(&get_protocols(), show_protocols(None), protocol) {
        assert_eq!(protocol.len(), 9);

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
        assert_eq!(protocol[2].since, "2022-04-14 11:22:33");
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

        assert_eq!(protocol[7].name, "pipe6_kernel_main");
        assert_eq!(protocol[7].proto, "Pipe");
        assert!(protocol[7].table.is_none());
        assert_eq!(protocol[7].state, "up");
        assert_eq!(protocol[7].since, "2025-10-17");
        assert_eq!(protocol[7].info.as_ref().unwrap(), "table6_kernel_main <=> table6_meadow");

        assert_eq!(protocol[8].name, "pipe6_kernel_default");
        assert_eq!(protocol[8].proto, "Pipe");
        assert!(protocol[8].table.is_none());
        assert_eq!(protocol[8].state, "up");
        assert_eq!(protocol[8].since, "2025-10-17 08:18:58");
        assert_eq!(protocol[8].info.as_ref().unwrap(), "table6_kernel_default <=> table6_meadow");
    }
);

test_sync_async_request!(
    test_show_protocols_pattern(&get_protocols_only_kernel(), show_protocols(Some("kernel*")), protocol) {
        assert_eq!(protocol.len(), 2);

        assert_eq!(protocol[0].name, "kernel_v4");
        assert_eq!(protocol[0].proto, "Kernel");
        assert_eq!(protocol[0].table.as_ref().unwrap(), "master4");
        assert_eq!(protocol[0].state, "up");
        assert_eq!(protocol[0].since, "2022-04-14 11:22:33");
        assert!(protocol[0].info.is_none());

        assert_eq!(protocol[1].name, "kernel_v6");
        assert_eq!(protocol[1].proto, "Kernel");
        assert_eq!(protocol[1].table.as_ref().unwrap(), "master6");
        assert_eq!(protocol[1].state, "up");
        assert_eq!(protocol[1].since, "2022-04-14");
        assert!(protocol[1].info.is_none());
    }
);

test_sync_async_request!(
    test_show_protocols_all(&get_protocols_all(), show_protocols_details(None), protocols) {
        assert_eq!(protocols.len(), 7);

        assert_eq!(protocols[0].protocol.name, "device1");
        assert_eq!(protocols[0].protocol.proto, "Device");
        assert_eq!(protocols[0].protocol.state, "up");
        assert_eq!(protocols[0].protocol.since, "2022-04-14");
        assert!(protocols[0].detail.is_none());

        assert_eq!(protocols[1].protocol.name, "direct_eth0");
        assert_eq!(protocols[1].protocol.proto, "Direct");
        assert_eq!(protocols[1].protocol.state, "up");
        assert_eq!(protocols[1].protocol.since, "2022-04-14");
        let details = protocols[1]
            .detail
            .as_ref()
            .expect("detail should've been present");
        assert!(details.proto_info.is_none());
        assert_eq!(details.channels[0].name, "ipv4");
        assert_eq!(details.channels[0].state, "UP");
        assert_eq!(details.channels[0].table, "master4");
        assert_eq!(details.channels[1].name, "ipv6");
        assert_eq!(details.channels[1].state, "UP");
        assert_eq!(details.channels[1].table, "master6");

        assert_eq!(protocols[2].protocol.name, "kernel_v4");
        assert_eq!(protocols[2].protocol.proto, "Kernel");
        assert_eq!(protocols[2].protocol.state, "up");
        assert_eq!(protocols[2].protocol.since, "2022-04-14 11:22:33");
        let details = protocols[2]
            .detail
            .as_ref()
            .expect("detail should've been present");
        assert!(details.proto_info.is_none());
        assert_eq!(details.channels[0].name, "ipv4");
        assert_eq!(details.channels[0].state, "UP");
        assert_eq!(details.channels[0].table, "master4");

        assert_eq!(protocols[3].protocol.name, "kernel_v6");
        assert_eq!(protocols[3].protocol.proto, "Kernel");
        assert_eq!(protocols[3].protocol.state, "up");
        assert_eq!(protocols[3].protocol.since, "2022-04-14");
        let details = protocols[3]
            .detail
            .as_ref()
            .expect("detail should've been present");
        assert!(details.proto_info.is_none());
        assert_eq!(details.channels[0].name, "ipv6");
        assert_eq!(details.channels[0].state, "UP");
        assert_eq!(details.channels[0].table, "master6");

        assert_eq!(protocols[4].protocol.name, "bfd1");
        assert_eq!(protocols[4].protocol.proto, "BFD");
        assert_eq!(protocols[4].protocol.state, "up");
        assert_eq!(protocols[4].protocol.since, "2022-04-14");
        assert!(protocols[4].detail.is_none());

        assert_eq!(protocols[5].protocol.name, "bgp_r1_v4");
        assert_eq!(protocols[5].protocol.proto, "BGP");
        assert_eq!(protocols[5].protocol.state, "up");
        assert_eq!(protocols[5].protocol.since, "2022-04-14");
        let details = protocols[5]
            .detail
            .as_ref()
            .expect("detail should've been present");
        assert!(matches!(&details.description, Some(x) if x == "IPv4 BGP with internal router"));
        let ProtoSpecificInfo::Bgp(bgp_info) = details
            .proto_info
            .as_ref()
            .expect("proto info should've been present");
        assert_eq!(bgp_info.local_as, 64560);
        assert_eq!(bgp_info.neighbor_as, 64561);
        let bgp_session = bgp_info
            .session
            .as_ref()
            .expect("expected bgp session to be present");
        assert_eq!(bgp_session.neighbor_id, "172.29.0.1");
        assert_eq!(bgp_session.hold_time, 240);
        assert_eq!(bgp_session.keepalive_time, 80);
        assert_eq!(details.channels[0].name, "ipv4");
        assert_eq!(details.channels[0].state, "UP");
        let route_stats = details.channels[0]
            .route_stats
            .as_ref()
            .expect("route stats should've been present");
        assert_eq!(route_stats.imported, 1);
        assert_eq!(route_stats.exported, 0);

        assert_eq!(protocols[6].protocol.name, "bgp_r1_v6");
        assert_eq!(protocols[6].protocol.proto, "BGP");
        assert_eq!(protocols[6].protocol.state, "up");
        assert_eq!(protocols[6].protocol.since, "2022-04-14");
        let details = protocols[6]
            .detail
            .as_ref()
            .expect("detail should've been present");
        assert!(matches!(&details.description, Some(x) if x == "IPv6 BGP with internal router"));
        let ProtoSpecificInfo::Bgp(bgp_info) = details
            .proto_info
            .as_ref()
            .expect("proto info should've been present");
        assert_eq!(bgp_info.local_as, 64560);
        assert_eq!(bgp_info.neighbor_as, 64561);
        let bgp_session = bgp_info
            .session
            .as_ref()
            .expect("expected bgp session to be present");
        assert_eq!(bgp_session.neighbor_id, "172.29.0.1");
        assert_eq!(bgp_session.hold_time, 240);
        assert_eq!(bgp_session.keepalive_time, 80);
        assert_eq!(details.channels[0].name, "ipv6");
        assert_eq!(details.channels[0].state, "UP");
        let route_stats = details.channels[0]
            .route_stats
            .as_ref()
            .expect("route stats should've been present");
        assert_eq!(route_stats.imported, 1);
        assert_eq!(route_stats.exported, 0);
    }
);

test_sync_async_request!(
    test_show_status(&get_show_status(), show_status(), status) {
        assert_eq!(status.version_line, "BIRD 2.0.7");
        assert_eq!(status.router_id, "172.29.0.12");
        assert_eq!(status.server_time.to_string(), "2022-05-08 10:14:23.381");
        assert_eq!(status.last_reboot_on.to_string(), "2022-04-14 22:23:28.096");
        assert_eq!(
            status.last_reconfigured_on.to_string(),
            "2022-04-15 00:00:46.707",
        );
        assert_eq!(status.status, "Daemon is up and running");
    }
);

/// Validates response of `show interfaces` command
fn validate_show_interfaces_response(response: &[Message]) {
    // for device lo
    match &response[0] {
        Message::InterfaceList(s) => assert_eq!(s, "lo up (index=1)"),
        _ => panic!("was expecting Message::InterfaceList"),
    }
    match &response[1] {
        Message::InterfaceFlags(s) => {
            assert_eq!(s, "\tMultiAccess AdminUp LinkUp Loopback Ignored MTU=65536")
        }
        _ => panic!("was expecting Message::InterfaceFlags"),
    }
    match &response[2] {
        Message::InterfaceAddress(s) => assert_eq!(
            s,
            "\t127.0.0.1/8 (Preferred, scope host)\n\t::1/128 (Preferred, scope host)"
        ),
        _ => panic!("was expecting Message::InterfaceAddress"),
    }
    // for device eth0
    match &response[3] {
        Message::InterfaceList(s) => assert_eq!(s, "eth0 up (index=2)"),
        _ => panic!("was expecting Message::InterfaceList"),
    }
    match &response[4] {
        Message::InterfaceFlags(s) => assert_eq!(
            s,
            "\tMultiAccess Broadcast Multicast AdminUp LinkUp MTU=9000"
        ),
        _ => panic!("was expecting Message::InterfaceFlags"),
    }
    match &response[5] {
        Message::InterfaceAddress(s) => assert_eq!(
            s,
            "\t172.30.0.12/16 (Preferred, scope site)\n\t172.29.1.15/32 (scope univ)\n\t172.29.1.16/32 (scope univ)\n\t172.29.1.17/32 (scope univ)\n\tfe80::4495:80ff:fe71:a791/64 (Preferred, scope link)\n\tfe80::4490::72/64 (scope univ)"
        ),
        _ => panic!("was expecting Message::InterfaceAddress"),
    }
    // for device eth1
    match &response[6] {
        Message::InterfaceList(s) => assert_eq!(s, "eth1 up (index=3)"),
        _ => panic!("was expecting Message::InterfaceList"),
    }
    match &response[7] {
        Message::InterfaceFlags(s) => assert_eq!(
            s,
            "\tMultiAccess Broadcast Multicast AdminUp LinkUp MTU=1500"
        ),
        _ => panic!("was expecting Message::InterfaceFlags"),
    }
    match &response[8] {
        Message::InterfaceAddress(s) => assert_eq!(
            s,
            "\t169.254.199.2/30 (Preferred, opposite 169.254.199.1, scope univ)\n\tfe80::a06f:7ff:fea7:c662/64 (Preferred, scope link)\n\tfe80:169:254:199::2/126 (scope link)"
        ),
        _ => panic!("was expecting Message::InterfaceAddress"),
    }
}

fn get_test_text() -> String {
    heredoc(
        "1001-lo up (index=1)
        1004-\tMultiAccess AdminUp LinkUp Loopback Ignored MTU=65536
        1003-\t127.0.0.1/8 (Preferred, scope host)
         \t::1/128 (Preferred, scope host)
        1001-eth0 up (index=2)
        1004-\tMultiAccess Broadcast Multicast AdminUp LinkUp MTU=9000
        1003-\t172.30.0.12/16 (Preferred, scope site)
         \t172.29.1.15/32 (scope univ)
         \t172.29.1.16/32 (scope univ)
         \t172.29.1.17/32 (scope univ)
         \tfe80::4495:80ff:fe71:a791/64 (Preferred, scope link)
         \tfe80::4490::72/64 (scope univ)
        1001-eth1 up (index=3)
        1004-\tMultiAccess Broadcast Multicast AdminUp LinkUp MTU=1500
        1003-\t169.254.199.2/30 (Preferred, opposite 169.254.199.1, scope univ)
         \tfe80::a06f:7ff:fea7:c662/64 (Preferred, scope link)
         \tfe80:169:254:199::2/126 (scope link)
        0000 
        ",
    )
}

fn get_interfaces_summary() -> String {
    heredoc(
        "2005-Interface  State  IPv4 address       IPv6 address
        1005-lo         up     127.0.0.1/8        ::1/128
         eth0       up     172.30.0.12/16     fe80::4495:80ff:fe71:a791/64
         eth1       up     169.254.199.2/30   fe80::a06f:7ff:fea7:c662/64
        0000 
        ",
    )
}

fn get_show_status() -> String {
    heredoc(
        "1000-BIRD 2.0.7
        1011-Router ID is 172.29.0.12
         Current server time is 2022-05-08 10:14:23.381
         Last reboot on 2022-04-14 22:23:28.096
         Last reconfiguration on 2022-04-15 00:00:46.707
        0013 Daemon is up and running
        ",
    )
}

fn get_protocols() -> String {
    heredoc(
        "2002-Name       Proto      Table      State  Since         Info
        1002-device1    Device     ---        up     2022-04-14    
         direct_eth0 Direct     ---        up     2022-04-14    
         kernel_v4  Kernel     master4    up     2022-04-14 11:22:33    
         kernel_v6  Kernel     master6    up     2022-04-14    
         bfd1       BFD        ---        up     2022-04-14    
         bgp_local4 BGP        ---        up     2022-04-16    Established   
         bgp_local6 BGP        ---        up     2022-04-16    Established   
         pipe6_kernel_main Pipe       ---        up     2025-10-17    table6_kernel_main <=> table6_meadow
         pipe6_kernel_default Pipe       ---        up     2025-10-17 08:18:58  table6_kernel_default <=> table6_meadow
        0000 
        ",
    )
}

fn get_protocols_only_kernel() -> String {
    heredoc(
        "2002-Name       Proto      Table      State  Since         Info
        1002-kernel_v4  Kernel     master4    up     2022-04-14 11:22:33    
         kernel_v6  Kernel     master6    up     2022-04-14    
        0000 
        ",
    )
}

fn get_protocols_all() -> String {
    heredoc(
        "2002-Name       Proto      Table      State  Since         Info
        1002-device1    Device     ---        up     2022-04-14    
        1006-
        1002-direct_eth0 Direct     ---        up     2022-04-14    
        1006-  Channel ipv4
             State:          UP
             Table:          master4
             Preference:     240
             Input filter:   ACCEPT
             Output filter:  REJECT
             Routes:         7 imported, 0 exported, 7 preferred
             Route change stats:     received   rejected   filtered    ignored   accepted
               Import updates:              7          0          0          0          7
               Import withdraws:            0          0        ---          0          0
               Export updates:              0          0          0        ---          0
               Export withdraws:            0        ---        ---        ---          0
           Channel ipv6
             State:          UP
             Table:          master6
             Preference:     240
             Input filter:   ACCEPT
             Output filter:  REJECT
             Routes:         0 imported, 0 exported, 0 preferred
             Route change stats:     received   rejected   filtered    ignored   accepted
               Import updates:              3          0          0          1          2
               Import withdraws:            2          0        ---          0          2
               Export updates:              0          0          0        ---          0
               Export withdraws:            0        ---        ---        ---          0
         
        1002-kernel_v4  Kernel     master4    up     2022-04-14 11:22:33    
        1006-  Channel ipv4
             State:          UP
             Table:          master4
             Preference:     10
             Input filter:   REJECT
             Output filter:  save_to_kernel
             Routes:         0 imported, 2 exported, 0 preferred
             Route change stats:     received   rejected   filtered    ignored   accepted
               Import updates:              0          0          0          0          0
               Import withdraws:            0          0        ---          0          0
               Export updates:             20          0         14        ---          6
               Export withdraws:            4        ---        ---        ---          4
         
        1002-kernel_v6  Kernel     master6    up     2022-04-14    
        1006-  Channel ipv6
             State:          UP
             Table:          master6
             Preference:     10
             Input filter:   REJECT
             Output filter:  save_to_kernel
             Routes:         0 imported, 2 exported, 0 preferred
             Route change stats:     received   rejected   filtered    ignored   accepted
               Import updates:              0          0          0          0          0
               Import withdraws:            0          0        ---          0          0
               Export updates:             12          0          3        ---          9
               Export withdraws:            9        ---        ---        ---          7
         
        1002-bfd1       BFD        ---        up     2022-04-14    
        1006-
        1002-bgp_r1_v4 BGP        ---        up     2022-04-14    Established   
        1006-  Description:    IPv4 BGP with internal router
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
               4-octet AS numbers
               Enhanced refresh
               Long-lived graceful restart
             Session:          external AS4
             Source address:   172.29.0.12
             Hold timer:       207.832/240
             Keepalive timer:  48.076/80
           Channel ipv4
             State:          UP
             Table:          master4
             Preference:     100
             Input filter:   ACCEPT
             Output filter:  REJECT
             Routes:         1 imported, 0 exported, 1 preferred
             Route change stats:     received   rejected   filtered    ignored   accepted
               Import updates:              3          0          0          0          3
               Import withdraws:            2          0        ---          0          2
               Export updates:             13          3         10        ---          0
               Export withdraws:            4        ---        ---        ---          0
             BGP Next hop:   172.29.0.1
         
        1002-bgp_r1_v6 BGP        ---        up     2022-04-14    Established   
        1006-  Description:    IPv6 BGP with internal router
           BGP state:          Established
             Neighbor address: fe80:172:29::1%eth0
             Neighbor AS:      64561
             Local AS:         64560
             Neighbor ID:      172.29.0.1
             Local capabilities
               Multiprotocol
                 AF announced: ipv6
               Route refresh
               Graceful restart
               4-octet AS numbers
               Enhanced refresh
               Long-lived graceful restart
             Neighbor capabilities
               Multiprotocol
                 AF announced: ipv6
               Route refresh
               Graceful restart
               4-octet AS numbers
               Enhanced refresh
               Long-lived graceful restart
             Session:          external AS4
             Source address:   fe80:172:29::12
             Hold timer:       138.941/240
             Keepalive timer:  71.918/80
           Channel ipv6
             State:          UP
             Table:          master6
             Preference:     100
             Input filter:   ACCEPT
             Output filter:  REJECT
             Routes:         1 imported, 0 exported, 1 preferred
             Route change stats:     received   rejected   filtered    ignored   accepted
               Import updates:              7          1          2          3          1
               Import withdraws:            2          0        ---          0          2
               Export updates:             12          1          1        ---         10
               Export withdraws:            4        ---        ---        ---          4
             BGP Next hop:   :: fe80:172:29::1%eth0
         
        0000 
        ",
    )
}
