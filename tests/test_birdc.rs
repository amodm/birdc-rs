//! Integration tests for birdc.
//!
//! For each test, we start a [MockServer], and exchange protocol data
//! with it to test

use birdc::*;

mod server;
use server::*;

/// This tests if the client open, and the greeting exchange works correctly
/// for a single client.
#[tokio::test]
async fn test_single_client_open() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server("", 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    client.connect().await.expect("failed to connect client");
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

/// This tests if we receive the right sequence of response [Message]s from the
/// server, upon a `show interfaces` command
#[tokio::test]
async fn test_raw_protocol() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server(&get_test_text(), 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let mut connection = client.connect().await.expect("failed to connect client");
    let response = connection
        .send_request("show interfaces")
        .await
        .expect("failed to send request");
    validate_show_interfaces_response(&response);

    server.wait_until(1, 3).await;
}

/// Tests for raw protocol, just like [test_raw_protocol], but the server
/// sends response in delayed batches, to test buffering.
#[tokio::test]
async fn test_raw_protocol_with_delays() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server(&get_test_text(), 100)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let mut connection = client.connect().await.expect("failed to connect client");
    let response = connection
        .send_request("show interfaces")
        .await
        .expect("failed to send request");
    validate_show_interfaces_response(&response);

    server.wait_until(1, 3).await;
}

#[tokio::test]
async fn test_show_interfaces() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server(&get_test_text(), 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let mut connection = client.connect().await.expect("failed to connect client");
    let response = connection
        .show_interfaces()
        .await
        .expect("failed to parse response");
    assert_eq!(response.len(), 3);

    server.wait_until(1, 3).await;
}

#[tokio::test]
async fn test_show_interfaces_summary() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server(&get_interfaces_summary(), 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let mut connection = client.connect().await.expect("failed to connect client");
    let response = connection
        .show_interfaces_summary()
        .await
        .expect("failed to parse response");
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

    server.wait_until(1, 3).await;
}

#[tokio::test]
async fn test_show_protocols() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server(&get_protocols(), 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let mut connection = client.connect().await.expect("failed to connect client");
    let protocol = connection
        .show_protocols(None)
        .await
        .expect("failed to parse response");

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

#[tokio::test]
async fn test_show_protocols_pattern() {
    let _ = env_logger::try_init();
    let server = MockServer::start_server(&get_protocols_only_kernel(), 0)
        .await
        .expect("failed to start server");
    let client = Client::for_unix_socket(&server.unix_socket);
    let mut connection = client.connect().await.expect("failed to connect client");
    let protocol = connection
        .show_protocols(Some("kernel*"))
        .await
        .expect("failed to parse response");

    assert_eq!(protocol.len(), 2);

    assert_eq!(protocol[0].name, "kernel_v4");
    assert_eq!(protocol[0].proto, "Kernel");
    assert_eq!(protocol[0].table.as_ref().unwrap(), "master4");
    assert_eq!(protocol[0].state, "up");
    assert_eq!(protocol[0].since, "2022-04-14");
    assert!(protocol[0].info.is_none());

    assert_eq!(protocol[1].name, "kernel_v6");
    assert_eq!(protocol[1].proto, "Kernel");
    assert_eq!(protocol[1].table.as_ref().unwrap(), "master6");
    assert_eq!(protocol[1].state, "up");
    assert_eq!(protocol[1].since, "2022-04-14");
    assert!(protocol[1].info.is_none());
}

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
        Message::InterfaceAddress(s) => assert_eq!(s, "\t172.30.0.12/16 (Preferred, scope site)\n\t172.29.1.15/32 (scope univ)\n\t172.29.1.16/32 (scope univ)\n\t172.29.1.17/32 (scope univ)\n\tfe80::4495:80ff:fe71:a791/64 (Preferred, scope link)\n\tfe80::4490::72/64 (scope univ)"),
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
        Message::InterfaceAddress(s) => assert_eq!(s, "\t169.254.199.2/30 (Preferred, opposite 169.254.199.1, scope univ)\n\tfe80::a06f:7ff:fea7:c662/64 (Preferred, scope link)\n\tfe80:169:254:199::2/126 (scope link)"),
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

fn get_protocols() -> String {
    heredoc(
        "2002-Name       Proto      Table      State  Since         Info
        1002-device1    Device     ---        up     2022-04-14    
         direct_eth0 Direct     ---        up     2022-04-14    
         kernel_v4  Kernel     master4    up     2022-04-14    
         kernel_v6  Kernel     master6    up     2022-04-14    
         bfd1       BFD        ---        up     2022-04-14    
         bgp_local4 BGP        ---        up     2022-04-16    Established   
         bgp_local6 BGP        ---        up     2022-04-16    Established   
        0000 
        ",
    )
}

fn get_protocols_only_kernel() -> String {
    heredoc(
        "2002-Name       Proto      Table      State  Since         Info
        1002-kernel_v4  Kernel     master4    up     2022-04-14    
         kernel_v6  Kernel     master6    up     2022-04-14    
        0000 
        ",
    )
}
