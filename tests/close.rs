//! Closing a session gives its connection back to the server.
//!
//! Runs a local server on a free port; the client keeps its `pki` folder in the
//! working directory, so the test moves to a temporary one first.

use opcua_tag_browser::opcua::client::prelude::Session;
use opcua_tag_browser::opcua::server::prelude::{Server, ServerBuilder};
use opcua_tag_browser::opcua::sync::RwLock;
use opcua_tag_browser::{catch_panic, connect, ConnectOptions, OpcUaSession, PlcSession};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn start_server(dir: &std::path::Path) -> (Arc<RwLock<Server>>, String) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server = ServerBuilder::new_anonymous("close-test")
        .application_uri("urn:close-test")
        .host_and_port("127.0.0.1", port)
        .discovery_urls(vec![format!("opc.tcp://127.0.0.1:{port}/")])
        .pki_dir(dir.join("server-pki"))
        .create_sample_keypair(true)
        .trust_client_certs()
        .server()
        .expect("a test server");

    let server = Arc::new(RwLock::new(server));
    let running = server.clone();
    std::thread::spawn(move || Server::run_server(running));

    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the test server did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    (server, format!("opc.tcp://127.0.0.1:{port}/"))
}

fn gone_within(raw: &Arc<RwLock<Session>>, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if !catch_panic(|| Ok(raw.read().is_connected())).unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn closing_a_session_releases_its_connection() {
    let dir = std::env::temp_dir().join(format!("otb-close-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_current_dir(&dir).unwrap();

    let (server, endpoint) = start_server(&dir);
    let options = ConnectOptions::insecure().session_retry_limit(0);

    // CloseSession alone: the server keeps the channel, and so the TCP connection.
    let raw = connect(&endpoint, &options).expect("a session");
    raw.read()
        .close_session_and_delete_subscriptions()
        .expect("session closed");
    assert!(
        !gone_within(&raw, Duration::from_secs(1)),
        "CloseSession alone keeps the connection"
    );

    // The crate's close releases it.
    let raw = connect(&endpoint, &options).expect("a session");
    let session = OpcUaSession::new(raw.clone());
    session
        .close_session_and_delete_subscriptions()
        .expect("session closed");
    assert!(
        gone_within(&raw, Duration::from_secs(3)),
        "the connection is released"
    );

    // Closing a session that is already gone is not a panic.
    let _ = session.close_session_and_delete_subscriptions();

    server.write().abort();
}
