//! A server that refuses: the collector says why, in plain words and without a panic.

mod common;

use common::{free_port, in_temp_dir};
use opcua_tag_browser::opcua::client::prelude::StatusCode;
use opcua_tag_browser::opcua::server::prelude::{
    Server, ServerBuilder, ServerEndpoint, ServerUserToken,
};
use opcua_tag_browser::opcua::sync::RwLock;
use opcua_tag_browser::{Collector, ConnectOptions, Error, Security};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn run(builder: ServerBuilder, port: u16) -> Arc<RwLock<Server>> {
    let server = Arc::new(RwLock::new(builder.server().expect("a test server")));
    let running = server.clone();
    thread::spawn(move || Server::run_server(running));

    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the test server did not start");
        thread::sleep(Duration::from_millis(100));
    }
    server
}

fn base(name: &str, dir: &std::path::Path, port: u16) -> ServerBuilder {
    ServerBuilder::new()
        .application_name(name)
        .application_uri(format!("urn:{name}"))
        .host_and_port("127.0.0.1", port)
        .discovery_urls(vec![format!("opc.tcp://127.0.0.1:{port}/")])
        .pki_dir(dir.join("server-pki"))
        .create_sample_keypair(true)
}

#[test]
fn a_server_without_guests_says_a_user_is_needed() {
    let dir = in_temp_dir("refused-guest");
    let port = free_port();
    let server = run(
        base("no-guest-test", &dir, port)
            .user_token("operator", ServerUserToken::user_pass("operator", "secret"))
            .endpoint(
                "none",
                ServerEndpoint::new_none("/", &["operator".to_string()]),
            )
            .trust_client_certs(),
        port,
    );

    let refused = Collector::new("lab", format!("opc.tcp://127.0.0.1:{port}/"))
        .connect_options(ConnectOptions::insecure().session_retry_limit(0))
        .no_cache()
        .discover();

    assert!(
        matches!(refused, Err(Error::UserRequired { .. })),
        "got {:?}",
        refused.map(|tags| tags.len())
    );
    server.write().abort();
}

#[test]
fn a_server_that_does_not_trust_this_client_gives_its_reason_not_a_panic() {
    let dir = in_temp_dir("refused-untrusted");
    let port = free_port();
    let server = run(
        base("untrusting-test", &dir, port).endpoint(
            "encrypted",
            ServerEndpoint::new_basic256sha256_sign_encrypt("/", &["ANONYMOUS".to_string()]),
        ),
        port,
    );

    let refused = Collector::new("lab", format!("opc.tcp://127.0.0.1:{port}/"))
        .connect_options(
            ConnectOptions::insecure()
                .security(Security::Auto)
                .pki_dir(dir.join("client-pki"))
                .session_retry_limit(0),
        )
        .no_cache()
        .discover();

    match refused {
        Err(Error::Connect { status, .. }) => assert_ne!(
            status,
            StatusCode::BadUnexpectedError,
            "the refusal became a panic and lost its reason"
        ),
        other => panic!(
            "a server that does not trust the client must refuse, got {:?}",
            other.map(|tags| tags.len())
        ),
    }
    server.write().abort();
}
