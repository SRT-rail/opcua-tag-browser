//! A server that turned encryption on: `Security::Auto` follows it, and a
//! certificate other than the trusted one is refused before any session.

mod common;

use common::{free_port, in_temp_dir, wait_until, Recorder};
use opcua_tag_browser::opcua::server::prelude::{
    NodeId, Server, ServerBuilder, ServerEndpoint, Variable,
};
use opcua_tag_browser::opcua::sync::RwLock;
use opcua_tag_browser::{Collector, ConnectOptions, Error, Security, TagSink};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn start_encrypted_server(dir: &std::path::Path, port: u16) -> Arc<RwLock<Server>> {
    let server = ServerBuilder::new()
        .application_name("encrypted-test")
        .application_uri("urn:encrypted-test")
        .host_and_port("127.0.0.1", port)
        .discovery_urls(vec![format!("opc.tcp://127.0.0.1:{port}/")])
        .endpoint(
            "encrypted",
            ServerEndpoint::new_basic256sha256_sign_encrypt("/", &["ANONYMOUS".to_string()]),
        )
        .pki_dir(dir.join("server-pki"))
        .create_sample_keypair(true)
        .trust_client_certs()
        .server()
        .expect("a test server");
    {
        let address_space = server.address_space();
        let mut address_space = address_space.write();
        let folder = address_space
            .add_folder("Lab", "Lab", &NodeId::objects_folder_id())
            .unwrap();
        let _ = address_space.add_variables(
            vec![Variable::new(
                &NodeId::new(1, "Speed"),
                "Speed",
                "Speed",
                7i32,
            )],
            &folder,
        );
    }

    let server = Arc::new(RwLock::new(server));
    let running = server.clone();
    thread::spawn(move || Server::run_server(running));

    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the test server did not start");
        thread::sleep(Duration::from_millis(100));
    }
    server
}

fn options(dir: &std::path::Path) -> ConnectOptions {
    ConnectOptions::insecure()
        .security(Security::Auto)
        .pki_dir(dir.join("client-pki"))
        .session_retry_limit(0)
}

#[test]
fn auto_connects_encrypted_when_the_server_offers_only_encryption() {
    let dir = in_temp_dir("secured-auto");
    let port = free_port();
    let server = start_encrypted_server(&dir, port);

    let sink = Arc::new(Recorder::default());
    let collector = Collector::new("lab", format!("opc.tcp://127.0.0.1:{port}/"))
        .connect_options(options(&dir))
        .no_cache()
        .read_attributes(false)
        .shared_sink(sink.clone() as Arc<dyn TagSink>);
    let handle = collector.handle();
    let running = thread::spawn(move || collector.run());

    wait_until(Duration::from_secs(30), "a value", || {
        !sink.values.lock().unwrap().is_empty()
    });
    let info = handle
        .session()
        .and_then(|session| session.connection_info())
        .expect("what the session was opened with");
    assert_eq!(info.security, "SignAndEncrypt Basic256Sha256");
    assert!(info.server_certificate.is_some());
    assert!(opcua_tag_browser::client_certificate(&dir.join("client-pki")).is_some());

    handle.stop();
    running.join().unwrap().unwrap();
    server.write().abort();
}

#[test]
fn another_certificate_than_the_trusted_one_is_refused() {
    let dir = in_temp_dir("secured-pinned");
    let port = free_port();
    let server = start_encrypted_server(&dir, port);

    let refused = Collector::new("lab", format!("opc.tcp://127.0.0.1:{port}/"))
        .connect_options(options(&dir).server_certificate(Some("00".to_string())))
        .no_cache()
        .discover();

    assert!(
        matches!(refused, Err(Error::ServerCertificateChanged { .. })),
        "got {:?}",
        refused.map(|tags| tags.len())
    );
    server.write().abort();
}

#[test]
fn a_plain_endpoint_is_refused_when_encryption_is_asked_for() {
    let dir = in_temp_dir("secured-plain");
    let port = free_port();
    let server = common::start_server(&dir, port);

    let refused = Collector::new("lab", format!("opc.tcp://127.0.0.1:{port}/"))
        .connect_options(options(&dir).security(Security::Encrypted))
        .no_cache()
        .discover();

    assert!(
        matches!(refused, Err(Error::NoMatchingSecurity { .. })),
        "got {:?}",
        refused.map(|tags| tags.len())
    );
    server.write().abort();
}
