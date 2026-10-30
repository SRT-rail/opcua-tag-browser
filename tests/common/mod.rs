//! A local server and a proxy in front of it.
//!
//! The server listens on 127.0.0.1 and the collector reaches it through the
//! proxy on 127.0.0.2 with the same port, so the server's endpoint still
//! matches. The proxy can freeze its open connections without closing them,
//! which is what a PLC that dropped the session looks like from the client,
//! and it counts the connections still open.

#![allow(dead_code)]

use opcua_tag_browser::opcua::server::prelude::{NodeId, Server, ServerBuilder, Variable};
use opcua_tag_browser::opcua::sync::RwLock;
use opcua_tag_browser::{ConnectionChange, TagChange, TagSink};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn start_server(dir: &std::path::Path, port: u16) -> Arc<RwLock<Server>> {
    let server = ServerBuilder::new_anonymous("liveness-test")
        .application_uri("urn:liveness-test")
        .host_and_port("127.0.0.1", port)
        .discovery_urls(vec![format!("opc.tcp://127.0.0.1:{port}/")])
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

pub type OnAccept = Box<dyn Fn() + Send>;

pub struct Proxy {
    accepted: Arc<AtomicUsize>,
    frozen_below: Arc<AtomicUsize>,
    open: Arc<AtomicUsize>,
}

impl Proxy {
    pub fn start(port: u16, on_accept: Option<OnAccept>) -> Self {
        let listener =
            TcpListener::bind(("127.0.0.2", port)).expect("127.0.0.2 is a loopback address");
        let proxy = Self {
            accepted: Arc::default(),
            frozen_below: Arc::default(),
            open: Arc::default(),
        };
        let (accepted, frozen_below, open) = (
            proxy.accepted.clone(),
            proxy.frozen_below.clone(),
            proxy.open.clone(),
        );

        thread::spawn(move || {
            for (id, client) in listener.incoming().enumerate() {
                let Ok(client) = client else { continue };
                if let Some(hook) = &on_accept {
                    hook();
                }
                let Ok(server) = TcpStream::connect(("127.0.0.1", port)) else {
                    continue;
                };
                accepted.store(id + 1, Ordering::SeqCst);
                open.fetch_add(1, Ordering::SeqCst);
                pump(
                    id,
                    client.try_clone().unwrap(),
                    server.try_clone().unwrap(),
                    &frozen_below,
                    Some(open.clone()),
                );
                pump(id, server, client, &frozen_below, None);
            }
        });
        proxy
    }

    pub fn freeze_open_connections(&self) {
        self.frozen_below
            .store(self.accepted.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    pub fn open_connections(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }
}

pub fn pump(
    id: usize,
    mut from: TcpStream,
    mut to: TcpStream,
    frozen_below: &Arc<AtomicUsize>,
    open: Option<Arc<AtomicUsize>>,
) {
    let frozen_below = frozen_below.clone();
    thread::spawn(move || {
        from.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            if id < frozen_below.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            match from.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if to.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
        let _ = to.shutdown(Shutdown::Both);
        if let Some(open) = open {
            open.fetch_sub(1, Ordering::SeqCst);
        }
    });
}

#[derive(Default)]
pub struct Recorder {
    pub connections: Mutex<Vec<bool>>,
    pub values: Mutex<Vec<String>>,
}

impl TagSink for Recorder {
    fn tag_changed(&self, event: &TagChange<'_>) {
        self.values.lock().unwrap().push(event.value.to_string());
    }

    fn connection_changed(&self, event: &ConnectionChange<'_>) {
        self.connections.lock().unwrap().push(event.connected);
    }
}

impl Recorder {
    pub fn count(&self, connected: bool) -> usize {
        self.connections
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == connected)
            .count()
    }
}

pub fn wait_until(limit: Duration, what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < deadline, "{what} within {limit:?}");
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn in_temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("otb-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_current_dir(&dir).unwrap();
    dir
}
