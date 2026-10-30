//! A stop that lands while connecting leaves no session open.

mod common;

use common::{free_port, in_temp_dir, start_server, wait_until, Proxy, Recorder};
use opcua_tag_browser::{Collector, CollectorHandle, ConnectOptions, TagSink};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn collector(endpoint: &str, sink: Arc<dyn TagSink>) -> Collector {
    Collector::new("lab", endpoint)
        .connect_options(ConnectOptions::insecure().session_retry_limit(0))
        .no_cache()
        .read_attributes(false)
        .shared_sink(sink)
}

#[test]
fn a_stop_while_connecting_leaves_no_session_open() {
    let dir = in_temp_dir("stop-connecting");
    let port = free_port();
    let server = start_server(&dir, port);

    let slot: Arc<Mutex<Option<CollectorHandle>>> = Arc::default();
    let stopper = slot.clone();
    let proxy = Proxy::start(
        port,
        Some(Box::new(move || {
            if let Some(handle) = stopper.lock().unwrap().as_ref() {
                handle.stop();
            }
        })),
    );

    let sink = Arc::new(Recorder::default());
    let collector = collector(&format!("opc.tcp://127.0.0.2:{port}/"), sink.clone());
    *slot.lock().unwrap() = Some(collector.handle());

    collector.run().expect("a stop is not an error");

    wait_until(Duration::from_secs(5), "every connection closed", || {
        proxy.open_connections() == 0
    });
    assert_eq!(sink.count(true), 0, "never reported connected");
    server.write().abort();
}
