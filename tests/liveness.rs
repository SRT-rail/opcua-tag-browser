//! A session that stops delivering while the connection stays up is
//! replaced.

mod common;

use common::{free_port, in_temp_dir, start_server, wait_until, Proxy, Recorder};
use opcua_tag_browser::{Collector, ConnectOptions, MonitorOptions, TagSink};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn collector(endpoint: &str, sink: Arc<dyn TagSink>) -> Collector {
    Collector::new("lab", endpoint)
        .connect_options(ConnectOptions::insecure().session_retry_limit(0))
        .no_cache()
        .read_attributes(false)
        .monitor_options(
            MonitorOptions::default()
                .liveness_timeout(Duration::from_secs(4))
                .restart_backoff_min(Duration::from_millis(200)),
        )
        .shared_sink(sink)
}

#[test]
fn a_session_that_stops_delivering_is_replaced() {
    let dir = in_temp_dir("liveness");
    let port = free_port();
    let server = start_server(&dir, port);
    let proxy = Proxy::start(port, None);

    let sink = Arc::new(Recorder::default());
    let collector = collector(&format!("opc.tcp://127.0.0.2:{port}/"), sink.clone());
    let handle = collector.handle();
    let running = thread::spawn(move || collector.run());

    wait_until(Duration::from_secs(20), "connected", || {
        sink.count(true) == 1
    });
    wait_until(Duration::from_secs(5), "the first value", || {
        sink.values.lock().unwrap().contains(&"7".to_string())
    });

    thread::sleep(Duration::from_secs(8));
    assert_eq!(
        sink.count(false),
        0,
        "a quiet tag is not silence: the server clock keeps the session alive"
    );

    proxy.freeze_open_connections();
    let frozen = Instant::now();
    wait_until(Duration::from_secs(10), "reported disconnected", || {
        sink.count(false) == 1
    });
    assert!(
        frozen.elapsed() >= Duration::from_millis(1500),
        "not before the timeout, counted from the last delivery"
    );

    wait_until(
        Duration::from_secs(40),
        "connected again on a new session",
        || sink.count(true) == 2,
    );

    handle.stop();
    running.join().unwrap().unwrap();
    server.write().abort();
}
