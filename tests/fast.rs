//! Tags chosen as fast are read directly and often, on the collector's own
//! session, instead of waiting for the server to publish them.

mod common;

use common::{free_port, in_temp_dir, start_server, wait_until, Proxy, Recorder};
use opcua_tag_browser::opcua::server::prelude::{DateTime, NodeId};
use opcua_tag_browser::{Collector, ConnectOptions, MonitorOptions, TagSink};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn a_fast_tag_is_read_directly_on_the_same_session() {
    let dir = in_temp_dir("fast");
    let port = free_port();
    let server = start_server(&dir, port);
    let proxy = Proxy::start(port, None);

    let sink = Arc::new(Recorder::default());
    let collector = Collector::new("lab", format!("opc.tcp://127.0.0.2:{port}/"))
        .connect_options(ConnectOptions::insecure().session_retry_limit(0))
        .no_cache()
        .read_attributes(false)
        .monitor_options(MonitorOptions::default().fast_interval(Duration::from_millis(100)))
        .fast(|tag| tag.path.ends_with("Mode"))
        .shared_sink(sink.clone() as Arc<dyn TagSink>);
    let handle = collector.handle();
    let running = thread::spawn(move || collector.run());

    wait_until(Duration::from_secs(20), "both values", || {
        let values = sink.values.lock().unwrap();
        values.contains(&"7".to_string()) && values.contains(&"3".to_string())
    });
    assert_eq!(
        *sink.polled.lock().unwrap(),
        ["3"],
        "the fast tag is read, the other one subscribed"
    );

    let changed = Instant::now();
    let now = DateTime::now();
    let set = server.read().address_space().write().set_variable_value(
        NodeId::new(1, "Mode"),
        4i32,
        &now,
        &now,
    );
    assert!(set);
    wait_until(Duration::from_millis(500), "the new value", || {
        sink.polled.lock().unwrap().contains(&"4".to_string())
    });
    assert!(changed.elapsed() < Duration::from_millis(500));
    assert_eq!(
        proxy.open_connections(),
        1,
        "fast reads on the same session"
    );

    handle.stop();
    running.join().unwrap().unwrap();
    server.write().abort();
}
