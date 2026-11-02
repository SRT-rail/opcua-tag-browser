//! Subscriptions and polling share one session, so a collector costs the
//! server one of its sessions, not two.

mod common;

use common::{free_port, in_temp_dir, start_server, wait_until, Proxy, Recorder};
use opcua_tag_browser::{Collector, ConnectOptions, MonitorOptions, TagSink};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn subscribing_and_polling_hold_one_connection() {
    let dir = in_temp_dir("one-session");
    let port = free_port();
    let server = start_server(&dir, port);
    let proxy = Proxy::start(port, None);

    let sink = Arc::new(Recorder::default());
    let collector = Collector::new("lab", format!("opc.tcp://127.0.0.2:{port}/"))
        .connect_options(ConnectOptions::insecure().session_retry_limit(0))
        .no_cache()
        .read_attributes(false)
        .monitor_options(MonitorOptions::default().max_subscribed_items(1))
        .shared_sink(sink.clone() as Arc<dyn TagSink>);
    let handle = collector.handle();
    let running = thread::spawn(move || collector.run());

    wait_until(Duration::from_secs(20), "both values", || {
        let values = sink.values.lock().unwrap();
        values.contains(&"7".to_string()) && values.contains(&"3".to_string())
    });
    assert_eq!(
        sink.polled.lock().unwrap().len(),
        1,
        "one tag subscribed, the other polled"
    );

    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            proxy.open_connections(),
            1,
            "subscriptions and polling on one session"
        );
    }

    handle.stop();
    running.join().unwrap().unwrap();
    wait_until(Duration::from_secs(5), "the connection closed", || {
        proxy.open_connections() == 0
    });
    server.write().abort();
}
