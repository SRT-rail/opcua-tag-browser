//! A running collector names itself to the server and knows the session id the server gave it.

mod common;

use common::{free_port, in_temp_dir, start_server, wait_until, Recorder};
use opcua_tag_browser::{Collector, ConnectOptions, TagSink};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn the_running_session_reports_the_id_the_server_gave_it() {
    let dir = in_temp_dir("session-identity");
    let port = free_port();
    let server = start_server(&dir, port);

    let sink = Arc::new(Recorder::default());
    let options = ConnectOptions::insecure()
        .session_retry_limit(0)
        .application_name("SRT HMI test panel 1")
        .application_uri("urn:srt:hmi:test:panel-1")
        .session_name("SRT HMI test panel 1");
    let collector = Collector::new("lab", format!("opc.tcp://127.0.0.1:{port}/"))
        .connect_options(options)
        .no_cache()
        .read_attributes(false)
        .shared_sink(sink.clone() as Arc<dyn TagSink>);
    let handle = collector.handle();
    let running = thread::spawn(move || collector.run());

    wait_until(Duration::from_secs(20), "a value", || {
        !sink.values.lock().unwrap().is_empty()
    });
    let info = handle
        .session()
        .and_then(|session| session.connection_info())
        .expect("what the session was opened with");
    assert!(!info.session_id.expect("the server's session id").is_empty());
    assert_eq!(info.security, "None");
    assert_eq!(info.user, None);

    handle.stop();
    running.join().unwrap().unwrap();
    server.write().abort();
}
