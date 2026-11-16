//! One PLC, end to end.

use crate::backoff::{sleep_interruptible, Backoff};
use crate::browser::OpcUaNodeBrowser;
use crate::connection::ConnectOptions;
use crate::error::{Error, Result};
use crate::filter::{DefaultNodeFilter, NodeFilter};
use crate::live::LiveSession;
use crate::monitor::{spawn_watchdog, Liveness, MonitorOptions, Poller, Subscribed, Subscriber};
use crate::scanner::{ScanOptions, TreeScanner};
use crate::session::PlcSession;
use crate::sink::{ConnectionChange, TagSink};
use crate::tag::PlcTag;
use crate::tagset::{glob_match, TagSet};
#[cfg(feature = "write")]
use crate::writer::TagClient;
use opcua::client::prelude::NodeId;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

#[cfg(feature = "json-cache")]
use crate::repository::TagRepository;

type Registry = Arc<Mutex<Vec<(String, Arc<dyn PlcSession>)>>>;
type Selector = Box<dyn Fn(&PlcTag) -> bool + Send + Sync>;
/// One session, both as itself and as the [`PlcSession`] scanning and polling use.
type OpenSession = (Arc<LiveSession>, Arc<dyn PlcSession>);

/// Connects to one PLC, discovers its tags, and streams every change to a sink.
///
/// Subscribes as many tags as the server will monitor, polls the rest, and
/// reconnects on its own when the link drops.
///
/// ```no_run
/// use opcua_tag_browser::{Collector, TagChange};
///
/// # fn main() -> opcua_tag_browser::Result<()> {
/// Collector::new("line1", "opc.tcp://192.168.201.2:4840")
///     .insecure()
///     .matching("Machine/Axis*")
///     .sink(|e: &TagChange<'_>| println!("{} = {}", e.path(), e.value))
///     .run()
/// # }
/// ```
pub struct Collector {
    name: String,
    endpoint_url: String,
    sink: Option<Arc<dyn TagSink>>,
    #[cfg(feature = "json-cache")]
    cache: Option<Arc<dyn TagRepository + Send + Sync>>,
    filter: Arc<dyn NodeFilter + Send + Sync>,
    selector: Option<Selector>,
    fast: Option<Selector>,
    poll: Option<Selector>,
    scan_options: ScanOptions,
    connect_options: ConnectOptions,
    monitor_options: MonitorOptions,
    force_rescan: AtomicBool,
    read_attributes: bool,
    resilient: bool,
    deferred_error: Option<Error>,
    stop: Arc<AtomicBool>,
    sessions: Registry,
    subscribed_last_seen: Arc<Mutex<std::collections::HashMap<String, (String, String)>>>,
}

impl Collector {
    /// Creates a collector for one endpoint.
    ///
    /// Tags are cached in `plc_tags_<name>.json` by default; override with
    /// [`cache_file`](Self::cache_file) or disable with [`no_cache`](Self::no_cache).
    pub fn new(name: impl Into<String>, endpoint_url: impl Into<String>) -> Self {
        let name = name.into();

        Self {
            #[cfg(feature = "json-cache")]
            cache: Some(Arc::new(crate::repository::JsonFileTagRepository::new(
                format!("plc_tags_{name}.json"),
            ))),
            endpoint_url: endpoint_url.into(),
            name,
            sink: None,
            filter: Arc::new(DefaultNodeFilter),
            selector: None,
            fast: None,
            poll: None,
            scan_options: ScanOptions::default(),
            connect_options: ConnectOptions::default(),
            monitor_options: MonitorOptions::default(),
            force_rescan: AtomicBool::new(false),
            read_attributes: true,
            resilient: true,
            deferred_error: None,
            stop: Arc::new(AtomicBool::new(false)),
            sessions: Arc::new(Mutex::new(Vec::new())),
            subscribed_last_seen: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Sets where observed changes are delivered. Required unless
    /// [`jsonl`](Self::jsonl) is used.
    ///
    /// A closure taking `&TagChange` works directly.
    pub fn sink(mut self, sink: impl TagSink + 'static) -> Self {
        self.sink = Some(Arc::new(sink));
        self
    }

    /// Sets a sink shared with other collectors.
    pub fn shared_sink(mut self, sink: Arc<dyn TagSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Writes changes to daily JSONL files in `dir`.
    ///
    /// A directory error is deferred to [`run`](Self::run) so the chain reads
    /// cleanly.
    #[cfg(feature = "jsonl-sink")]
    pub fn jsonl(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        match crate::sinks::JsonlSink::new(dir) {
            Ok(sink) => self.sink = Some(Arc::new(sink)),
            Err(e) => self.deferred_error = Some(Error::SinkSetup(e.to_string())),
        }
        self
    }

    /// Monitors only the named tags, by browse path or display name.
    ///
    /// Selecting fewer tags than the server's monitored-item ceiling means
    /// everything arrives by subscription and polling never engages.
    pub fn only(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let wanted: Vec<String> = names.into_iter().map(Into::into).collect();
        self.selector = Some(Box::new(move |tag| {
            wanted
                .iter()
                .any(|w| w == &tag.path || w == &tag.display_name)
        }));
        self
    }

    /// Monitors only tags whose browse path matches a glob.
    ///
    /// `*` matches any run of characters, `?` matches one.
    pub fn matching(mut self, pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        self.selector = Some(Box::new(move |tag| glob_match(&pattern, &tag.path)));
        self
    }

    /// Monitors only tags satisfying a predicate.
    pub fn select(mut self, predicate: impl Fn(&PlcTag) -> bool + Send + Sync + 'static) -> Self {
        self.selector = Some(Box::new(predicate));
        self
    }

    /// Reads the tags satisfying a predicate directly, every
    /// [`MonitorOptions::fast_interval`], instead of subscribing to them.
    ///
    /// A server pushes subscription changes no more often than its own
    /// minimum publishing interval, often once a second. For a value that has
    /// to look live, such as an engine speed, read it directly instead. The
    /// reads go through the collector's session and are reported as
    /// [`Source::Poll`](crate::Source::Poll). Keep the list short: each of
    /// these tags is read about ten times a second.
    pub fn fast(mut self, predicate: impl Fn(&PlcTag) -> bool + Send + Sync + 'static) -> Self {
        self.fast = Some(Box::new(predicate));
        self
    }

    /// Polls the tags satisfying a predicate and never subscribes to them.
    ///
    /// A server monitors a limited number of items for all its clients
    /// together. Tags that nobody watches closely can be left to polling, so
    /// the subscriptions keep room for the ones that matter.
    pub fn poll(mut self, predicate: impl Fn(&PlcTag) -> bool + Send + Sync + 'static) -> Self {
        self.poll = Some(Box::new(predicate));
        self
    }

    /// Connects without encryption or authentication, trusting any certificate.
    ///
    /// Shorthand for `connect_options(ConnectOptions::insecure())`. Appropriate
    /// on an isolated machine network with no PKI; naming it keeps the choice
    /// visible in your source.
    pub fn insecure(mut self) -> Self {
        self.connect_options = ConnectOptions::insecure();
        self
    }

    /// Overrides connection and security settings.
    pub fn connect_options(mut self, options: ConnectOptions) -> Self {
        self.connect_options = options;
        self
    }

    /// Caches the scanned tag list in a JSON file.
    #[cfg(feature = "json-cache")]
    pub fn cache_file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.cache = Some(Arc::new(crate::repository::JsonFileTagRepository::new(
            path,
        )));
        self
    }

    /// Caches the scanned tag list somewhere of your choosing.
    #[cfg(feature = "json-cache")]
    pub fn cache(mut self, repo: Arc<dyn TagRepository + Send + Sync>) -> Self {
        self.cache = Some(repo);
        self
    }

    /// Disables caching; every start rescans the address space.
    #[cfg(feature = "json-cache")]
    pub fn no_cache(mut self) -> Self {
        self.cache = None;
        self
    }

    /// Ignores any cached tag list and rescans once.
    pub fn force_rescan(mut self, yes: bool) -> Self {
        self.force_rescan = AtomicBool::new(yes);
        self
    }

    /// Sets whether a fresh scan reads each tag's `DataType`, `ValueRank`,
    /// `AccessLevel`, `MinimumSamplingInterval`, and `Historizing` attributes.
    ///
    /// On by default. These come from a `Read` pass separate from the
    /// `Browse` that discovers tags, so turning this off skips one extra
    /// round trip per scan at the cost of leaving [`PlcTag`]'s attribute
    /// fields `None`. Has no effect when tags are loaded from cache.
    pub fn read_attributes(mut self, yes: bool) -> Self {
        self.read_attributes = yes;
        self
    }

    /// Sets whether `run()` restarts automatically when a run attempt ends
    /// for a reason other than `CollectorHandle::stop`.
    ///
    /// On by default. A run attempt can end because the underlying `opcua`
    /// session exhausted its reconnect budget
    /// ([`ConnectOptions::session_retry_limit`]), or because of an internal
    /// panic caught at the boundary. With `resilient` on, `Collector` treats
    /// that the same way the poller already treats a dropped polling
    /// session: log it, back off
    /// ([`MonitorOptions::restart_backoff_min`]/`restart_backoff_max`), and
    /// try again — a fresh connect, a fresh scan-or-cache-load, fresh
    /// subscriptions — until `CollectorHandle::stop` is called or the failure
    /// is one retrying cannot fix (bad credentials, a client that cannot be
    /// built at all).
    ///
    /// Turn this off to get the old behavior: `run()` returns on the first
    /// such failure.
    pub fn resilient(mut self, yes: bool) -> Self {
        self.resilient = yes;
        self
    }

    /// Replaces the node filter applied during scanning.
    pub fn filter(mut self, filter: Arc<dyn NodeFilter + Send + Sync>) -> Self {
        self.filter = filter;
        self
    }

    /// Overrides scan tuning.
    pub fn scan_options(mut self, options: ScanOptions) -> Self {
        self.scan_options = options;
        self
    }

    /// Overrides subscription and polling tuning.
    pub fn monitor_options(mut self, options: MonitorOptions) -> Self {
        self.monitor_options = options;
        self
    }

    /// Returns a handle for stopping this collector from another thread.
    ///
    /// Take it before [`run`](Self::run), which consumes the collector.
    pub fn handle(&self) -> CollectorHandle {
        CollectorHandle {
            name: self.name.clone(),
            stop: self.stop.clone(),
            sessions: self.sessions.clone(),
        }
    }

    /// Stops this collector cleanly on Ctrl+C.
    ///
    /// Installs a process-wide signal handler, so call it from a binary that
    /// owns the process. Inside a larger application, take a
    /// [`handle`](Self::handle) and wire it into your own instead.
    #[cfg(feature = "ctrl-c")]
    pub fn handle_ctrl_c(self) -> Self {
        let handle = self.handle();
        if let Err(e) = ctrlc::set_handler(move || handle.stop()) {
            log::warn!("could not install Ctrl+C handler: {e}");
        }
        self
    }

    /// Scans the address space and returns the tags, without monitoring them.
    pub fn discover(&self) -> Result<TagSet> {
        if let Some(e) = &self.deferred_error {
            return Err(Error::SinkSetup(e.to_string()));
        }
        let (_, session) = self.open("discover")?;
        self.load_or_scan(session)
    }

    /// Opens a session for reading and writing individual tags.
    ///
    /// The returned client is independent of [`run`](Self::run) and usable on
    /// its own.
    ///
    /// ```no_run
    /// # use opcua_tag_browser::Collector;
    /// # fn main() -> opcua_tag_browser::Result<()> {
    /// let plc = Collector::new("line1", "opc.tcp://192.168.201.2:4840")
    ///     .insecure()
    ///     .client()?;
    ///
    /// plc.set("Machine/Axis1/Setpoint", 1500.0)?;
    /// println!("{}", plc.get("Machine/Axis1/Speed")?);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "write")]
    pub fn client(&self) -> Result<TagClient> {
        let (_, session) = self.open(&format!("{}-client", self.name))?;
        let tags = self.load_or_scan(session.clone())?;
        Ok(TagClient::new(session, Arc::new(tags)))
    }

    /// Runs until stopped. Blocks the calling thread.
    ///
    /// With [`resilient`](Self::resilient) on (the default), a run attempt
    /// that ends for any recoverable reason is retried with backoff instead
    /// of returning — see that method for exactly what counts as
    /// recoverable. `run()` then only returns via `CollectorHandle::stop`, or
    /// immediately on a non-recoverable setup error.
    pub fn run(mut self) -> Result<()> {
        if let Some(e) = self.deferred_error.take() {
            return Err(e);
        }

        let sink = self.sink.clone().ok_or(Error::MissingSink)?;

        if !self.resilient {
            return self.run_attempt(&sink);
        }

        let mut backoff = Backoff::new(
            self.monitor_options.restart_backoff_min,
            self.monitor_options.restart_backoff_max,
        );

        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Ok(());
            }

            let attempt_started = std::time::Instant::now();

            match self.run_attempt(&sink) {
                Ok(()) => {
                    return Ok(());
                }
                Err(e) if !e.is_recoverable() => {
                    log::error!("[{}] {e}, not retrying", self.name);
                    return Err(e);
                }
                Err(e) => {
                    if self.stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }

                    if attempt_started.elapsed() >= self.monitor_options.restart_backoff_max {
                        backoff.reset();
                    }

                    if e.server_full() {
                        let delay = self.monitor_options.server_full_wait;
                        log::warn!(
                            "[{}] {e}: the server has no room for another session, asking again in {} s",
                            self.name,
                            delay.as_secs()
                        );
                        sleep_interruptible(delay, &self.stop);
                        continue;
                    }

                    let delay = backoff.next();
                    log::error!("[{}] {e}, restarting in {}ms", self.name, delay.as_millis());
                    sleep_interruptible(delay, &self.stop);
                }
            }
        }
    }

    /// Connects, discovers tags, subscribes and polls, and blocks until the
    /// session ends — by request, by giving up on reconnecting, or by panic.
    ///
    /// Every background thread spawned here (watchdog, poller) is scoped to
    /// this attempt via `attempt_stop`, not the collector-wide stop flag, so
    /// a caller in `run()` can start a fresh attempt afterward without
    /// leaking the previous one's threads.
    fn run_attempt(&self, sink: &Arc<dyn TagSink>) -> Result<()> {
        let attempt_stop = Arc::new(AtomicBool::new(false));
        let _bridge = spawn_stop_bridge(self.stop.clone(), attempt_stop.clone());
        let _attempt_guard = SetTrueOnDrop(attempt_stop.clone());

        let (live, session) = self.open(&self.name)?;

        spawn_watchdog(
            self.name.clone(),
            self.endpoint_url.clone(),
            session.clone(),
            sink.clone(),
            attempt_stop.clone(),
            self.monitor_options.health_check_interval,
        );

        let tags = self.selected(self.load_or_scan(session.clone())?);
        if tags.is_empty() {
            log::warn!("[{}] no tags to monitor", self.name);
            return Ok(());
        }

        if self.stop.load(Ordering::Relaxed) {
            self.close_previous(&self.name);
            return Ok(());
        }

        let (fast, tags): (Vec<PlcTag>, Vec<PlcTag>) = match &self.fast {
            Some(fast) => tags.into_iter().partition(|tag| fast(tag)),
            None => (Vec::new(), tags),
        };
        let (slow, tags): (Vec<PlcTag>, Vec<PlcTag>) = match &self.poll {
            Some(poll) => tags.into_iter().partition(|tag| poll(tag)),
            None => (Vec::new(), tags),
        };

        let split_at = self.monitor_options.max_subscribed_items.min(tags.len());
        let (to_subscribe, remainder) = tags.split_at(split_at);

        log::info!(
            "[{}] subscribing {} tags, polling {}",
            self.name,
            to_subscribe.len(),
            remainder.len()
        );

        self.spawn_poller(
            session.clone(),
            fast,
            "fast",
            self.monitor_options.fast_interval,
            sink.clone(),
            attempt_stop.clone(),
        );

        let liveness = Arc::new(Liveness::new());
        // the heartbearte type a bit of a lie
        let subscriber = Subscriber::new(
            live.clone(),
            self.monitor_options.clone(),
            self.name.clone(),
            sink.clone(),
            self.subscribed_last_seen.clone(),
            liveness.clone(),
        );
        let Subscribed {
            rejected,
            heartbeat,
        } = subscriber.subscribe_all(to_subscribe);

        let mut to_poll = remainder.to_vec();
        to_poll.extend(rejected);
        to_poll.extend(slow);
        self.spawn_poller(
            session,
            to_poll,
            "poll",
            self.monitor_options.poll_interval,
            sink.clone(),
            attempt_stop.clone(),
        );

        if self.stop.load(Ordering::Relaxed) {
            self.close_previous(&self.name);
            return Ok(());
        }

        log::info!("[{}] listening", self.name);
        self.report_connection(sink, true);
        liveness.beat();

        loop {
            if live.has_ended() {
                break;
            }
            if self.stop.load(Ordering::Relaxed) {
                log::debug!("[{}] stop requested", self.name);
                return Ok(());
            }
            if let Some(reason) = liveness.failure(self.monitor_options.liveness_timeout, heartbeat)
            {
                log::warn!("[{}] {reason}; opening a new session", self.name);
                self.report_connection(sink, false);
                self.close_previous(&self.name);
                return Err(Error::Silent(reason));
            }
            thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }

    fn report_connection(&self, sink: &Arc<dyn TagSink>, connected: bool) {
        sink.connection_changed(&ConnectionChange {
            timestamp: SystemTime::now(),
            collector: &self.name,
            endpoint_url: &self.endpoint_url,
            connected,
        });
    }

    /// Applies the selector, if one was set.
    fn selected(&self, tags: TagSet) -> Vec<PlcTag> {
        match &self.selector {
            None => tags.into_vec(),
            Some(predicate) => {
                let all = tags.len();
                let kept: Vec<PlcTag> = tags
                    .into_vec()
                    .into_iter()
                    .filter(|t| predicate(t))
                    .collect();
                log::info!("[{}] selected {} of {all} tags", self.name, kept.len());
                kept
            }
        }
    }

    /// Opens a session and registers it for shutdown.
    ///
    /// A stop that arrives while connecting finds nothing to close yet, so the
    /// new session is closed here instead of being left on the server.
    fn open(&self, name: &str) -> Result<OpenSession> {
        self.close_previous(name);

        let live = LiveSession::connect(&self.endpoint_url, &self.connect_options)?;
        let session: Arc<dyn PlcSession> = live.clone();

        registry_lock(&self.sessions).push((name.to_string(), session.clone()));

        if self.stop.load(Ordering::Relaxed) {
            self.close_previous(name);
            return Err(Error::Stopped);
        }

        Ok((live, session))
    }

    /// Closes any session already registered under `name`.
    fn close_previous(&self, name: &str) {
        let stale: Vec<Arc<dyn PlcSession>> = {
            let mut sessions = registry_lock(&self.sessions);
            let mut stale = Vec::new();
            sessions.retain(|(existing, session)| {
                if existing == name {
                    stale.push(session.clone());
                    false
                } else {
                    true
                }
            });
            stale
        };

        for session in stale {
            if let Err(e) = session.close_session_and_delete_subscriptions() {
                log::warn!("[{name}] previous session not released ({e}); server will time it out");
            }
        }
    }

    /// Returns cached tags, or scans and caches them.
    fn load_or_scan(&self, session: Arc<dyn PlcSession>) -> Result<TagSet> {
        #[cfg(feature = "json-cache")]
        if let Some(cache) = &self.cache {
            if cache.exists() && !self.force_rescan.load(Ordering::Relaxed) {
                match cache.load() {
                    Ok(tags) => {
                        log::info!("[{}] loaded {} tags from cache", self.name, tags.len());
                        return Ok(TagSet::new(tags));
                    }
                    Err(e) => log::warn!("[{}] cache unusable ({e}), rescanning", self.name),
                }
            }
        }

        log::info!("[{}] scanning address space", self.name);

        let browser = OpcUaNodeBrowser::new(session.clone());
        let scanner = TreeScanner::new(&browser, self.filter.as_ref(), self.scan_options.clone());
        let report = scanner.scan(NodeId::objects_folder_id())?;

        if !report.is_complete() {
            log::warn!(
                "[{}] {} subtrees were unreadable",
                self.name,
                report.skipped.len()
            );
            for (node_id, err) in &report.skipped {
                log::debug!("[{}]   {node_id}: {err}", self.name);
            }
        }

        log::info!("[{}] discovered {} tags", self.name, report.tags.len());

        let mut tags = report.into_tags();

        if self.read_attributes {
            crate::attributes::fill_variable_attributes(session.as_ref(), &mut tags);
        }

        #[cfg(feature = "json-cache")]
        if let Some(cache) = &self.cache {
            cache.save(&tags)?;
            self.force_rescan.store(false, Ordering::Relaxed);
        }

        Ok(TagSet::new(tags))
    }

    /// Runs a poller on its own thread, reading `tags` every `interval`
    /// through the attempt's session.
    ///
    /// One session carries both the subscriptions and the reads: servers cap
    /// their sessions, often at ten, and every client counts against that. The
    /// poller ends with the session; the next attempt starts a new one.
    ///
    /// `stop` scopes this poller to one [`run_attempt`](Self::run_attempt):
    /// it is set when that attempt ends, not only on collector shutdown, so
    /// a restart does not leave the previous attempt's poller running
    /// alongside the new one.
    fn spawn_poller(
        &self,
        session: Arc<dyn PlcSession>,
        tags: Vec<PlcTag>,
        kind: &str,
        interval: Duration,
        sink: Arc<dyn TagSink>,
        stop: Arc<AtomicBool>,
    ) {
        if tags.is_empty() {
            return;
        }

        let name = format!("{}-{kind}", self.name);
        let mut monitor_options = self.monitor_options.clone();
        monitor_options.poll_interval = interval;
        let mut backoff = Backoff::new(
            self.monitor_options.reconnect_backoff_min,
            self.monitor_options.reconnect_delay,
        );

        thread::spawn(move || {
            let mut last = std::collections::HashMap::new();

            log::info!(
                "[{name}] polling {} tags every {}ms",
                tags.len(),
                monitor_options.poll_interval.as_millis()
            );

            while !stop.load(Ordering::Relaxed) && session.is_connected() {
                let round = panic::catch_unwind(AssertUnwindSafe(|| {
                    Poller::new(
                        session.clone(),
                        monitor_options.clone(),
                        name.clone(),
                        sink.clone(),
                    )
                    .poll_forever(&tags, &stop, &mut last);
                }));

                match round {
                    Ok(()) => break,
                    Err(payload) => {
                        let delay = backoff.next();
                        log::error!(
                            "[{name}] polling stopped on an internal error ({}), starting again in {}ms",
                            crate::session::panic_message(&payload),
                            delay.as_millis()
                        );
                        sleep_interruptible(delay, &stop);
                    }
                }
            }
        });
    }
}

/// Stops a running [`Collector`] and closes its sessions.
///
/// The crate never calls `process::exit`; wire this into your own signal
/// handler, or use [`Collector::handle_ctrl_c`].
#[derive(Clone)]
pub struct CollectorHandle {
    name: String,
    stop: Arc<AtomicBool>,
    sessions: Registry,
}

impl CollectorHandle {
    /// The session this collector runs on now, for reads and writes that should not open one
    /// more session on the server.
    ///
    /// `None` while the collector connects or reconnects. Closing what this returns does
    /// nothing: the collector owns the session, closes it on [`stop`](Self::stop) and replaces it
    /// when it reconnects, so ask again once [`PlcSession::is_connected`] turns false.
    pub fn session(&self) -> Option<Arc<dyn PlcSession>> {
        registry_lock(&self.sessions)
            .iter()
            .find(|(name, session)| *name == self.name && session.is_connected())
            .map(|(_, session)| {
                Arc::new(crate::session::Borrowed(session.clone())) as Arc<dyn PlcSession>
            })
    }

    /// Signals shutdown and closes every session this collector opened.
    ///
    /// Closing matters: a server does not learn an abandoned session is gone
    /// until it times out, and until then its monitored items still count
    /// against the budget. Restart a collector a few times without this and you
    /// exhaust a server that was nowhere near its limit.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);

        for (name, session) in registry_lock(&self.sessions).iter() {
            match session.close_session_and_delete_subscriptions() {
                Ok(()) => log::info!("[{name}] session closed"),
                Err(e) => log::warn!("[{name}] could not close session: {e}"),
            }
        }

        thread::sleep(std::time::Duration::from_millis(200));
    }

    /// Whether shutdown has been signalled.
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

fn registry_lock(
    registry: &Registry,
) -> std::sync::MutexGuard<'_, Vec<(String, Arc<dyn PlcSession>)>> {
    registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Sets an `AtomicBool` to `true` when dropped, regardless of which return
/// path triggered the drop (including an early `?`).
struct SetTrueOnDrop(Arc<AtomicBool>);

impl Drop for SetTrueOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Mirrors `global_stop` into `attempt_stop`, so a per-attempt scope notices
/// permanent shutdown without being the thing that causes it.
///
/// The bridge thread also exits as soon as `attempt_stop` is set directly
/// (by the attempt ending on its own), so it never outlives the attempt it
/// watches.
fn spawn_stop_bridge(global_stop: Arc<AtomicBool>, attempt_stop: Arc<AtomicBool>) -> StopBridge {
    let handle = thread::spawn(move || {
        while !global_stop.load(Ordering::Relaxed) && !attempt_stop.load(Ordering::Relaxed) {
            thread::sleep(std::time::Duration::from_millis(200));
        }
        attempt_stop.store(true, Ordering::Relaxed);
    });
    StopBridge(Some(handle))
}

/// Joins the bridge thread when a `run_attempt` scope ends, so restarts do
/// not accumulate idle threads.
struct StopBridge(Option<thread::JoinHandle<()>>);

impl Drop for StopBridge {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::client::prelude::{
        BrowseDescription, BrowseResult, ByteString, DataValue, ReadValueId, StatusCode,
        TimestampsToReturn,
    };

    struct Fake {
        connected: AtomicBool,
        closed: AtomicBool,
    }

    impl PlcSession for Fake {
        fn browse(
            &self,
            _: &[BrowseDescription],
        ) -> std::result::Result<Option<Vec<BrowseResult>>, StatusCode> {
            Ok(None)
        }

        fn browse_next(
            &self,
            _: bool,
            _: &[ByteString],
        ) -> std::result::Result<Option<Vec<BrowseResult>>, StatusCode> {
            Ok(None)
        }

        fn read(
            &self,
            _: &[ReadValueId],
            _: TimestampsToReturn,
            _: f64,
        ) -> std::result::Result<Vec<DataValue>, StatusCode> {
            Ok(Vec::new())
        }

        #[cfg(feature = "write")]
        fn write(
            &self,
            nodes: &[opcua::client::prelude::WriteValue],
        ) -> std::result::Result<Vec<StatusCode>, StatusCode> {
            Ok(vec![StatusCode::Good; nodes.len()])
        }

        fn close_session_and_delete_subscriptions(&self) -> std::result::Result<(), StatusCode> {
            self.closed.store(true, Ordering::Relaxed);
            self.connected.store(false, Ordering::Relaxed);
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn the_running_session_is_lent_but_the_borrower_cannot_close_it() {
        let collector = Collector::new("line1", "opc.tcp://127.0.0.1:4840");
        let handle = collector.handle();
        assert!(handle.session().is_none(), "nothing is open before run");

        let fake = Arc::new(Fake {
            connected: AtomicBool::new(true),
            closed: AtomicBool::new(false),
        });
        let shared: Arc<dyn PlcSession> = fake.clone();
        registry_lock(&collector.sessions).push(("line1-client".into(), shared.clone()));
        assert!(
            handle.session().is_none(),
            "only the collector's own session is lent"
        );

        registry_lock(&collector.sessions).push(("line1".into(), shared));
        let lent = handle.session().expect("the running session");
        assert!(lent.is_connected());
        assert_eq!(lent.close_session_and_delete_subscriptions(), Ok(()));
        assert!(
            !fake.closed.load(Ordering::Relaxed),
            "the borrower cannot close it"
        );
        assert!(lent.is_connected());

        fake.connected.store(false, Ordering::Relaxed);
        assert!(!lent.is_connected());
        assert!(handle.session().is_none(), "a dropped session is not lent");
    }
}
