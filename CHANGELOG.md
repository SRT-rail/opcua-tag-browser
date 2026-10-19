## [Unreleased]

### Added

- `write` feature, on by default. It holds everything in this crate that can change a PLC:
  `TagClient`, `Collector::client`, `PlcSession::write` and `OpcUaSession::inner`. A read-only
  program (such as an edge data agent) builds with `default-features = false` and gets none of
  them. Nothing changes for builds with default features.

## [0.2.12] - 2026-07-31

### Fixed

- Preserved subscription `last_seen` change detection state on `Collector` across
  session reconnects. Previously, when a PLC connection dropped and re-established
  (e.g., when monitoring multiple PLCs with one endpoint retrying), the OPC UA
  server sent an initial batch notification for all subscribed items upon
  re-subscribing. Because `Subscriber` created a fresh empty map on every attempt,
  all subscribed tags were re-logged/re-printed on every reconnect even if their
  values had not changed. `Collector` now owns the map for its entire lifetime.

## [0.2.11] - 2026-07-31

### Fixed

- Added client-side deduplication to subscription `DataChangeCallback`. OPC UA
  servers often fire duplicate notifications when timestamps update or server
  keepalive ticks fire even when the tag's value and quality remain unchanged.
  Subscribed tags are now deduplicated on the client side so events are only
  sent to `TagSink` when the value or status code actually changes.

## [0.2.10] - 2026-07-31

### Fixed

- Preserved the poller's `last_seen` change detection cache across polling
  session reconnects. Previously, every time the poller re-established its session
  (e.g., after brief network glitches or transient batch read errors), the
  cache was wiped, causing all polled tags to be reported again as new values
  even when their values had not changed on the PLC.

## [0.2.9] - 2026-07-31

### Fixed

- `OpcUaSession::is_connected` was not wrapped in `catch_panic` unlike all other
  `PlcSession` methods. The `opcua` 0.12 crate can panic inside `is_connected`
  when the session is mid-reconnect and its internal message queue has not been
  re-initialised yet — the same root cause as the 0.2.7 entry. The watchdog
  calls `is_connected` on every health-check tick, so it was the most common
  trigger of "MessageQueue::send_message called before make_request_channel"
  panics during reconnection. The call is now guarded; a panic is treated as
  "not connected" so the watchdog correctly reports the link as down without
  crashing its own thread or the session thread.

## [0.2.8] - 2026-07-31

### Changed

- The session-thread abandonment wait on stop was reduced from 2 s to 300 ms.
  Since `disconnect()` cannot be safely called from outside the session thread
  (see 0.2.7), that 2-second window was not doing anything useful. The thread
  is still killed when the process exits after the collector threads return.
  Application code should pair `CollectorHandle::stop` with a force-exit timer
  (e.g. 3–4 s) so that a blocked TCP `connect` on an unreachable host does not
  make the process wait for the full OS timeout (~16 s on Windows).

## [0.2.7] - 2026-07-31

### Fixed

- Calling `disconnect()` on the `opcua` session from outside the session thread
  caused a panic — "MessageQueue::send_message should never be called before
  make_request_channel" — when the session was mid-reconnect and its internal
  message queue had not yet been re-initialised. The `disconnect()` call has
  been removed from the stop path entirely. `run_attempt` now simply waits up
  to 2 seconds for the session thread to finish on its own, then abandons it.
  The abandoned thread is killed when the process exits after all collector
  threads return.

## [0.2.6] - 2026-07-31

### Fixed

- `CollectorHandle::stop` (and so Ctrl+C) could hang indefinitely when called
  while `Session::run` was executing inside `run_attempt`. The previous fix used
  `raw.write().disconnect()` to signal the session thread to exit, but
  `Session::run` holds the write lock on `raw` for the duration of its loop —
  causing a deadlock where the collector thread waited forever for a lock that
  the session thread would never release. The write is now attempted with
  `try_write()` spinning for up to 500 ms; if the lock cannot be acquired the
  collector thread falls through to the existing 2-second thread-exit wait and
  abandons the session thread if it still has not exited, after which
  `run_attempt` returns and the process exits normally.


### Fixed

- `CollectorHandle::stop` (and so Ctrl+C via `handle_ctrl_c`) could hang for
  the length of the session's entire reconnect budget — up to
  `session_retry_limit` x `session_retry_interval` — if it was called while
  the underlying `opcua` session was actively retrying an unreachable server.
  `Session::run` gives the `opcua` crate no way to interrupt it mid-retry, so
  `Collector` now runs it on its own thread and stops waiting the moment
  `stop` is requested, abandoning that thread rather than blocking on it.
- The poller registered a new session in the shared registry on every
  reconnect without removing the previous one. On a long-running collector
  that had reconnected several times, `CollectorHandle::stop` would then try
  to close each stale entry and log a `BadNotConnected` warning for every one
  of them. Reconnecting now replaces the poller's registry entry instead of
  accumulating another.

## [0.2.2] - 2026-07-31

### Added

- `ConnectOptions::session_retry_limit` / `session_retry_interval`, controlling
  how the underlying `opcua` session reconnects and re-attaches its existing
  subscriptions after a dropped connection. Defaults raised from `opcua`'s own
  10 retries / 10s apart to 20 retries / 2s apart.
- `MonitorOptions::reconnect_backoff_min`, `restart_backoff_min`, and
  `restart_backoff_max`: exponential-backoff-with-jitter tuning for the poller
  and for `Collector`'s own restart loop
- `Collector::resilient` (on by default): `run()` now restarts automatically
  — fresh connect, fresh scan-or-cache-load, fresh subscriptions — whenever a
  run attempt ends for a recoverable reason, instead of returning. Bad
  credentials or a client that cannot be built at all still return
  immediately, since retrying those can never succeed.
- `Error::is_recoverable`

### Changed

- `MonitorOptions::health_check_interval` default lowered from 3s to 1s (the
  check is a local flag read, not a network call, so this is free)
- The poller's fixed `reconnect_delay` between attempts is now exponential
  backoff starting at `reconnect_backoff_min`, so a short blip recovers almost
  immediately instead of always waiting the full delay

## [0.2.1] - 2026-07-31

Version-only release: `0.2.0` was already claimed on crates.io by an earlier
publish attempt, so this ships the same content under `0.2.1`. The entries
below were not previously changelogged.

### Added

- `PlcTag` now carries the OPC 10000-3 Table 13 `Variable` attributes:
  `browse_name`, `data_type`, `value_rank`, `access_level`,
  `min_sampling_interval`, `historizing`, `type_definition`, `reference_type`,
  read in a batched pass after each scan (`Collector::read_attributes`,
  default on)
- `PlcTag::is_readable`, `is_writable`, `has_history`, `is_array`, `is_property`
- `ScanOptions::include_properties`, excluding `HasProperty` metadata nodes
  (`EngineeringUnits`, `EURange`, ...) from scans by default
- `Error::NotWritable`

### Changed

- **Breaking:** `PlcTag::path` is now built from `BrowseName` rather than
  `DisplayName`, which is stable across server locales. Existing caches load,
  but paths may differ; rescan to refresh.
- `TagClient::set` refuses a write to a tag whose `AccessLevel` says read-only,
  returning `Error::NotWritable` without a round trip
- Subscriptions use each tag's own `MinimumSamplingInterval` when the server
  reported one, instead of one sampling interval applied uniformly
- Fixed a broken intra-doc link (`PlcTag`'s docs pointed at
  `ScanOptions::read_attributes`, which doesn't exist; the toggle is
  `Collector::read_attributes`)

## [0.2.0] - 2026-07-30

### Added
- `Collector`: connect, discover, subscribe, poll, reconnect, and stream changes
  to a sink, with `CollectorHandle` for shutdown from another thread
- `TagClient` for reading and writing individual values by browse path
- `TagSet`, indexing tags for lookup by path, name, node id, or glob
- `TagSink` with `TagChange` / `ConnectionChange`, implemented by any closure;
  `sinks::LogSink` and `sinks::JsonlSink` ship ready to use
- Tag selection via `Collector::only`, `matching`, and `select`
- `MonitorOptions`, including a deadband filter for noisy analogue values
- `Security` and `Credentials` on `ConnectOptions`, plus `ConnectOptions::insecure`
- `discover` free function for a one-off scan of an endpoint
- `PlcSession::write`; `variant_as_f64`, `variant_as_i64`, `variant_as_bool`
- `ScanOptions::max_depth` and `descend_into_variables` builder methods
- Features: `monitoring` (default), `jsonl-sink`, `ctrl-c`, `full`

### Changed
- **Breaking:** `ConnectOptions::default` now signs and encrypts with
  `Basic256Sha256` and rejects untrusted server certificates. Plaintext servers
  need `ConnectOptions::insecure`, which records the decision in your source.
- **Breaking:** `NodeFilter`'s blanket impl now requires `Fn(&str) -> bool + Send + Sync`
- Sending credentials over an unencrypted channel fails with
  `Error::InsecureCredentials` instead of transmitting them; `Credentials`
  redacts passwords in `Debug`
- New `Error` variants: `MissingSink`, `SinkSetup`, `InsecureCredentials`,
  `UnknownTag`, `BadNodeId`, `Write`, `Read`

## [0.1.3] - 2026-07-29

### Added
- README with usage guide, design notes, and version compatibility table
- Expanded crate-level documentation

### Changed
- `#![deny(rustdoc::broken_intra_doc_links)]` now enforced at build time