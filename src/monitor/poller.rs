//! Cyclic reading for tags the server would not monitor.

use super::MonitorOptions;
use crate::session::PlcSession;
use crate::sink::{Source, TagChange, TagSink};
use crate::tag::PlcTag;
use crate::variant::{format_quality, format_variant, variant_as_f64};
use opcua::client::prelude::*;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

/// Floor for adaptive batch sizing, so a failing batch cannot stall the loop.
const MIN_BATCH_SIZE: usize = 10;

/// Good reads in a row before a shrunken batch size doubles again.
const GROW_AFTER: u32 = 20;

/// What was last seen for a tag, for change detection.
pub(crate) struct LastSeen {
    pub(crate) rendered: String,
    pub(crate) quality: String,
    pub(crate) numeric: Option<f64>,
}

/// Reads tags in batches and reports those whose value or quality changed.
pub(crate) struct Poller {
    session: Arc<dyn PlcSession>,
    options: MonitorOptions,
    collector: String,
    sink: Arc<dyn TagSink>,
}

impl Poller {
    pub(crate) fn new(
        session: Arc<dyn PlcSession>,
        options: MonitorOptions,
        collector: String,
        sink: Arc<dyn TagSink>,
    ) -> Self {
        Self {
            session,
            options,
            collector,
            sink,
        }
    }

    /// Polls until `stop` is set or the connection drops.
    pub(crate) fn poll_forever(
        &self,
        tags: &[PlcTag],
        stop: &Arc<AtomicBool>,
        last: &mut HashMap<String, LastSeen>,
    ) {
        let readable: Vec<(&PlcTag, ReadValueId)> = tags
            .iter()
            .filter_map(|tag| {
                let node_id = NodeId::from_str(&tag.node_id).ok()?;
                Some((tag, ReadValueId::from(node_id)))
            })
            .collect();

        if readable.is_empty() {
            return;
        }

        let mut batch_size = self.options.poll_batch_size;
        if let Some(limit) = self.server_max_nodes_per_read() {
            if limit < batch_size {
                log::info!("[{}] server caps reads at {limit} nodes", self.collector);
                batch_size = limit;
            }
        }

        let max_age = self.options.poll_interval.as_millis() as f64;
        let full_size = batch_size;
        let mut good_reads = 0;

        while !stop.load(Ordering::Relaxed) {
            let mut start = 0;

            while start < readable.len() && !stop.load(Ordering::Relaxed) {
                let end = (start + batch_size).min(readable.len());
                let batch = &readable[start..end];
                let requests: Vec<ReadValueId> = batch.iter().map(|(_, rv)| rv.clone()).collect();

                match self
                    .session
                    .read(&requests, TimestampsToReturn::Both, max_age)
                {
                    Ok(values) => {
                        self.report_changes(batch, &values, last);
                        start = end;
                        good_reads += 1;
                        if batch_size < full_size && good_reads >= GROW_AFTER {
                            batch_size = (batch_size * 2).min(full_size);
                            good_reads = 0;
                            log::info!(
                                "[{}] reads succeed again, batch size back up to {batch_size}",
                                self.collector
                            );
                        }
                    }
                    Err(status) => {
                        good_reads = 0;
                        if !self.session.is_connected() {
                            log::warn!("[{}] connection lost, ending poll loop", self.collector);
                            return;
                        }

                        if batch_size > MIN_BATCH_SIZE {
                            batch_size = (batch_size / 2).max(MIN_BATCH_SIZE);
                            log::warn!(
                                "[{}] read of {} failed ({status}), batch size now {batch_size}",
                                self.collector,
                                batch.len()
                            );
                        } else {
                            self.report_unreadable(batch, status, last);
                            start = end;
                        }
                    }
                }
            }

            thread::sleep(self.options.poll_interval);
        }
    }

    /// Reports any tag in the batch whose value or quality changed.
    fn report_changes(
        &self,
        batch: &[(&PlcTag, ReadValueId)],
        values: &[DataValue],
        last: &mut HashMap<String, LastSeen>,
    ) {
        for ((tag, _), data_value) in batch.iter().zip(values.iter()) {
            let Some(ref variant) = data_value.value else {
                continue;
            };

            if matches!(variant, Variant::ExtensionObject(_)) {
                continue;
            }

            let rendered = format_variant(variant);
            let quality = format_quality(data_value.status);
            let numeric = variant_as_f64(variant);

            if !self.is_change(last.get(&tag.node_id), &rendered, &quality, numeric) {
                continue;
            }

            let good = data_value.status.map(|s| s.is_good()).unwrap_or(true);

            self.sink.tag_changed(&TagChange {
                timestamp: SystemTime::now(),
                collector: &self.collector,
                tag,
                variant,
                value: &rendered,
                quality: &quality,
                good,
                source: Source::Poll,
            });

            last.insert(
                tag.node_id.clone(),
                LastSeen {
                    rendered,
                    quality,
                    numeric,
                },
            );
        }
    }

    /// Marks the tags of a batch that cannot be read even at the smallest
    /// size as bad, keeping their last value, so they do not look live.
    fn report_unreadable(
        &self,
        batch: &[(&PlcTag, ReadValueId)],
        status: StatusCode,
        last: &mut HashMap<String, LastSeen>,
    ) {
        let quality = format_quality(Some(status));
        let mut marked = 0;
        for (tag, _) in batch {
            let previous = last.get(&tag.node_id);
            if previous.is_some_and(|seen| seen.quality == quality) {
                continue;
            }
            let rendered = previous
                .map(|seen| seen.rendered.clone())
                .unwrap_or_default();
            self.sink.tag_changed(&TagChange {
                timestamp: SystemTime::now(),
                collector: &self.collector,
                tag,
                variant: &Variant::Empty,
                value: &rendered,
                quality: &quality,
                good: false,
                source: Source::Poll,
            });
            last.insert(
                tag.node_id.clone(),
                LastSeen {
                    rendered,
                    quality: quality.clone(),
                    numeric: None,
                },
            );
            marked += 1;
        }
        if marked > 0 {
            log::warn!(
                "[{}] {marked} polled tags cannot be read ({status}); shown as bad until a read succeeds",
                self.collector
            );
        }
    }

    /// Whether a reading differs enough from the previous one to report.
    fn is_change(
        &self,
        previous: Option<&LastSeen>,
        rendered: &str,
        quality: &str,
        numeric: Option<f64>,
    ) -> bool {
        let Some(previous) = previous else {
            return true;
        };

        if previous.quality != quality {
            return true;
        }

        if let (Some(threshold), Some(new), Some(old)) =
            (self.options.deadband, numeric, previous.numeric)
        {
            return (new - old).abs() >= threshold;
        }

        previous.rendered != rendered
    }

    /// Asks the server for its own `MaxNodesPerRead` limit.
    fn server_max_nodes_per_read(&self) -> Option<usize> {
        let node_id: NodeId =
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead.into();

        let values = self
            .session
            .read(
                &[ReadValueId::from(node_id)],
                TimestampsToReturn::Neither,
                0.0,
            )
            .ok()?;

        match values.into_iter().next()?.value? {
            Variant::UInt32(limit) if limit > 0 => Some(limit as usize),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeSession {
        failing_reads: Mutex<usize>,
        broken: Option<String>,
        sizes: Mutex<Vec<usize>>,
    }

    impl PlcSession for FakeSession {
        fn browse(&self, _: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
            Ok(None)
        }

        fn browse_next(
            &self,
            _: bool,
            _: &[ByteString],
        ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
            Ok(None)
        }

        fn read(
            &self,
            nodes: &[ReadValueId],
            _: TimestampsToReturn,
            _: f64,
        ) -> Result<Vec<DataValue>, StatusCode> {
            self.sizes.lock().unwrap().push(nodes.len());
            let mut failing = self.failing_reads.lock().unwrap();
            let broken = self
                .broken
                .as_ref()
                .is_some_and(|broken| nodes.iter().any(|node| &node.node_id.to_string() == broken));
            if *failing > 0 || broken {
                *failing = failing.saturating_sub(1);
                return Err(StatusCode::BadTimeout);
            }
            Ok(nodes
                .iter()
                .map(|_| DataValue::value_only(Variant::Int32(1)))
                .collect())
        }

        #[cfg(feature = "write")]
        fn write(&self, _: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode> {
            Ok(Vec::new())
        }

        fn close_session_and_delete_subscriptions(&self) -> Result<(), StatusCode> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            true
        }
    }

    type Seen = Arc<Mutex<Vec<(String, String, bool)>>>;

    fn tags(count: usize) -> Vec<PlcTag> {
        (0..count)
            .map(|i| {
                PlcTag::new(
                    format!("T{i}"),
                    "",
                    format!("ns=1;s=T{i}"),
                    "Variable",
                    format!("Line/T{i}"),
                )
            })
            .collect()
    }

    fn poll(session: Arc<FakeSession>, tags: &[PlcTag], batch: usize, passes: u64) -> Seen {
        let seen: Seen = Arc::default();
        let into = seen.clone();
        let sink: Arc<dyn TagSink> = Arc::new(move |change: &TagChange<'_>| {
            into.lock().unwrap().push((
                change.tag.path.clone(),
                change.quality.to_string(),
                change.good,
            ));
        });
        let mut options =
            MonitorOptions::default().poll_interval(std::time::Duration::from_millis(1));
        options.poll_batch_size = batch;
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = stop.clone();
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(passes * 20));
            stopper.store(true, Ordering::Relaxed);
        });
        Poller::new(session, options, "line1-poll".into(), sink).poll_forever(
            tags,
            &stop,
            &mut HashMap::new(),
        );
        seen
    }

    #[test]
    fn tags_that_cannot_be_read_are_shown_bad_not_frozen() {
        let session = Arc::new(FakeSession {
            broken: Some("ns=1;s=T3".into()),
            ..Default::default()
        });
        let seen = poll(session, &tags(20), MIN_BATCH_SIZE, 5);
        let seen = seen.lock().unwrap();

        let t3: Vec<_> = seen
            .iter()
            .filter(|(path, _, _)| path == "Line/T3")
            .collect();
        assert_eq!(t3.len(), 1, "reported bad once, not on every pass: {t3:?}");
        assert_eq!((t3[0].1.as_str(), t3[0].2), ("BAD (BadTimeout)", false));
        assert!(seen
            .iter()
            .any(|(path, quality, good)| path == "Line/T15" && quality == "GOOD" && *good));
    }

    #[test]
    fn the_batch_size_grows_back_once_reads_succeed() {
        let session = Arc::new(FakeSession {
            failing_reads: Mutex::new(3),
            ..Default::default()
        });
        poll(session.clone(), &tags(40), 40, 30);
        let sizes = session.sizes.lock().unwrap();

        assert!(
            sizes.contains(&MIN_BATCH_SIZE),
            "shrunk after the failures: {sizes:?}"
        );
        assert_eq!(sizes.last(), Some(&40), "back to the full size: {sizes:?}");
    }
}
