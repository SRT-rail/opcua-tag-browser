//! Server-push monitoring, chunked to what the server will accept.

use super::{Liveness, MonitorOptions};
use crate::sink::{Source, TagChange, TagSink};
use crate::tag::PlcTag;
use crate::variant::{format_quality, format_variant};
use opcua::client::prelude::*;
use opcua::sync::RwLock;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

const HEARTBEAT_SAMPLING_MS: f64 = 500.0;

/// What [`Subscriber::subscribe_all`] got from the server.
pub(crate) struct Subscribed {
    /// Tags the server refused; the caller polls them instead.
    pub(crate) rejected: Vec<PlcTag>,
    /// Whether the server reports its clock, so that silence means trouble.
    pub(crate) heartbeat: bool,
}

/// Subscribes tags in chunks and forwards every change the server pushes.
pub(crate) struct Subscriber {
    raw: Arc<RwLock<Session>>,
    options: MonitorOptions,
    collector: String,
    sink: Arc<dyn TagSink>,
    last_seen: Arc<std::sync::Mutex<HashMap<String, (String, String)>>>,
    liveness: Arc<Liveness>,
}

impl Subscriber {
    pub(crate) fn new(
        raw: Arc<RwLock<Session>>,
        options: MonitorOptions,
        collector: String,
        sink: Arc<dyn TagSink>,
        last_seen: Arc<std::sync::Mutex<HashMap<String, (String, String)>>>,
        liveness: Arc<Liveness>,
    ) -> Self {
        Self {
            raw,
            options,
            collector,
            sink,
            last_seen,
            liveness,
        }
    }

    /// Subscribes to `tags`, and to the server's clock in the first
    /// subscription.
    ///
    /// Rejected tags are not an error: the caller polls them instead.
    pub(crate) fn subscribe_all(&self, tags: &[PlcTag]) -> Subscribed {
        let default_sampling = self.options.sampling_interval.as_millis() as f64;

        let requests: Vec<(&PlcTag, MonitoredItemCreateRequest)> = tags
            .iter()
            .filter_map(|tag| {
                let node_id = NodeId::from_str(&tag.node_id).ok()?;
                let sampling_interval = tag
                    .min_sampling_interval
                    .filter(|&ms| ms > 0.0)
                    .unwrap_or(default_sampling);

                let params = MonitoringParameters {
                    sampling_interval,
                    queue_size: 1,
                    discard_oldest: true,
                    ..Default::default()
                };

                Some((
                    tag,
                    MonitoredItemCreateRequest::new(
                        ReadValueId::from(node_id),
                        MonitoringMode::Reporting,
                        params,
                    ),
                ))
            })
            .collect();

        let by_node_id: Arc<HashMap<String, PlcTag>> = Arc::new(
            tags.iter()
                .map(|t| (t.node_id.clone(), t.clone()))
                .collect(),
        );

        let mut rejected = Vec::new();
        let mut first = None;

        for (index, chunk) in requests.chunks(self.options.sub_chunk_size).enumerate() {
            let sub_id = match self.create_subscription(by_node_id.clone()) {
                Ok(id) => id,
                Err(status) => {
                    log::warn!(
                        "[{}] could not create subscription {}: {status}",
                        self.collector,
                        index + 1
                    );
                    rejected.extend(chunk.iter().map(|(t, _)| (*t).clone()));
                    continue;
                }
            };

            log::info!(
                "[{}] subscription {} covers {} items",
                self.collector,
                index + 1,
                chunk.len()
            );
            first.get_or_insert(sub_id);

            for batch in chunk.chunks(self.options.request_batch_size) {
                let (batch_tags, batch_requests): (Vec<&PlcTag>, Vec<_>) =
                    batch.iter().map(|(t, r)| (*t, r.clone())).unzip();

                match self.raw.write().create_monitored_items(
                    sub_id,
                    TimestampsToReturn::Both,
                    &batch_requests,
                ) {
                    Ok(results) => {
                        for (tag, result) in batch_tags.iter().zip(results.iter()) {
                            if result.status_code.is_bad() {
                                log::debug!(
                                    "[{}] rejected {}: {}",
                                    self.collector,
                                    tag.node_id,
                                    result.status_code
                                );
                                rejected.push((*tag).clone());
                            }
                        }
                    }
                    Err(status) => {
                        log::warn!(
                            "[{}] batch of {} rejected: {status}",
                            self.collector,
                            batch_tags.len()
                        );
                        rejected.extend(batch_tags.into_iter().cloned());
                    }
                }
            }
        }

        if !rejected.is_empty() {
            log::info!(
                "[{}] {} tags refused, falling back to polling",
                self.collector,
                rejected.len()
            );
        }

        let heartbeat = first.is_some_and(|sub_id| self.watch_server_clock(sub_id));
        Subscribed {
            rejected,
            heartbeat,
        }
    }

    /// Adds the server's current time to a subscription, so that it
    /// delivers twice a second even when no tag changes.
    fn watch_server_clock(&self, sub_id: u32) -> bool {
        let request = MonitoredItemCreateRequest::new(
            ReadValueId::from(NodeId::new(
                0,
                VariableId::Server_ServerStatus_CurrentTime as u32,
            )),
            MonitoringMode::Reporting,
            MonitoringParameters {
                sampling_interval: HEARTBEAT_SAMPLING_MS,
                queue_size: 1,
                discard_oldest: true,
                ..Default::default()
            },
        );
        let refused = match self.raw.write().create_monitored_items(
            sub_id,
            TimestampsToReturn::Neither,
            &[request],
        ) {
            Ok(results) => match results.first() {
                Some(result) if result.status_code.is_good() => return true,
                Some(result) => result.status_code,
                None => StatusCode::BadUnexpectedError,
            },
            Err(status) => status,
        };
        log::warn!(
            "[{}] server clock not watched ({refused}): a session that stops delivering is noticed only when the connection drops",
            self.collector
        );
        false
    }

    /// Creates one subscription whose callback forwards changes to the sink.
    fn create_subscription(
        &self,
        by_node_id: Arc<HashMap<String, PlcTag>>,
    ) -> Result<u32, StatusCode> {
        let collector = self.collector.clone();
        let sink = self.sink.clone();
        let last_seen = self.last_seen.clone();
        let liveness = self.liveness.clone();

        self.raw.write().create_subscription(
            self.options.publishing_interval.as_millis() as f64,
            self.options.lifetime_count,
            self.options.max_keep_alive_count,
            0,
            0,
            true,
            DataChangeCallback::new(move |items| {
                liveness.beat();
                for item in items {
                    let node_id = item.item_to_monitor().node_id.to_string();

                    let Some(latest) = item.values().last() else {
                        continue;
                    };
                    let Some(ref variant) = latest.value else {
                        continue;
                    };

                    if matches!(variant, Variant::ExtensionObject(_)) {
                        continue;
                    }

                    let Some(tag) = by_node_id.get(&node_id) else {
                        continue;
                    };

                    let value_str = format_variant(variant);
                    let quality_str = format_quality(latest.status);

                    {
                        let mut map = last_seen
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some((prev_val, prev_qual)) = map.get(&node_id) {
                            if prev_val == &value_str && prev_qual == &quality_str {
                                continue;
                            }
                        }
                        map.insert(node_id.clone(), (value_str.clone(), quality_str.clone()));
                    }

                    let good = latest.status.map(|s| s.is_good()).unwrap_or(true);

                    sink.tag_changed(&TagChange {
                        timestamp: SystemTime::now(),
                        collector: &collector,
                        tag,
                        variant,
                        value: &value_str,
                        quality: &quality_str,
                        good,
                        source: Source::Subscribe,
                    });
                }
            }),
        )
    }
}
