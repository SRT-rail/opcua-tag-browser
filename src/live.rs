//! Sessions on the asynchronous `async-opcua` client, used by [`Collector`](crate::Collector).
//!
//! The `opcua` 0.12 client keeps a session locked for the whole of every
//! request, and its publish loop needs the same lock, so a slow read on a
//! session stalls that session's subscription data. This client sends each
//! request on its own, so one session can subscribe and poll at the same time.
//!
//! Values cross between the two crates' types through their OPC UA binary
//! encoding, so everything downstream renders exactly as before.

use crate::connection::{reachable, ConnectOptions, Credentials, Security};
use crate::error::{Error, Result};
use crate::session::{catch_panic, PlcSession};
use async_opcua::client::{
    ClientBuilder, DataChangeCallback, IdentityToken, MonitoredItem, Password, Session,
    SessionPollResult,
};
use async_opcua::types as ua;
use futures::StreamExt;
use opcua::client::prelude as old;
use std::future::Future;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Matches the `opcua` 0.12 client, so a stuck request fails as soon as before.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for a new session to come up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest wait for a session to close; after it the server times it out.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the event loop gets to end after a close before it is dropped.
const LOOP_END_TIMEOUT: Duration = Duration::from_secs(1);
/// `opcua` 0.12 asks for up to this many references per browsed node.
const MAX_REFERENCES_PER_NODE: u32 = 1000;
/// Limits for converting values that the client already accepted.
const CONVERT_LIMIT: usize = 1 << 24;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("opcua-live")
            .enable_all()
            .build()
            .expect("the OPC UA runtime starts")
    })
}

/// Runs a future to completion from synchronous code.
///
/// From inside another Tokio runtime, blocking that runtime's thread on this
/// one would panic, so the future then runs from a plain thread instead.
fn block_on<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_err() {
        return runtime().block_on(future);
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| runtime().block_on(future))
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}

fn old_status(status: ua::StatusCode) -> old::StatusCode {
    old::StatusCode::from_bits_truncate(status.bits())
}

fn new_decoding() -> ua::DecodingOptions {
    ua::DecodingOptions {
        max_string_length: CONVERT_LIMIT,
        max_byte_string_length: CONVERT_LIMIT,
        max_array_length: CONVERT_LIMIT,
        ..Default::default()
    }
}

fn old_decoding() -> opcua::types::DecodingOptions {
    opcua::types::DecodingOptions {
        max_string_length: CONVERT_LIMIT,
        max_byte_string_length: CONVERT_LIMIT,
        max_array_length: CONVERT_LIMIT,
        ..Default::default()
    }
}

/// Converts an `opcua` 0.12 value to its `async-opcua` equivalent.
pub(crate) fn to_new<T, U>(value: &T) -> std::result::Result<U, old::StatusCode>
where
    T: opcua::types::BinaryEncoder<T>,
    U: ua::BinaryDecodable,
{
    let context = ua::ContextOwned::new_default(Default::default(), new_decoding());
    U::decode(&mut Cursor::new(value.encode_to_vec()), &context.context())
        .map_err(|_| old::StatusCode::BadDecodingError)
}

/// Converts an `async-opcua` value to its `opcua` 0.12 equivalent.
pub(crate) fn to_old<T, U>(value: &T) -> std::result::Result<U, old::StatusCode>
where
    T: ua::BinaryEncodable,
    U: opcua::types::BinaryEncoder<U>,
{
    let context = ua::ContextOwned::default();
    let mut bytes = Vec::with_capacity(value.byte_len(&context.context()));
    value
        .encode(&mut bytes, &context.context())
        .map_err(|_| old::StatusCode::BadEncodingError)?;
    U::decode(&mut Cursor::new(bytes), &old_decoding())
        .map_err(|_| old::StatusCode::BadDecodingError)
}

fn to_new_all<T, U>(values: &[T]) -> std::result::Result<Vec<U>, old::StatusCode>
where
    T: opcua::types::BinaryEncoder<T>,
    U: ua::BinaryDecodable,
{
    values.iter().map(to_new).collect()
}

fn to_old_all<T, U>(values: &[T]) -> std::result::Result<Vec<U>, old::StatusCode>
where
    T: ua::BinaryEncodable,
    U: opcua::types::BinaryEncoder<U>,
{
    values.iter().map(to_old).collect()
}

fn timestamps(value: old::TimestampsToReturn) -> ua::TimestampsToReturn {
    match value {
        old::TimestampsToReturn::Source => ua::TimestampsToReturn::Source,
        old::TimestampsToReturn::Server => ua::TimestampsToReturn::Server,
        old::TimestampsToReturn::Both => ua::TimestampsToReturn::Both,
        old::TimestampsToReturn::Neither => ua::TimestampsToReturn::Neither,
        old::TimestampsToReturn::Invalid => ua::TimestampsToReturn::Invalid,
    }
}

fn security_mode(security: Security) -> ua::MessageSecurityMode {
    match security {
        Security::None => ua::MessageSecurityMode::None,
        Security::Sign(_) => ua::MessageSecurityMode::Sign,
        Security::SignAndEncrypt(_) => ua::MessageSecurityMode::SignAndEncrypt,
    }
}

fn token_policy(credentials: &Credentials) -> ua::UserTokenPolicy {
    match credentials {
        Credentials::Anonymous => ua::UserTokenPolicy::anonymous(),
        Credentials::UserName { policy_id, .. } => ua::UserTokenPolicy {
            policy_id: policy_id.as_str().into(),
            token_type: ua::UserTokenType::UserName,
            issued_token_type: ua::UAString::null(),
            issuer_endpoint_url: ua::UAString::null(),
            security_policy_uri: ua::UAString::null(),
        },
    }
}

fn identity(credentials: &Credentials) -> IdentityToken {
    match credentials {
        Credentials::Anonymous => IdentityToken::Anonymous,
        Credentials::UserName { user, password, .. } => {
            IdentityToken::UserName(user.clone(), Password::new(password.clone()))
        }
    }
}

/// One `async-opcua` session and the event loop that keeps it running.
pub(crate) struct LiveSession {
    session: Arc<Session>,
    connected: Arc<AtomicBool>,
    ended: Arc<AtomicBool>,
    event_loop: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LiveSession {
    /// Opens a session, failing fast when nothing answers at the endpoint.
    pub(crate) fn connect(endpoint_url: &str, options: &ConnectOptions) -> Result<Arc<Self>> {
        if !matches!(options.credentials, Credentials::Anonymous)
            && !options.security.is_encrypted()
        {
            return Err(Error::InsecureCredentials);
        }
        if !reachable(endpoint_url, options.reach_timeout) {
            return Err(Error::Connect {
                endpoint: endpoint_url.to_string(),
                status: old::StatusCode::BadNotConnected,
            });
        }

        let endpoint_url = endpoint_url.to_string();
        let options = options.clone();
        catch_panic(|| Ok(block_on(Self::open(endpoint_url.clone(), options)))).map_err(
            |status| Error::Connect {
                endpoint: endpoint_url.clone(),
                status,
            },
        )?
    }

    async fn open(endpoint_url: String, options: ConnectOptions) -> Result<Arc<Self>> {
        let failed = |status: old::StatusCode| Error::Connect {
            endpoint: endpoint_url.clone(),
            status,
        };

        let mut client = ClientBuilder::new()
            .application_name(options.application_name.clone())
            .application_uri(options.application_uri.clone())
            .create_sample_keypair(options.create_sample_keypair)
            .trust_server_certs(options.trust_server_certs)
            .verify_server_certs(options.verify_server_certs)
            .session_timeout(options.session_timeout_ms)
            .session_retry_limit(options.session_retry_limit)
            .session_retry_initial(options.session_retry_interval)
            .request_timeout(REQUEST_TIMEOUT)
            .client()
            .map_err(|errors| Error::ClientBuild(errors.join(", ")))?;

        log::debug!(
            "connecting to {} with {:?} as {:?}",
            endpoint_url,
            options.security,
            options.credentials
        );

        let endpoint: ua::EndpointDescription = (
            endpoint_url.as_str(),
            options.security.policy().to_str(),
            security_mode(options.security),
            token_policy(&options.credentials),
        )
            .into();

        let (session, event_loop) = client
            .connect_to_matching_endpoint(endpoint, identity(&options.credentials))
            .await
            .map_err(|e| failed(old_status(e.status())))?;

        let connected = Arc::new(AtomicBool::new(false));
        let ended = Arc::new(AtomicBool::new(false));
        let mut running = tokio::spawn(drive(
            event_loop.enter(),
            connected.clone(),
            ended.clone(),
            endpoint_url.clone(),
        ));

        let up = tokio::time::timeout(CONNECT_TIMEOUT, async {
            tokio::select! {
                up = session.wait_for_connection() => up,
                _ = &mut running => false,
            }
        })
        .await
        .unwrap_or(false);

        let live = Arc::new(Self {
            session,
            connected,
            ended,
            event_loop: Mutex::new(Some(running)),
        });

        if !up || live.ended.load(Ordering::Relaxed) {
            live.close().await;
            return Err(failed(old::StatusCode::BadNotConnected));
        }

        live.connected.store(true, Ordering::Relaxed);
        log::info!("connected to {}", endpoint_url);
        Ok(live)
    }

    /// Whether the event loop has stopped, so this session will not deliver
    /// again.
    pub(crate) fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Relaxed)
    }

    /// Creates a subscription that hands every value to `on_value`.
    pub(crate) fn create_subscription(
        &self,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        on_value: impl FnMut(ua::DataValue, &MonitoredItem) + Send + Sync + 'static,
    ) -> std::result::Result<u32, old::StatusCode> {
        self.call(move |session| async move {
            session
                .create_subscription(
                    publishing_interval,
                    lifetime_count,
                    max_keep_alive_count,
                    0,
                    0,
                    true,
                    DataChangeCallback::new(on_value),
                )
                .await
        })
    }

    /// Adds items to a subscription, returning each item's status.
    pub(crate) fn create_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: ua::TimestampsToReturn,
        items: Vec<ua::MonitoredItemCreateRequest>,
    ) -> std::result::Result<Vec<ua::StatusCode>, old::StatusCode> {
        self.call(move |session| async move {
            session
                .create_monitored_items(subscription_id, timestamps_to_return, items)
                .await
                .map(|created| {
                    created
                        .into_iter()
                        .map(|item| item.result.status_code)
                        .collect()
                })
        })
    }

    fn call<T, F, Fut>(&self, request: F) -> std::result::Result<T, old::StatusCode>
    where
        F: FnOnce(Arc<Session>) -> Fut,
        Fut: Future<Output = std::result::Result<T, ua::Error>> + Send + 'static,
        T: Send + 'static,
    {
        let future = request(self.session.clone());
        catch_panic(|| block_on(future).map_err(|e| old_status(e.status())))
    }

    async fn close(&self) {
        self.closing().await;
    }

    /// Closes the session and its connection, then makes sure the event loop
    /// and its socket are gone.
    fn closing(&self) -> impl Future<Output = ()> + Send + 'static {
        let session = self.session.clone();
        let connected = self.connected.clone();
        let ended = self.ended.clone();
        let running = self
            .event_loop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();

        async move {
            let closed = tokio::time::timeout(CLOSE_TIMEOUT, session.disconnect()).await;
            if !matches!(closed, Ok(Ok(()))) {
                log::debug!("session not closed cleanly; the server will time it out");
            }
            connected.store(false, Ordering::Relaxed);

            if let Some(mut running) = running {
                if tokio::time::timeout(LOOP_END_TIMEOUT, &mut running)
                    .await
                    .is_err()
                {
                    running.abort();
                }
            }
            ended.store(true, Ordering::Relaxed);
        }
    }
}

/// Runs the session's event loop and keeps the connected flag in step.
async fn drive(
    events: impl futures::Stream<Item = std::result::Result<SessionPollResult, ua::StatusCode>>,
    connected: Arc<AtomicBool>,
    ended: Arc<AtomicBool>,
    endpoint_url: String,
) {
    futures::pin_mut!(events);
    while let Some(event) = events.next().await {
        match event {
            Ok(SessionPollResult::ConnectionLost(status)) => {
                connected.store(false, Ordering::Relaxed);
                log::warn!("connection to {endpoint_url} lost ({status})");
            }
            Ok(SessionPollResult::Reconnected(_)) => connected.store(true, Ordering::Relaxed),
            Ok(_) => {}
            Err(status) => {
                log::debug!("session with {endpoint_url} ended ({status})");
                break;
            }
        }
    }
    connected.store(false, Ordering::Relaxed);
    ended.store(true, Ordering::Relaxed);
}

impl PlcSession for LiveSession {
    fn browse(
        &self,
        nodes_to_browse: &[old::BrowseDescription],
    ) -> std::result::Result<Option<Vec<old::BrowseResult>>, old::StatusCode> {
        let nodes: Vec<ua::BrowseDescription> = to_new_all(nodes_to_browse)?;
        let results = self.call(move |session| async move {
            session.browse(&nodes, MAX_REFERENCES_PER_NODE, None).await
        })?;
        to_old_all(&results).map(Some)
    }

    fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[old::ByteString],
    ) -> std::result::Result<Option<Vec<old::BrowseResult>>, old::StatusCode> {
        let points: Vec<ua::ByteString> = to_new_all(continuation_points)?;
        let results = self.call(move |session| async move {
            session
                .browse_next(release_continuation_points, &points)
                .await
        })?;
        to_old_all(&results).map(Some)
    }

    fn read(
        &self,
        nodes_to_read: &[old::ReadValueId],
        timestamps_to_return: old::TimestampsToReturn,
        max_age: f64,
    ) -> std::result::Result<Vec<old::DataValue>, old::StatusCode> {
        let nodes: Vec<ua::ReadValueId> = to_new_all(nodes_to_read)?;
        let timestamps = timestamps(timestamps_to_return);
        let values = self
            .call(move |session| async move { session.read(&nodes, timestamps, max_age).await })?;
        to_old_all(&values)
    }

    #[cfg(feature = "write")]
    fn write(
        &self,
        nodes_to_write: &[old::WriteValue],
    ) -> std::result::Result<Vec<old::StatusCode>, old::StatusCode> {
        let nodes: Vec<ua::WriteValue> = to_new_all(nodes_to_write)?;
        let results = self.call(move |session| async move { session.write(&nodes).await })?;
        Ok(results.into_iter().map(old_status).collect())
    }

    fn close_session_and_delete_subscriptions(&self) -> std::result::Result<(), old::StatusCode> {
        let closing = self.closing();
        catch_panic(|| {
            block_on(closing);
            Ok(())
        })
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed) && !self.has_ended()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variant::{format_quality, format_variant};

    fn round_trip(value: old::DataValue) -> old::DataValue {
        let new: ua::DataValue = to_new(&value).expect("to async-opcua");
        to_old(&new).expect("back to opcua 0.12")
    }

    #[test]
    fn values_render_the_same_after_crossing_both_crates() {
        let values = vec![
            old::Variant::Boolean(true),
            old::Variant::Int16(-12),
            old::Variant::UInt32(4_000_000_000),
            old::Variant::Float(12.5),
            old::Variant::Double(-0.125),
            old::Variant::from("Pompa \"A\" ok"),
            old::Variant::from(old::DateTime::now()),
            old::Variant::from(vec![1i32, 2, 3]),
            old::Variant::from(old::LocalizedText::new("it", "Allarme")),
            old::Variant::Empty,
        ];
        for value in values {
            let mut data = old::DataValue::new_now(value.clone());
            data.status = Some(old::StatusCode::Good);
            let back = round_trip(data.clone());
            assert_eq!(
                back.value.as_ref().map(format_variant),
                data.value.as_ref().map(format_variant)
            );
            assert_eq!(format_quality(back.status), format_quality(data.status));
            assert_eq!(back.source_timestamp, data.source_timestamp);
        }
    }

    #[test]
    fn a_bad_status_crosses_unchanged() {
        let mut data = old::DataValue::new_now(0i32);
        data.status = Some(old::StatusCode::BadWaitingForInitialData);
        assert_eq!(
            round_trip(data).status,
            Some(old::StatusCode::BadWaitingForInitialData)
        );
    }

    #[test]
    fn a_structure_of_unknown_type_crosses_as_raw_bytes() {
        let body = old::ExtensionObject {
            node_id: old::NodeId::new(3, 5001u32),
            body: old::ExtensionObjectEncoding::ByteString(old::ByteString::from(vec![1u8, 2, 3])),
        };
        let back = round_trip(old::DataValue::new_now(old::Variant::from(body.clone())));
        assert_eq!(back.value, Some(old::Variant::from(body)));
    }

    #[test]
    fn requests_cross_unchanged() {
        let id = old::ReadValueId::from(old::NodeId::new(3, "\"Machine\".\"S_cSemiAuto\""));
        let new: ua::ReadValueId = to_new(&id).unwrap();
        assert_eq!(new.node_id.to_string(), id.node_id.to_string());
        assert_eq!(
            timestamps(old::TimestampsToReturn::Both),
            ua::TimestampsToReturn::Both
        );
    }
}
