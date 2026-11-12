//! Session abstraction over the `opcua` client.

use opcua::client::prelude::*;
use opcua::sync::RwLock;
use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

/// The OPC UA session operations this crate needs.
///
/// Kept object safe so scanning and writing logic can be exercised against a
/// fake session in tests without a live server.
pub trait PlcSession: Send + Sync {
    /// Lists child nodes for the supplied browse descriptions.
    fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode>;

    /// Continues a paginated browse using continuation points.
    fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode>;

    /// Reads node values directly from the server.
    fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode>;

    /// Writes values to nodes on the server.
    ///
    /// The returned status codes correspond one to one with `nodes_to_write`;
    /// an overall `Ok` does not mean every individual write succeeded.
    #[cfg(feature = "write")]
    fn write(&self, nodes_to_write: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode>;

    /// Closes the session and deletes its subscriptions server-side, then drops
    /// the connection.
    ///
    /// Call this on shutdown: without it the server holds monitored items until
    /// the session times out, which counts against its item budget. The session
    /// cannot be used afterwards.
    fn close_session_and_delete_subscriptions(&self) -> Result<(), StatusCode>;

    /// Reports whether the transport is currently connected.
    fn is_connected(&self) -> bool;

    /// What this session was opened with: the id the server gave it, the
    /// security, the server's certificate and the user.
    ///
    /// `None` when the session does not know it.
    fn connection_info(&self) -> Option<crate::connection::ConnectionInfo> {
        None
    }
}

/// A [`PlcSession`] backed by a live `opcua` client session.
///
/// Every call is wrapped in [`catch_panic`], so a panic inside the `opcua`
/// crate surfaces as [`StatusCode::BadUnexpectedError`] instead of tearing down
/// the calling thread.
pub struct OpcUaSession {
    session: Arc<RwLock<Session>>,
}

impl OpcUaSession {
    /// Wraps an existing `opcua` session.
    pub fn new(session: Arc<RwLock<Session>>) -> Self {
        Self { session }
    }

    /// Returns the wrapped session.
    ///
    /// Use this for operations outside this crate's scope, such as calling
    /// server methods or reading history. The raw session can also write and
    /// call methods, so it is part of the `write` feature.
    #[cfg(feature = "write")]
    pub fn inner(&self) -> &Arc<RwLock<Session>> {
        &self.session
    }
}

impl PlcSession for OpcUaSession {
    fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        catch_panic(|| self.session.read().browse(nodes_to_browse))
    }

    fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        catch_panic(|| {
            self.session
                .read()
                .browse_next(release_continuation_points, continuation_points)
        })
    }

    fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode> {
        catch_panic(|| {
            self.session
                .read()
                .read(nodes_to_read, timestamps_to_return, max_age)
        })
    }

    #[cfg(feature = "write")]
    fn write(&self, nodes_to_write: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode> {
        catch_panic(|| self.session.read().write(nodes_to_write))
    }

    fn close_session_and_delete_subscriptions(&self) -> Result<(), StatusCode> {
        let closed = catch_panic(|| self.session.read().close_session_and_delete_subscriptions());
        let _ = catch_panic(|| {
            let session = self.session.read();
            if session.is_connected() {
                session.close_secure_channel()
            } else {
                Ok(())
            }
        });
        closed
    }

    fn is_connected(&self) -> bool {
        catch_panic(|| {
            if self.session.read().is_connected() {
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .unwrap_or(false)
    }
}

/// A session lent out by its owner: everything but closing it.
pub(crate) struct Borrowed(pub(crate) Arc<dyn PlcSession>);

impl PlcSession for Borrowed {
    fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        self.0.browse(nodes_to_browse)
    }

    fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        self.0
            .browse_next(release_continuation_points, continuation_points)
    }

    fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode> {
        self.0.read(nodes_to_read, timestamps_to_return, max_age)
    }

    #[cfg(feature = "write")]
    fn write(&self, nodes_to_write: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode> {
        self.0.write(nodes_to_write)
    }

    fn close_session_and_delete_subscriptions(&self) -> Result<(), StatusCode> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }

    fn connection_info(&self) -> Option<crate::connection::ConnectionInfo> {
        self.0.connection_info()
    }
}

/// Runs a closure, converting any panic into [`StatusCode::BadUnexpectedError`].
///
/// The `opcua` crate panics on some malformed server responses. In a long-lived
/// data collector that would kill the worker thread, so it is converted to an
/// error the caller can retry.
pub fn catch_panic<T>(f: impl FnOnce() -> Result<T, StatusCode>) -> Result<T, StatusCode> {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|payload| {
        log::error!("internal panic recovered: {}", panic_message(&payload));
        Err(StatusCode::BadUnexpectedError)
    })
}

/// Extracts a readable message from a panic payload.
pub fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message.to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}
