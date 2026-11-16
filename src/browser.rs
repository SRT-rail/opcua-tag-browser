//! Listing the children of a node, with pagination handled.

use crate::error::{Error, Result};
use crate::session::PlcSession;
use opcua::client::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A child node discovered while browsing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BrowsedNode {
    /// Identifier of the discovered node.
    pub node_id: NodeId,
    /// Text of the node's `DisplayName` attribute.
    pub display_name: String,
    /// The node's `BrowseName`, namespace-qualified.
    ///
    /// Stable across server locales, unlike `display_name`.
    pub browse_name: String,
    /// Class of the discovered node.
    pub node_class: NodeClass,
    /// `TypeDefinition` node ID, when the browse returned one.
    pub type_definition: Option<NodeId>,
    /// Reference type that reached this node, when the browse returned one.
    pub reference_type: Option<NodeId>,
}
impl BrowsedNode {
    /// Builds a browsed node record.
    ///
    /// Provided so callers outside this crate — test doubles, alternative
    /// [`NodeBrowser`] backends — can construct values despite
    /// `#[non_exhaustive]`.
    pub fn new(
        node_id: NodeId,
        display_name: impl Into<String>,
        browse_name: impl Into<String>,
        node_class: NodeClass,
    ) -> Self {
        Self {
            node_id,
            display_name: display_name.into(),
            browse_name: browse_name.into(),
            node_class,
            type_definition: None,
            reference_type: None,
        }
    }

    /// Sets the `TypeDefinition` node ID.
    pub fn with_type_definition(mut self, type_definition: NodeId) -> Self {
        self.type_definition = Some(type_definition);
        self
    }

    /// Sets the reference type that reached this node.
    pub fn with_reference_type(mut self, reference_type: NodeId) -> Self {
        self.reference_type = Some(reference_type);
        self
    }
}

/// Nodes asked for in one `Browse` request; halved while the server refuses that many.
const BROWSE_BATCH: usize = 50;

/// Requests in a row the server leaves unanswered before the rest are not asked for.
const GIVE_UP_AFTER: usize = 8;

/// Lists the children of a node.
///
/// Implement this to drive [`TreeScanner`](crate::TreeScanner) against a fake
/// address space in tests, or against a cached snapshot.
pub trait NodeBrowser {
    /// Returns every child of `node_id`, following continuation points.
    fn children_of(&self, node_id: &NodeId) -> Result<Vec<BrowsedNode>>;

    /// Returns the children of each node, in the order given, following continuation points.
    ///
    /// The default asks for one node at a time with [`children_of`](Self::children_of);
    /// a live browser asks for many nodes per request.
    fn children_of_many(&self, node_ids: &[NodeId]) -> Vec<Result<Vec<BrowsedNode>>> {
        node_ids
            .iter()
            .map(|node_id| self.children_of(node_id))
            .collect()
    }
}

/// A [`NodeBrowser`] backed by a live session.
pub struct OpcUaNodeBrowser {
    session: Arc<dyn PlcSession>,
    batch: AtomicUsize,
}

impl OpcUaNodeBrowser {
    /// Creates a browser over the given session.
    pub fn new(session: Arc<dyn PlcSession>) -> Self {
        Self {
            session,
            batch: AtomicUsize::new(BROWSE_BATCH),
        }
    }

    fn follow(&self, node_id: &NodeId, result: BrowseResult) -> Result<Vec<BrowsedNode>> {
        if result.status_code.is_bad() {
            return Err(browse_error(node_id, result.status_code));
        }
        let mut children = Vec::new();
        append_references(&result.references, &mut children);

        let mut point = result.continuation_point;
        while has_more(&point) {
            let next = match self.session.browse_next(false, &[point.clone()]) {
                Ok(Some(next)) => next,
                Ok(None) => break,
                Err(status) => {
                    let _ = self.session.browse_next(true, &[point]);
                    return Err(browse_error(node_id, status));
                }
            };
            let mut next_point = ByteString::null();
            for next_result in next {
                if next_result.status_code.is_bad() {
                    return Err(browse_error(node_id, next_result.status_code));
                }
                append_references(&next_result.references, &mut children);
                next_point = next_result.continuation_point;
            }
            point = next_point;
        }
        Ok(children)
    }
}

impl NodeBrowser for OpcUaNodeBrowser {
    fn children_of(&self, node_id: &NodeId) -> Result<Vec<BrowsedNode>> {
        let results = self
            .session
            .browse(&[describe(node_id)])
            .map_err(|status| browse_error(node_id, status))?;

        let mut children = Vec::new();
        for result in results.unwrap_or_default() {
            children.extend(self.follow(node_id, result)?);
        }

        log::trace!("{} has {} children", node_id, children.len());
        Ok(children)
    }

    fn children_of_many(&self, node_ids: &[NodeId]) -> Vec<Result<Vec<BrowsedNode>>> {
        let mut answers = Vec::with_capacity(node_ids.len());
        let mut size = self.batch.load(Ordering::Relaxed).max(1);
        let mut unanswered = 0;

        while answers.len() < node_ids.len() {
            let start = answers.len();
            let batch = &node_ids[start..(start + size).min(node_ids.len())];
            let descriptions: Vec<BrowseDescription> = batch.iter().map(describe).collect();

            match self.session.browse(&descriptions) {
                Ok(Some(results)) if results.len() == batch.len() => {
                    unanswered = 0;
                    for (node_id, result) in batch.iter().zip(results) {
                        answers.push(self.follow(node_id, result));
                    }
                }
                Ok(_) | Err(_) if size > 1 => {
                    size = (size / 2).max(1);
                    self.batch.store(size, Ordering::Relaxed);
                    log::debug!(
                        "the server refused {} nodes per browse, asking for {size}",
                        batch.len()
                    );
                }
                Ok(_) => {
                    unanswered = 0;
                    answers.push(self.children_of(&batch[0]));
                }
                Err(status) => {
                    answers.push(Err(browse_error(&batch[0], status)));
                    unanswered = if passing(status) { unanswered + 1 } else { 0 };
                    if unanswered >= GIVE_UP_AFTER {
                        let rest = &node_ids[answers.len()..];
                        answers.extend(
                            rest.iter()
                                .map(|node_id| Err(browse_error(node_id, status))),
                        );
                    }
                }
            }
        }

        log::trace!("{} nodes browsed", node_ids.len());
        answers
    }
}

fn describe(node_id: &NodeId) -> BrowseDescription {
    BrowseDescription {
        node_id: node_id.clone(),
        browse_direction: BrowseDirection::Forward,
        reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
        include_subtypes: true,
        node_class_mask: 0,
        result_mask: BrowseResultMask::All as u32,
    }
}

fn browse_error(node_id: &NodeId, status: StatusCode) -> Error {
    Error::Browse {
        node_id: node_id.to_string(),
        status,
    }
}

/// Failures the server or the link may recover from; anything else is an answer.
pub(crate) fn passing(status: StatusCode) -> bool {
    let code = status.bits() & StatusCode::STATUS_MASK.bits();
    [
        StatusCode::BadTimeout,
        StatusCode::BadRequestTimeout,
        StatusCode::BadTooManyOperations,
        StatusCode::BadResourceUnavailable,
        StatusCode::BadTcpServerTooBusy,
        StatusCode::BadNoContinuationPoints,
        StatusCode::BadCommunicationError,
        StatusCode::BadConnectionClosed,
        StatusCode::BadSecureChannelClosed,
        StatusCode::BadNotConnected,
        StatusCode::BadSessionClosed,
        StatusCode::BadSessionIdInvalid,
        StatusCode::BadServerHalted,
        StatusCode::BadOutOfMemory,
        StatusCode::BadInternalError,
        StatusCode::BadUnexpectedError,
    ]
    .iter()
    .any(|known| known.bits() == code)
}

/// Returns true when a continuation point carries a non-empty value.
///
/// A present-but-empty byte string would otherwise loop forever.
fn has_more(point: &ByteString) -> bool {
    point.value.as_ref().is_some_and(|bytes| !bytes.is_empty())
}

/// Converts raw reference descriptions into [`BrowsedNode`] values.
fn append_references(references: &Option<Vec<ReferenceDescription>>, out: &mut Vec<BrowsedNode>) {
    let Some(references) = references else { return };
    for reference in references {
        let type_definition = reference.type_definition.node_id.clone();
        out.push(BrowsedNode {
            node_id: reference.node_id.node_id.clone(),
            display_name: reference.display_name.text.to_string(),
            browse_name: reference.browse_name.name.to_string(),
            node_class: reference.node_class,
            type_definition: (!type_definition.is_null()).then_some(type_definition),
            reference_type: (!reference.reference_type_id.is_null())
                .then(|| reference.reference_type_id.clone()),
        });
    }
}
