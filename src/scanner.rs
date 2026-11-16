//! Walking an address space into a flat tag list.

use crate::browser::{passing, BrowsedNode, NodeBrowser};
use crate::error::{Error, Result};
use crate::filter::NodeFilter;
use crate::tag::PlcTag;
use opcua::client::prelude::{NodeClass, NodeId, ReferenceTypeId, StatusCode};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Failures in a row, after their retries, that end a scan: the server has stopped answering.
const GIVE_UP_AFTER: usize = 8;

/// Tuning knobs for a scan.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScanOptions {
    /// Maximum recursion depth below the root node.
    ///
    /// Guards against pathological address spaces. Twelve levels covers a
    /// typical PLC data-block hierarchy with room to spare.
    pub max_depth: usize,

    /// Whether to descend into the children of `Variable` nodes.
    ///
    /// Structured tags expose their members as child variables, so this is
    /// usually what you want. Turn it off to collect only top-level variables.
    pub descend_into_variables: bool,

    /// Whether to include nodes reached via `HasProperty`.
    ///
    /// Properties are metadata (`EngineeringUnits`, `EURange`) rather than
    /// process data, and on a typical server there is one such node per
    /// variable — leaving this off roughly halves a scan's tag count.
    pub include_properties: bool,

    /// How many more times a node is browsed after a failure the server may
    /// recover from (busy, timeout, a dropped link), before its subtree is skipped.
    pub retries: u32,

    /// Pause before the first retry; each later retry waits three times longer.
    pub retry_pause: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_depth: 12,
            descend_into_variables: true,
            include_properties: false,
            retries: 2,
            retry_pause: Duration::from_millis(300),
        }
    }
}

impl ScanOptions {
    /// Sets the maximum recursion depth below the root node.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Sets whether to descend into the children of `Variable` nodes.
    pub fn descend_into_variables(mut self, yes: bool) -> Self {
        self.descend_into_variables = yes;
        self
    }

    /// Sets whether to include nodes reached via `HasProperty`.
    pub fn include_properties(mut self, yes: bool) -> Self {
        self.include_properties = yes;
        self
    }

    /// Sets how many more times a node is browsed after a failure the server may recover from.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Sets the pause before the first retry.
    pub fn retry_pause(mut self, pause: Duration) -> Self {
        self.retry_pause = pause;
        self
    }
}

/// The outcome of a scan, including the subtrees that could not be read.
///
/// Partial results are reported rather than silently dropped: a scan that
/// returns 2,400 tags because one subtree failed looks identical to a healthy
/// 2,400-tag scan unless the failure is surfaced.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ScanReport {
    /// Every variable node discovered, in browse order.
    pub tags: Vec<PlcTag>,
    /// Subtrees that could not be browsed, paired with the reason.
    pub skipped: Vec<(String, Error)>,
}

impl ScanReport {
    /// Returns `true` when no subtree was skipped.
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty()
    }

    /// Consumes the report and returns just the tags.
    pub fn into_tags(self) -> Vec<PlcTag> {
        self.tags
    }
}

/// Recursively walks an address space, collecting variable nodes as tags.
///
/// The tree is read one level at a time, many nodes per request through
/// [`NodeBrowser::children_of_many`], and a node reached by more than one path
/// is browsed once. The result is the same as walking it node by node: every
/// path to a node is listed, in depth-first order.
pub struct TreeScanner<'a> {
    browser: &'a dyn NodeBrowser,
    filter: &'a dyn NodeFilter,
    options: ScanOptions,
    progress: Option<&'a dyn Fn(&ScanProgress)>,
}

/// Where a running scan is, for showing it while it runs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScanProgress {
    /// Nodes whose children have been asked for so far.
    pub nodes: usize,
    /// Distinct tags found so far; a tag reached by two paths counts once.
    pub tags: usize,
    /// Path of a node being read now, such as `CAB/DataBlocksGlobal/ECUtoPLC`.
    pub at: String,
}

/// Nodes asked for between two progress reports.
const PROGRESS_STEP: usize = 200;

struct Frame {
    node_id: NodeId,
    path: String,
    depth: usize,
    ancestors: Vec<String>,
    outcome: Option<Result<Vec<BrowsedNode>>>,
    kids: Vec<Option<usize>>,
}

impl<'a> TreeScanner<'a> {
    /// Creates a scanner over the given browser and filter.
    pub fn new(
        browser: &'a dyn NodeBrowser,
        filter: &'a dyn NodeFilter,
        options: ScanOptions,
    ) -> Self {
        Self {
            browser,
            filter,
            options,
            progress: None,
        }
    }

    /// Calls `report` while the scan runs, before each group of requests it sends.
    pub fn on_progress(mut self, report: &'a dyn Fn(&ScanProgress)) -> Self {
        self.progress = Some(report);
        self
    }

    /// Scans everything reachable from `root`.
    ///
    /// Fails if `root` itself cannot be browsed, or if the server stops
    /// answering during the scan, so that a half-read tree is never taken for
    /// the whole one. A subtree the server refuses is recorded in
    /// [`ScanReport::skipped`].
    ///
    /// ```no_run
    /// use opcua_tag_browser::{
    ///     connect, ConnectOptions, DefaultNodeFilter, OpcUaNodeBrowser,
    ///     OpcUaSession, PlcSession, ScanOptions, TreeScanner,
    /// };
    /// use opcua_tag_browser::opcua::client::prelude::NodeId;
    /// use std::sync::Arc;
    ///
    /// # fn main() -> opcua_tag_browser::Result<()> {
    /// let raw = connect("opc.tcp://localhost:4840", &ConnectOptions::default())?;
    /// let session: Arc<dyn PlcSession> = Arc::new(OpcUaSession::new(raw));
    /// let browser = OpcUaNodeBrowser::new(session);
    /// let report = TreeScanner::new(&browser, &DefaultNodeFilter, ScanOptions::default())
    ///     .scan(NodeId::objects_folder_id())?;
    ///
    /// println!("{} tags", report.tags.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn scan(&self, root: NodeId) -> Result<ScanReport> {
        let children = self.browser.children_of(&root)?;

        let mut known: HashMap<String, Vec<BrowsedNode>> = HashMap::new();
        let mut refused: HashMap<String, StatusCode> = HashMap::new();
        let mut found: HashSet<String> = HashSet::new();
        self.count(&children, &mut found);
        known.insert(root.to_string(), children.clone());
        let mut frames = vec![Frame {
            ancestors: vec![root.to_string()],
            node_id: root,
            path: String::new(),
            depth: 1,
            outcome: Some(Ok(children)),
            kids: Vec::new(),
        }];

        let mut level = vec![0];
        while !level.is_empty() {
            let mut next = Vec::new();
            for id in level {
                let planned = self.plan(&frames[id]);
                let mut kids = Vec::with_capacity(planned.len());
                for frame in planned {
                    kids.push(frame.map(|frame| {
                        frames.push(frame);
                        next.push(frames.len() - 1);
                        frames.len() - 1
                    }));
                }
                frames[id].kids = kids;
            }
            self.fetch(&mut frames, &next, &mut known, &mut refused, &mut found)?;
            level = next;
        }

        let mut report = ScanReport::default();
        self.emit(&mut frames, 0, &mut report);

        log::info!(
            "scan finished: {} tags, {} subtrees skipped, {} nodes browsed",
            report.tags.len(),
            report.skipped.len(),
            known.len()
        );
        Ok(report)
    }

    fn accepted(&self, child: &BrowsedNode) -> bool {
        self.filter.accepts(&child.display_name)
            && (self.options.include_properties || !is_property(child))
    }

    fn plan(&self, frame: &Frame) -> Vec<Option<Frame>> {
        let Some(Ok(children)) = &frame.outcome else {
            return Vec::new();
        };
        if frame.depth > self.options.max_depth {
            return children.iter().map(|_| None).collect();
        }
        children
            .iter()
            .map(|child| self.child_frame(frame, child))
            .collect()
    }

    fn child_frame(&self, frame: &Frame, child: &BrowsedNode) -> Option<Frame> {
        if !self.accepted(child) {
            return None;
        }
        let recurse = match child.node_class {
            NodeClass::Variable => self.options.descend_into_variables,
            NodeClass::Object => true,
            _ => false,
        };
        if !recurse || frame.depth + 1 > self.options.max_depth {
            return None;
        }
        let key = child.node_id.to_string();
        if frame.ancestors.contains(&key) {
            log::trace!("cycle at {key}, not descending");
            return None;
        }
        let mut ancestors = frame.ancestors.clone();
        ancestors.push(key);
        Some(Frame {
            node_id: child.node_id.clone(),
            path: join_path(&frame.path, &child.browse_name),
            depth: frame.depth + 1,
            ancestors,
            outcome: None,
            kids: Vec::new(),
        })
    }

    fn count(&self, children: &[BrowsedNode], found: &mut HashSet<String>) {
        for child in children {
            if child.node_class == NodeClass::Variable && self.accepted(child) {
                found.insert(child.node_id.to_string());
            }
        }
    }

    fn fetch(
        &self,
        frames: &mut [Frame],
        level: &[usize],
        known: &mut HashMap<String, Vec<BrowsedNode>>,
        refused: &mut HashMap<String, StatusCode>,
        found: &mut HashSet<String>,
    ) -> Result<()> {
        let mut wanted: Vec<(NodeId, String)> = Vec::new();
        let mut asked: HashSet<String> = HashSet::new();
        for &id in level {
            let key = frames[id].node_id.to_string();
            if !known.contains_key(&key) && !refused.contains_key(&key) && asked.insert(key) {
                wanted.push((frames[id].node_id.clone(), frames[id].path.clone()));
            }
        }

        let mut failing = 0;
        for step in wanted.chunks(PROGRESS_STEP) {
            if let Some(report) = self.progress {
                report(&ScanProgress {
                    nodes: known.len() + refused.len(),
                    tags: found.len(),
                    at: step[0].1.clone(),
                });
            }
            let node_ids: Vec<NodeId> = step.iter().map(|(node_id, _)| node_id.clone()).collect();
            let answers = self.browser.children_of_many(&node_ids);
            for (node_id, answer) in node_ids.iter().zip(answers) {
                match self.retried(node_id, answer) {
                    Ok(children) => {
                        failing = 0;
                        self.count(&children, found);
                        known.insert(node_id.to_string(), children);
                    }
                    Err(e) => {
                        let status = status_of(&e);
                        failing = if passing(status) { failing + 1 } else { 0 };
                        if failing >= GIVE_UP_AFTER {
                            log::warn!("the server stopped answering during the scan: {e}");
                            return Err(e);
                        }
                        refused.insert(node_id.to_string(), status);
                    }
                }
            }
        }

        for &id in level {
            let key = frames[id].node_id.to_string();
            frames[id].outcome = Some(match known.get(&key) {
                Some(children) => Ok(children.clone()),
                None => Err(Error::Browse {
                    status: refused
                        .get(&key)
                        .copied()
                        .unwrap_or(StatusCode::BadUnexpectedError),
                    node_id: key,
                }),
            });
        }
        Ok(())
    }

    fn retried(
        &self,
        node_id: &NodeId,
        first: Result<Vec<BrowsedNode>>,
    ) -> Result<Vec<BrowsedNode>> {
        let mut answer = first;
        for attempt in 0..self.options.retries {
            let Err(e) = &answer else { break };
            if !passing(status_of(e)) {
                break;
            }
            log::debug!("browse of {node_id} failed ({e}), trying again");
            std::thread::sleep(self.options.retry_pause * 3u32.pow(attempt));
            answer = self.browser.children_of(node_id);
        }
        answer
    }

    fn emit(&self, frames: &mut Vec<Frame>, id: usize, report: &mut ScanReport) {
        if frames[id].depth > self.options.max_depth {
            return;
        }
        let Some(Ok(children)) = frames[id].outcome.take() else {
            return;
        };
        let kids = std::mem::take(&mut frames[id].kids);
        let parent_path = frames[id].path.clone();

        for (index, child) in children.into_iter().enumerate() {
            if !self.accepted(&child) {
                continue;
            }
            if child.node_class == NodeClass::Variable {
                let mut tag = PlcTag::new(
                    child.display_name.clone(),
                    child.browse_name.clone(),
                    child.node_id.to_string(),
                    format!("{:?}", child.node_class),
                    join_path(&parent_path, &child.browse_name),
                );
                tag.type_definition = child.type_definition.as_ref().map(ToString::to_string);
                tag.reference_type = child.reference_type.as_ref().map(ToString::to_string);
                report.tags.push(tag);
            }

            let Some(kid) = kids.get(index).copied().flatten() else {
                continue;
            };
            match frames[kid].outcome.take() {
                Some(Ok(grandchildren)) => {
                    frames[kid].outcome = Some(Ok(grandchildren));
                    self.emit(frames, kid, report);
                }
                Some(Err(e)) => {
                    let key = frames[kid].node_id.to_string();
                    log::warn!("skipping subtree {key}: {e}");
                    report.skipped.push((key, e));
                }
                None => {}
            }
        }
    }
}

fn status_of(error: &Error) -> StatusCode {
    match error {
        Error::Browse { status, .. } => *status,
        _ => StatusCode::BadUnexpectedError,
    }
}

/// Joins a parent browse path and a child name with `/`.
fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", parent, name)
    }
}

/// Whether a browsed node was reached via `HasProperty`.
fn is_property(child: &BrowsedNode) -> bool {
    let has_property: NodeId = ReferenceTypeId::HasProperty.into();
    child
        .reference_type
        .as_ref()
        .is_some_and(|r| *r == has_property)
}
