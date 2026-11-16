//! Many nodes per Browse request, within what the server accepts.

use opcua_tag_browser::opcua::client::prelude::*;
use opcua_tag_browser::{AcceptAll, OpcUaNodeBrowser, PlcSession, ScanOptions, TreeScanner};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

struct FakePlc {
    tree: HashMap<String, Vec<(NodeId, String, NodeClass)>>,
    most_per_request: usize,
    page: usize,
    accepted: Mutex<Vec<usize>>,
    refused: Mutex<usize>,
    open_points: Mutex<HashMap<Vec<u8>, (String, usize)>>,
    next_point: Mutex<u8>,
}

impl FakePlc {
    fn new(most_per_request: usize, page: usize) -> Self {
        Self {
            tree: HashMap::new(),
            most_per_request,
            page,
            accepted: Mutex::new(Vec::new()),
            refused: Mutex::new(0),
            open_points: Mutex::new(HashMap::new()),
            next_point: Mutex::new(0),
        }
    }

    fn with(mut self, parent: &NodeId, children: Vec<(NodeId, &str, NodeClass)>) -> Self {
        let children = children
            .into_iter()
            .map(|(id, name, class)| (id, name.to_string(), class))
            .collect();
        self.tree.insert(parent.to_string(), children);
        self
    }

    fn page_of(&self, key: &str, from: usize) -> BrowseResult {
        let children = self.tree.get(key).cloned().unwrap_or_default();
        let to = (from + self.page).min(children.len());
        let references = children[from..to]
            .iter()
            .map(|(id, name, class)| ReferenceDescription {
                reference_type_id: ReferenceTypeId::Organizes.into(),
                is_forward: true,
                node_id: ExpandedNodeId::from(id.clone()),
                browse_name: QualifiedName::new(2, name.as_str()),
                display_name: LocalizedText::new("", name),
                node_class: *class,
                type_definition: ExpandedNodeId::null(),
            })
            .collect();
        let continuation_point = if to < children.len() {
            let mut counter = self.next_point.lock().unwrap();
            *counter += 1;
            let point = vec![*counter];
            self.open_points
                .lock()
                .unwrap()
                .insert(point.clone(), (key.to_string(), to));
            ByteString::from(point)
        } else {
            ByteString::null()
        };
        BrowseResult {
            status_code: StatusCode::Good,
            continuation_point,
            references: Some(references),
        }
    }
}

impl PlcSession for FakePlc {
    fn browse(&self, nodes: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if nodes.len() > self.most_per_request {
            *self.refused.lock().unwrap() += 1;
            return Err(StatusCode::BadTooManyOperations);
        }
        self.accepted.lock().unwrap().push(nodes.len());
        Ok(Some(
            nodes
                .iter()
                .map(|n| self.page_of(&n.node_id.to_string(), 0))
                .collect(),
        ))
    }

    fn browse_next(
        &self,
        release: bool,
        points: &[ByteString],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        let mut results = Vec::new();
        for point in points {
            let bytes = point.value.clone().unwrap_or_default();
            let open = self.open_points.lock().unwrap().remove(&bytes);
            results.push(match (open, release) {
                (Some(_), true) => BrowseResult {
                    status_code: StatusCode::Good,
                    continuation_point: ByteString::null(),
                    references: None,
                },
                (Some((key, from)), false) => self.page_of(&key, from),
                (None, _) => BrowseResult {
                    status_code: StatusCode::BadContinuationPointInvalid,
                    continuation_point: ByteString::null(),
                    references: None,
                },
            });
        }
        Ok(Some(results))
    }

    fn read(
        &self,
        _: &[ReadValueId],
        _: TimestampsToReturn,
        _: f64,
    ) -> Result<Vec<DataValue>, StatusCode> {
        Err(StatusCode::BadNotSupported)
    }

    #[cfg(feature = "write")]
    fn write(&self, _: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode> {
        Err(StatusCode::BadNotSupported)
    }

    fn close_session_and_delete_subscriptions(&self) -> Result<(), StatusCode> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }
}

fn id(name: &str) -> NodeId {
    NodeId::new(3, name.to_string())
}

#[test]
fn many_nodes_go_in_one_request_and_never_more_than_the_server_accepts() {
    let root = id("root");
    let blocks: Vec<(NodeId, String)> = (0..120)
        .map(|i| (id(&format!("db{i}")), format!("DB{i}")))
        .collect();
    let mut plc = FakePlc::new(20, 1000).with(
        &root,
        blocks
            .iter()
            .map(|(node, name)| (node.clone(), name.as_str(), NodeClass::Object))
            .collect(),
    );
    for (node, _) in &blocks {
        plc = plc.with(
            node,
            vec![(id(&format!("{node}.speed")), "Speed", NodeClass::Variable)],
        );
    }
    let plc = Arc::new(plc);
    let browser = OpcUaNodeBrowser::new(plc.clone());

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    assert_eq!(report.tags.len(), 120);
    assert!(report.is_complete());
    let paths: HashSet<&str> = report.tags.iter().map(|t| t.path.as_str()).collect();
    assert_eq!(paths.len(), 120, "no tag twice");
    let accepted = plc.accepted.lock().unwrap();
    assert!(
        accepted.iter().all(|&n| n <= 20),
        "never more than the server takes: {accepted:?}"
    );
    assert!(
        accepted.len() < 30,
        "far fewer requests than the 241 nodes: {}",
        accepted.len()
    );
    assert!(
        *plc.refused.lock().unwrap() <= 2,
        "it learns the limit and stays under it"
    );
}

#[test]
fn a_long_list_is_read_page_by_page_and_no_page_is_left_open() {
    let root = id("root");
    let db = id("db");
    let members: Vec<(NodeId, String)> = (0..250)
        .map(|i| (id(&format!("v{i}")), format!("V{i}")))
        .collect();
    let plc = Arc::new(
        FakePlc::new(50, 100)
            .with(&root, vec![(db.clone(), "DB", NodeClass::Object)])
            .with(
                &db,
                members
                    .iter()
                    .map(|(node, name)| (node.clone(), name.as_str(), NodeClass::Variable))
                    .collect(),
            ),
    );
    let browser = OpcUaNodeBrowser::new(plc.clone());

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    assert_eq!(report.tags.len(), 250);
    assert_eq!(report.tags[0].path, "DB/V0");
    assert_eq!(report.tags[249].path, "DB/V249");
    assert!(
        plc.open_points.lock().unwrap().is_empty(),
        "every page followed to the end"
    );
}
