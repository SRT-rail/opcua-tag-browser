//! Scanner behaviour against a fake address space.

use opcua_tag_browser::opcua::client::prelude::{NodeClass, NodeId, ReferenceTypeId, StatusCode};
use opcua_tag_browser::{
    AcceptAll, BrowsedNode, DefaultNodeFilter, Error, NodeBrowser, ScanOptions, ScanProgress,
    TreeScanner,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

struct FakeBrowser {
    children: HashMap<String, Vec<BrowsedNode>>,
}

impl FakeBrowser {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }

    fn with(mut self, parent: &NodeId, children: Vec<BrowsedNode>) -> Self {
        self.children.insert(parent.to_string(), children);
        self
    }
}

impl NodeBrowser for FakeBrowser {
    fn children_of(&self, node_id: &NodeId) -> opcua_tag_browser::Result<Vec<BrowsedNode>> {
        Ok(self
            .children
            .get(&node_id.to_string())
            .cloned()
            .unwrap_or_default())
    }
}

fn node(id: &str, name: &str, class: NodeClass) -> BrowsedNode {
    BrowsedNode::new(NodeId::new(2, id.to_string()), name, name, class)
}

fn property(id: &str, browse_name: &str, display_name: &str, class: NodeClass) -> BrowsedNode {
    BrowsedNode::new(
        NodeId::new(2, id.to_string()),
        display_name,
        browse_name,
        class,
    )
    .with_reference_type(ReferenceTypeId::HasProperty.into())
}

#[test]
fn collects_variables_and_records_their_path() {
    let root = NodeId::new(2, "root");
    let machine = node("machine", "Machine", NodeClass::Object);
    let speed = node("speed", "Speed", NodeClass::Variable);

    let browser = FakeBrowser::new()
        .with(&root, vec![machine.clone()])
        .with(&machine.node_id, vec![speed]);

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .expect("scan should succeed");

    assert_eq!(report.tags.len(), 1);
    assert_eq!(report.tags[0].path, "Machine/Speed");
    assert!(report.is_complete());
}

#[test]
fn default_filter_drops_server_furniture() {
    let root = NodeId::new(2, "root");
    let browser = FakeBrowser::new().with(
        &root,
        vec![
            node("icon", "Icon", NodeClass::Variable),
            node("sep", "------", NodeClass::Variable),
            node("real", "Speed", NodeClass::Variable),
        ],
    );

    let report = TreeScanner::new(&browser, &DefaultNodeFilter, ScanOptions::default())
        .scan(root)
        .unwrap();

    assert_eq!(report.tags.len(), 1);
    assert_eq!(report.tags[0].display_name, "Speed");
}

#[test]
fn cyclic_references_terminate() {
    let root = NodeId::new(2, "root");
    let a = node("a", "A", NodeClass::Object);
    let b = node("b", "B", NodeClass::Object);

    let browser = FakeBrowser::new()
        .with(&root, vec![a.clone()])
        .with(&a.node_id, vec![b.clone()])
        .with(&b.node_id, vec![a.clone()]);

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    assert!(report.tags.is_empty());
}

#[test]
fn shared_node_is_expanded_under_every_path() {
    let root = NodeId::new(2, "root");
    let f = node("f", "F", NodeClass::Object);
    let b = node("b", "B", NodeClass::Object);
    let shared = node("shared", "H", NodeClass::Object);
    let leaf = node("leaf", "Value", NodeClass::Variable);

    let browser = FakeBrowser::new()
        .with(&root, vec![f.clone(), b.clone()])
        .with(&f.node_id, vec![shared.clone()])
        .with(&b.node_id, vec![shared.clone()])
        .with(&shared.node_id, vec![leaf]);

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    let paths: Vec<&str> = report.tags.iter().map(|t| t.path.as_str()).collect();
    assert!(paths.contains(&"F/H/Value"), "got {paths:?}");
    assert!(paths.contains(&"B/H/Value"), "got {paths:?}");
}

#[test]
fn depth_limit_is_respected() {
    let root = NodeId::new(2, "root");
    let level1 = node("l1", "L1", NodeClass::Object);
    let deep = node("deep", "Deep", NodeClass::Variable);

    let browser = FakeBrowser::new()
        .with(&root, vec![level1.clone()])
        .with(&level1.node_id, vec![deep]);

    let mut options = ScanOptions::default();
    options.max_depth = 1;

    let report = TreeScanner::new(&browser, &AcceptAll, options)
        .scan(root)
        .unwrap();

    assert!(report.tags.is_empty());
}

#[test]
fn path_is_built_from_browse_name_not_display_name() {
    let root = NodeId::new(2, "root");
    let speed = BrowsedNode::new(
        NodeId::new(2, "speed"),
        "Geschwindigkeit",
        "Speed",
        NodeClass::Variable,
    );

    let browser = FakeBrowser::new().with(&root, vec![speed]);

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    assert_eq!(report.tags[0].path, "Speed");
    assert_eq!(report.tags[0].display_name, "Geschwindigkeit");
}

#[test]
fn properties_are_excluded_by_default() {
    let root = NodeId::new(2, "root");
    let speed = node("speed", "Speed", NodeClass::Variable);
    let units = property(
        "units",
        "EngineeringUnits",
        "EngineeringUnits",
        NodeClass::Variable,
    );

    let browser = FakeBrowser::new().with(&root, vec![speed, units]);

    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    assert_eq!(report.tags.len(), 1);
    assert_eq!(report.tags[0].path, "Speed");
}

fn plant() -> (NodeId, FakeBrowser) {
    let root = NodeId::new(2, "root");
    let cab = node("cab", "CAB", NodeClass::Object);
    let device_set = node("deviceset", "DeviceSet", NodeClass::Object);
    let server = node("server", "Server", NodeClass::Object);
    let db1 = node("db1", "DB1", NodeClass::Object);
    let db2 = node("db2", "DB2", NodeClass::Object);
    let structure = node("struct", "Struct", NodeClass::Variable);
    let method = node("method", "Reset", NodeClass::Method);
    let units = property(
        "units",
        "EngineeringUnits",
        "EngineeringUnits",
        NodeClass::Variable,
    );

    let mut browser = FakeBrowser::new()
        .with(&root, vec![cab.clone(), device_set.clone(), server.clone()])
        .with(&device_set.node_id, vec![cab.clone()])
        .with(
            &server.node_id,
            vec![node("state", "ServerState", NodeClass::Variable)],
        )
        .with(&cab.node_id, vec![db1.clone(), db2.clone(), method])
        .with(
            &db1.node_id,
            vec![
                node("a", "A", NodeClass::Variable),
                structure.clone(),
                units,
                cab.clone(),
            ],
        )
        .with(
            &structure.node_id,
            vec![
                node("x", "X", NodeClass::Variable),
                node("y", "Y", NodeClass::Variable),
            ],
        );

    let members: Vec<BrowsedNode> = (0..120)
        .map(|i| node(&format!("m{i}"), &format!("M{i}"), NodeClass::Variable))
        .collect();
    browser = browser.with(&db2.node_id, members.clone());
    for (i, member) in members.iter().enumerate() {
        browser = browser.with(
            &member.node_id,
            vec![node(&format!("m{i}.v"), "Value", NodeClass::Variable)],
        );
    }
    (root, browser)
}

fn node_by_node(
    browser: &dyn NodeBrowser,
    root: &NodeId,
    options: &ScanOptions,
) -> Vec<(String, String)> {
    fn walk(
        browser: &dyn NodeBrowser,
        children: Vec<BrowsedNode>,
        parent: &str,
        depth: usize,
        ancestors: &mut Vec<String>,
        options: &ScanOptions,
        out: &mut Vec<(String, String)>,
    ) {
        if depth > options.max_depth {
            return;
        }
        let has_property: NodeId = ReferenceTypeId::HasProperty.into();
        for child in children {
            if !options.include_properties && child.reference_type.as_ref() == Some(&has_property) {
                continue;
            }
            let path = if parent.is_empty() {
                child.browse_name.clone()
            } else {
                format!("{parent}/{}", child.browse_name)
            };
            let recurse = match child.node_class {
                NodeClass::Variable => {
                    out.push((path.clone(), child.node_id.to_string()));
                    options.descend_into_variables
                }
                NodeClass::Object => true,
                _ => false,
            };
            let key = child.node_id.to_string();
            if !recurse || ancestors.contains(&key) {
                continue;
            }
            ancestors.push(key);
            if let Ok(grandchildren) = browser.children_of(&child.node_id) {
                walk(
                    browser,
                    grandchildren,
                    &path,
                    depth + 1,
                    ancestors,
                    options,
                    out,
                );
            }
            ancestors.pop();
        }
    }
    let mut out = Vec::new();
    let children = browser.children_of(root).unwrap();
    walk(
        browser,
        children,
        "",
        1,
        &mut vec![root.to_string()],
        options,
        &mut out,
    );
    out
}

#[test]
fn the_tree_gives_the_same_tags_paths_and_order_as_reading_it_node_by_node() {
    let (root, browser) = plant();
    let variants = [
        ScanOptions::default(),
        ScanOptions::default().max_depth(3),
        ScanOptions::default().max_depth(1),
        ScanOptions::default().descend_into_variables(false),
        ScanOptions::default().include_properties(true),
    ];
    for options in variants {
        let expected = node_by_node(&browser, &root, &options);
        let report = TreeScanner::new(&browser, &AcceptAll, options.clone())
            .scan(root.clone())
            .unwrap();
        let got: Vec<(String, String)> = report
            .tags
            .iter()
            .map(|t| (t.path.clone(), t.node_id.clone()))
            .collect();
        assert_eq!(got, expected, "with {options:?}");
        assert!(report.is_complete());
    }
    assert!(
        node_by_node(&browser, &root, &ScanOptions::default()).len() > 240,
        "the plant is big enough to matter"
    );
}

#[test]
fn no_path_is_listed_twice() {
    let (root, browser) = plant();
    let report = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();
    let mut seen = HashSet::new();
    for tag in &report.tags {
        assert!(
            seen.insert(tag.path.clone()),
            "{} is listed twice",
            tag.path
        );
    }
    assert!(
        seen.contains("CAB/DB1/A") && seen.contains("DeviceSet/CAB/DB1/A"),
        "each path to a shared node, once"
    );
}

struct CountingBrowser {
    inner: FakeBrowser,
    asked: RefCell<Vec<Vec<String>>>,
}

impl NodeBrowser for CountingBrowser {
    fn children_of(&self, node_id: &NodeId) -> opcua_tag_browser::Result<Vec<BrowsedNode>> {
        self.asked.borrow_mut().push(vec![node_id.to_string()]);
        self.inner.children_of(node_id)
    }

    fn children_of_many(
        &self,
        node_ids: &[NodeId],
    ) -> Vec<opcua_tag_browser::Result<Vec<BrowsedNode>>> {
        self.asked
            .borrow_mut()
            .push(node_ids.iter().map(ToString::to_string).collect());
        node_ids
            .iter()
            .map(|id| self.inner.children_of(id))
            .collect()
    }
}

#[test]
fn each_node_is_asked_for_once_and_a_whole_level_at_a_time() {
    let (root, inner) = plant();
    let browser = CountingBrowser {
        inner,
        asked: RefCell::new(Vec::new()),
    };
    TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .scan(root)
        .unwrap();

    let asked = browser.asked.borrow();
    let all: Vec<&String> = asked.iter().flatten().collect();
    let unique: HashSet<&String> = all.iter().copied().collect();
    assert_eq!(
        all.len(),
        unique.len(),
        "a node reached by two paths is asked for once"
    );
    assert!(
        asked.len() <= 8,
        "one request per level, not one per node: {}",
        asked.len()
    );
}

struct FlakyBrowser {
    inner: FakeBrowser,
    fail: HashMap<String, (StatusCode, usize)>,
    calls: RefCell<HashMap<String, usize>>,
}

impl NodeBrowser for FlakyBrowser {
    fn children_of(&self, node_id: &NodeId) -> opcua_tag_browser::Result<Vec<BrowsedNode>> {
        let key = node_id.to_string();
        let mut calls = self.calls.borrow_mut();
        let call = calls.entry(key.clone()).or_default();
        *call += 1;
        match self.fail.get(&key) {
            Some((status, times)) if *call <= *times => Err(Error::Browse {
                node_id: key,
                status: *status,
            }),
            _ => self.inner.children_of(node_id),
        }
    }
}

fn quick() -> ScanOptions {
    ScanOptions::default().retry_pause(Duration::ZERO)
}

#[test]
fn a_busy_answer_is_tried_again_and_nothing_is_lost() {
    let (root, inner) = plant();
    let expected = node_by_node(&inner, &root, &ScanOptions::default());
    let db1 = NodeId::new(2, "db1").to_string();
    let browser = FlakyBrowser {
        inner,
        fail: HashMap::from([(db1.clone(), (StatusCode::BadTooManyOperations, 2))]),
        calls: RefCell::new(HashMap::new()),
    };
    let report = TreeScanner::new(&browser, &AcceptAll, quick())
        .scan(root)
        .unwrap();
    let got: Vec<(String, String)> = report
        .tags
        .iter()
        .map(|t| (t.path.clone(), t.node_id.clone()))
        .collect();
    assert_eq!(got, expected);
    assert!(report.is_complete());
    assert_eq!(
        browser.calls.borrow()[&db1],
        3,
        "asked once, then twice more"
    );
}

#[test]
fn a_refusal_is_skipped_at_once_without_asking_again() {
    let (root, inner) = plant();
    let db1 = NodeId::new(2, "db1").to_string();
    let browser = FlakyBrowser {
        inner,
        fail: HashMap::from([(db1.clone(), (StatusCode::BadUserAccessDenied, 99))]),
        calls: RefCell::new(HashMap::new()),
    };
    let report = TreeScanner::new(&browser, &AcceptAll, quick())
        .scan(root)
        .unwrap();
    assert_eq!(browser.calls.borrow()[&db1], 1);
    assert_eq!(report.skipped.len(), 2, "under CAB and under DeviceSet/CAB");
    assert!(report.tags.iter().all(|t| !t.path.contains("DB1")));
    assert!(report.tags.iter().any(|t| t.path == "CAB/DB2/M0/Value"));
}

#[test]
fn a_server_that_stops_answering_ends_the_scan_instead_of_giving_half_a_list() {
    let (root, inner) = plant();
    let fail = (0..120)
        .map(|i| {
            (
                NodeId::new(2, format!("m{i}")).to_string(),
                (StatusCode::BadConnectionClosed, 99),
            )
        })
        .collect();
    let browser = FlakyBrowser {
        inner,
        fail,
        calls: RefCell::new(HashMap::new()),
    };
    let outcome = TreeScanner::new(&browser, &AcceptAll, quick()).scan(root);
    assert!(
        outcome.is_err(),
        "a dropped link must not be saved as the tag list"
    );
}

#[test]
fn progress_says_where_the_scan_is_and_how_many_tags_it_has_found() {
    let (root, browser) = plant();
    let seen: RefCell<Vec<(String, usize)>> = RefCell::new(Vec::new());
    let report =
        |progress: &ScanProgress| seen.borrow_mut().push((progress.at.clone(), progress.tags));

    let scanned = TreeScanner::new(&browser, &AcceptAll, ScanOptions::default())
        .on_progress(&report)
        .scan(root)
        .unwrap();

    let seen = seen.borrow();
    assert!(seen.len() >= 3, "{seen:?}");
    assert!(
        seen.windows(2).all(|pair| pair[0].1 <= pair[1].1),
        "the count only grows"
    );
    assert!(seen.iter().any(|(at, _)| at.starts_with("CAB")));
    let distinct: HashSet<&str> = scanned
        .tags
        .iter()
        .map(|tag| tag.node_id.as_str())
        .collect();
    assert!(seen.last().unwrap().1 <= distinct.len());
}

#[test]
fn properties_are_included_when_requested() {
    let root = NodeId::new(2, "root");
    let speed = node("speed", "Speed", NodeClass::Variable);
    let units = property(
        "units",
        "EngineeringUnits",
        "EngineeringUnits",
        NodeClass::Variable,
    );

    let browser = FakeBrowser::new().with(&root, vec![speed, units]);

    let options = ScanOptions::default().include_properties(true);
    let report = TreeScanner::new(&browser, &AcceptAll, options)
        .scan(root)
        .unwrap();

    assert_eq!(report.tags.len(), 2);
}
