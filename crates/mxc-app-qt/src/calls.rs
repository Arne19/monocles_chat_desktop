//! `CallLogModel` — a `QAbstractListModel` of the account's call history (audio/video calls
//! placed + received), for the Calls section. `reload(jid)` queries the store on the core runtime.

use std::pin::Pin;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::{QByteArray, QHash, QHashPair_i32_QByteArray, QModelIndex, QString, QVariant};

use mxc_store::CallLogEntry;

const ROLE_PEER: i32 = 256;
const ROLE_DIRECTION: i32 = 257;
const ROLE_VIDEO: i32 = 258;
const ROLE_ANSWERED: i32 = 259;
const ROLE_TIMESTAMP: i32 = 260;
const ROLE_GROUP: i32 = 261;
const ROLE_NAME: i32 = 262;
const ROLE_GROUP_GONE: i32 = 263;

/// One call-history row.
#[derive(Clone, Default)]
pub struct CallEntry {
    pub peer: String,
    /// "in" | "out".
    pub direction: String,
    pub video: bool,
    pub answered: bool,
    /// RFC3339 timestamp (formatted for display in QML).
    pub timestamp: String,
    /// A group call (XEP-0272 Muji): `peer` is the room JID.
    pub group: bool,
    /// Display name for a group call (the room's name); empty for 1:1 calls.
    pub name: String,
    /// A group call whose group we're no longer in: nothing to open or call back.
    pub group_gone: bool,
}

impl CallEntry {
    pub fn from_row(c: &CallLogEntry) -> Self {
        Self {
            peer: c.peer.clone(),
            direction: c.direction.clone(),
            video: c.video,
            answered: c.answered,
            timestamp: c.timestamp.clone(),
            group: c.is_group,
            name: String::new(),
            group_gone: false,
        }
    }
}

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!(<QtCore/QAbstractListModel>);
        type QAbstractListModel;

        include!("cxx-qt-lib/qhash.h");
        type QHash_i32_QByteArray = cxx_qt_lib::QHash<cxx_qt_lib::QHashPair_i32_QByteArray>;

        include!("cxx-qt-lib/qvariant.h");
        type QVariant = cxx_qt_lib::QVariant;

        include!("cxx-qt-lib/qmodelindex.h");
        type QModelIndex = cxx_qt_lib::QModelIndex;

        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        #[qobject]
        #[base = QAbstractListModel]
        #[qml_element]
        /// Calls newer than the persisted "seen" cursor — the Calls nav badge.
        #[qproperty(i32, unseen_count, cxx_name = "unseenCount")]
        type CallLogModel = super::CallLogModelRust;

        /// (Re)load the account's call history.
        #[qinvokable]
        fn reload(self: Pin<&mut CallLogModel>, jid: &QString);

        /// The user looked at the list: remember the newest entry as seen, badge → 0.
        #[qinvokable]
        #[cxx_name = "markSeen"]
        fn mark_seen(self: Pin<&mut CallLogModel>);
    }

    extern "RustQt" {
        #[qinvokable]
        #[cxx_override]
        fn data(self: &CallLogModel, index: &QModelIndex, role: i32) -> QVariant;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "row_count"]
        fn rowCount(self: &CallLogModel, parent: &QModelIndex) -> i32;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "role_names"]
        fn roleNames(self: &CallLogModel) -> QHash_i32_QByteArray;
    }

    unsafe extern "RustQt" {
        #[inherit]
        #[rust_name = "begin_reset_model"]
        fn beginResetModel(self: Pin<&mut CallLogModel>);
        #[inherit]
        #[rust_name = "end_reset_model"]
        fn endResetModel(self: Pin<&mut CallLogModel>);
    }

    impl cxx_qt::Threading for CallLogModel {}
}

/// Backing data for the `CallLogModel` QObject.
#[derive(Default)]
pub struct CallLogModelRust {
    items: Vec<CallEntry>,
    unseen_count: i32,
}

impl qobject::CallLogModel {
    pub fn reload(self: Pin<&mut Self>, jid: &QString) {
        crate::session::load_calls(jid.to_string(), self.qt_thread());
    }

    pub fn reset(mut self: Pin<&mut Self>, items: Vec<CallEntry>) {
        // Timestamps are stored sortable (RFC3339 / "Y-m-d H:M:S"), so a string compare works.
        let seen = crate::session::seen_mark("calls");
        let unseen = items.iter().filter(|c| c.timestamp.as_str() > seen.as_str()).count() as i32;
        self.as_mut().begin_reset_model();
        self.as_mut().rust_mut().items = items;
        self.as_mut().end_reset_model();
        self.as_mut().set_unseen_count(unseen);
    }

    /// Persist the newest visible entry as the seen cursor and clear the badge.
    pub fn mark_seen(mut self: Pin<&mut Self>) {
        if let Some(newest) = self.items.iter().map(|c| c.timestamp.as_str()).max() {
            crate::session::set_seen_mark("calls", newest);
        }
        self.as_mut().set_unseen_count(0);
    }

    fn data(&self, index: &QModelIndex, role: i32) -> QVariant {
        let Some(item) = self.items.get(index.row() as usize) else {
            return QVariant::default();
        };
        match role {
            ROLE_PEER => QVariant::from(&QString::from(item.peer.as_str())),
            ROLE_DIRECTION => QVariant::from(&QString::from(item.direction.as_str())),
            ROLE_VIDEO => QVariant::from(&item.video),
            ROLE_ANSWERED => QVariant::from(&item.answered),
            ROLE_TIMESTAMP => QVariant::from(&QString::from(item.timestamp.as_str())),
            ROLE_GROUP => QVariant::from(&item.group),
            ROLE_NAME => QVariant::from(&QString::from(item.name.as_str())),
            ROLE_GROUP_GONE => QVariant::from(&item.group_gone),
            _ => QVariant::default(),
        }
    }

    fn row_count(&self, _parent: &QModelIndex) -> i32 {
        self.items.len() as i32
    }

    fn role_names(&self) -> QHash<QHashPair_i32_QByteArray> {
        let mut roles = QHash::<QHashPair_i32_QByteArray>::default();
        roles.insert(ROLE_PEER, QByteArray::from("peer"));
        roles.insert(ROLE_DIRECTION, QByteArray::from("direction"));
        roles.insert(ROLE_VIDEO, QByteArray::from("video"));
        roles.insert(ROLE_ANSWERED, QByteArray::from("answered"));
        roles.insert(ROLE_TIMESTAMP, QByteArray::from("timestamp"));
        roles.insert(ROLE_GROUP, QByteArray::from("group"));
        roles.insert(ROLE_NAME, QByteArray::from("name"));
        roles.insert(ROLE_GROUP_GONE, QByteArray::from("groupGone"));
        roles
    }
}
