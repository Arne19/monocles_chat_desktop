//! `ConferenceModel` — a `QAbstractListModel` of the remote participants in the active
//! XEP-0272 Muji group call (see `session::conference_participants`). `load()` (re)populates it
//! from the latest `Event::ConferenceUpdate`.

use std::pin::Pin;

use cxx_qt::CxxQtType;
use cxx_qt_lib::{QByteArray, QHash, QHashPair_i32_QByteArray, QModelIndex, QString, QVariant};

const ROLE_NAME: i32 = 256;
const ROLE_JID: i32 = 257;
const ROLE_STATE: i32 = 258;
const ROLE_AVATAR: i32 = 259;
const ROLE_SID: i32 = 260;
const ROLE_TRUST: i32 = 261;

/// One remote participant of the active group call.
#[derive(Clone, Default)]
pub struct ConfPartEntry {
    /// Display name (the participant's MUC nick).
    pub name: String,
    /// Occupant JID (`room@host/nick`).
    pub jid: String,
    /// Per-pair call state: "connecting" | "active" | "ended".
    pub state: String,
    pub avatar_path: String,
    /// Per-pair Jingle session id — matches this participant's video frames (tagged by sid).
    pub sid: String,
    /// Call trust of this participant's leg: 0 = not OMEMO-authenticated/untrusted, 1 = lock,
    /// 2 = manually verified.
    pub trust: i64,
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
        type ConferenceModel = super::ConferenceModelRust;

        /// (Re)load the active conference's participants.
        #[qinvokable]
        fn load(self: Pin<&mut ConferenceModel>);
    }

    extern "RustQt" {
        #[qinvokable]
        #[cxx_override]
        fn data(self: &ConferenceModel, index: &QModelIndex, role: i32) -> QVariant;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "row_count"]
        fn rowCount(self: &ConferenceModel, parent: &QModelIndex) -> i32;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "role_names"]
        fn roleNames(self: &ConferenceModel) -> QHash_i32_QByteArray;
    }

    unsafe extern "RustQt" {
        #[inherit]
        #[rust_name = "begin_reset_model"]
        fn beginResetModel(self: Pin<&mut ConferenceModel>);
        #[inherit]
        #[rust_name = "end_reset_model"]
        fn endResetModel(self: Pin<&mut ConferenceModel>);
    }
}

/// Backing data for the `ConferenceModel` QObject.
#[derive(Default)]
pub struct ConferenceModelRust {
    items: Vec<ConfPartEntry>,
}

impl qobject::ConferenceModel {
    pub fn load(mut self: Pin<&mut Self>) {
        let items = crate::session::conference_participants();
        self.as_mut().begin_reset_model();
        self.as_mut().rust_mut().items = items;
        self.as_mut().end_reset_model();
    }

    fn data(&self, index: &QModelIndex, role: i32) -> QVariant {
        let Some(item) = self.items.get(index.row() as usize) else {
            return QVariant::default();
        };
        match role {
            ROLE_NAME => QVariant::from(&QString::from(item.name.as_str())),
            ROLE_JID => QVariant::from(&QString::from(item.jid.as_str())),
            ROLE_STATE => QVariant::from(&QString::from(item.state.as_str())),
            ROLE_AVATAR => QVariant::from(&QString::from(item.avatar_path.as_str())),
            ROLE_SID => QVariant::from(&QString::from(item.sid.as_str())),
            ROLE_TRUST => QVariant::from(&(item.trust as i32)),
            _ => QVariant::default(),
        }
    }

    fn row_count(&self, _parent: &QModelIndex) -> i32 {
        self.items.len() as i32
    }

    fn role_names(&self) -> QHash<QHashPair_i32_QByteArray> {
        let mut roles = QHash::<QHashPair_i32_QByteArray>::default();
        roles.insert(ROLE_NAME, QByteArray::from("name"));
        roles.insert(ROLE_JID, QByteArray::from("jid"));
        roles.insert(ROLE_STATE, QByteArray::from("state"));
        roles.insert(ROLE_AVATAR, QByteArray::from("avatarPath"));
        roles.insert(ROLE_SID, QByteArray::from("sid"));
        roles.insert(ROLE_TRUST, QByteArray::from("trust"));
        roles
    }
}
