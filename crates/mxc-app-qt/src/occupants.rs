//! `OccupantModel` — a `QAbstractListModel` of a MUC room's current occupants, derived from
//! the live presence map (see `session::occupants`). `load(room)` (re)populates it.

use std::pin::Pin;

use cxx_qt::CxxQtType;
use cxx_qt_lib::{QByteArray, QHash, QHashPair_i32_QByteArray, QModelIndex, QString, QVariant};

const ROLE_NICK: i32 = 256;
const ROLE_JID: i32 = 257;
const ROLE_PRESENCE: i32 = 258;
const ROLE_AVATAR: i32 = 259;
const ROLE_ROLE: i32 = 260;
const ROLE_AFFILIATION: i32 = 261;

/// One room occupant.
#[derive(Clone, Default)]
pub struct OccupantEntry {
    pub nick: String,
    /// Full occupant JID (`room@host/nick`) — the target for a private message.
    pub jid: String,
    pub presence: String,
    pub avatar_path: String,
    /// XEP-0045 role (`moderator`/`participant`/`visitor`) and affiliation, "" if unknown.
    pub role: String,
    pub affiliation: String,
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

        include!("cxx-qt-lib/qlist.h");
        type QList_i32 = cxx_qt_lib::QList<i32>;
    }

    extern "RustQt" {
        #[qobject]
        #[base = QAbstractListModel]
        #[qml_element]
        type OccupantModel = super::OccupantModelRust;

        /// (Re)load the occupants of `room` (bare room JID).
        #[qinvokable]
        fn load(self: Pin<&mut OccupantModel>, room: &QString);
    }

    extern "RustQt" {
        #[qinvokable]
        #[cxx_override]
        fn data(self: &OccupantModel, index: &QModelIndex, role: i32) -> QVariant;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "row_count"]
        fn rowCount(self: &OccupantModel, parent: &QModelIndex) -> i32;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "role_names"]
        fn roleNames(self: &OccupantModel) -> QHash_i32_QByteArray;
    }

    unsafe extern "RustQt" {
        #[inherit]
        #[rust_name = "begin_reset_model"]
        fn beginResetModel(self: Pin<&mut OccupantModel>);
        #[inherit]
        #[rust_name = "end_reset_model"]
        fn endResetModel(self: Pin<&mut OccupantModel>);
        // For in-place row updates (same membership) without losing the scroll position.
        #[inherit]
        fn index(self: &OccupantModel, row: i32, column: i32, parent: &QModelIndex) -> QModelIndex;
        #[inherit]
        #[rust_name = "data_changed"]
        fn dataChanged(
            self: Pin<&mut OccupantModel>,
            top_left: &QModelIndex,
            bottom_right: &QModelIndex,
            roles: &QList_i32,
        );
    }
}

/// Backing data for the `OccupantModel` QObject.
#[derive(Default)]
pub struct OccupantModelRust {
    items: Vec<OccupantEntry>,
}

impl qobject::OccupantModel {
    pub fn load(mut self: Pin<&mut Self>, room: &QString) {
        let items = crate::session::occupants(&room.to_string());
        // Same members in the same (nick-sorted) order → update rows in place: the popup
        // reloads on every list refresh (avatars arriving while the user scrolls), and a
        // full reset would yank the scroll position back to the top.
        let same = self.items.len() == items.len()
            && self.items.iter().zip(&items).all(|(a, b)| a.jid == b.jid);
        if same {
            let count = items.len() as i32;
            self.as_mut().rust_mut().items = items;
            if count > 0 {
                let parent = QModelIndex::default();
                let top = self.as_ref().index(0, 0, &parent);
                let bottom = self.as_ref().index(count - 1, 0, &parent);
                self.as_mut().data_changed(&top, &bottom, &cxx_qt_lib::QList::<i32>::default());
            }
            return;
        }
        self.as_mut().begin_reset_model();
        self.as_mut().rust_mut().items = items;
        self.as_mut().end_reset_model();
    }

    fn data(&self, index: &QModelIndex, role: i32) -> QVariant {
        let Some(item) = self.items.get(index.row() as usize) else {
            return QVariant::default();
        };
        match role {
            ROLE_NICK => QVariant::from(&QString::from(item.nick.as_str())),
            ROLE_JID => QVariant::from(&QString::from(item.jid.as_str())),
            ROLE_PRESENCE => QVariant::from(&QString::from(item.presence.as_str())),
            ROLE_AVATAR => QVariant::from(&QString::from(item.avatar_path.as_str())),
            ROLE_ROLE => QVariant::from(&QString::from(item.role.as_str())),
            ROLE_AFFILIATION => QVariant::from(&QString::from(item.affiliation.as_str())),
            _ => QVariant::default(),
        }
    }

    fn row_count(&self, _parent: &QModelIndex) -> i32 {
        self.items.len() as i32
    }

    fn role_names(&self) -> QHash<QHashPair_i32_QByteArray> {
        let mut roles = QHash::<QHashPair_i32_QByteArray>::default();
        roles.insert(ROLE_NICK, QByteArray::from("nick"));
        roles.insert(ROLE_JID, QByteArray::from("jid"));
        roles.insert(ROLE_PRESENCE, QByteArray::from("presence"));
        roles.insert(ROLE_AVATAR, QByteArray::from("avatarPath"));
        roles.insert(ROLE_ROLE, QByteArray::from("role"));
        roles.insert(ROLE_AFFILIATION, QByteArray::from("affiliation"));
        roles
    }
}
