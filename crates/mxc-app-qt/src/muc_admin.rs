//! Live per-room XEP-0045 state for the room-admin actions: whether the room supports
//! XEP-0425 moderation, our own role/affiliation, and each present occupant's. Fed by
//! `Event::MucPrivacy` / `Event::MucOccupant` (see `session.rs`) and queried by QML to gate
//! "Moderate…", "Kick…" and "Ban…". The rules mirror monocles Android
//! (`MucDetailsContextMenuHelper`); the room enforces them again on its side.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// One present occupant (or ourselves).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Occupant {
    pub role: String,
    pub affiliation: String,
    /// Bare real JID — only known in non-anonymous rooms or to moderators.
    pub real_jid: Option<String>,
    /// XEP-0421 occupant id, stable across nick changes.
    pub occupant_id: Option<String>,
}

#[derive(Default)]
struct Room {
    moderation: bool,
    /// The room stamps XEP-0421 occupant ids (needed for corrections, see [`can_correct`]).
    occupant_id: bool,
    self_nick: Option<String>,
    me: Occupant,
    occupants: HashMap<String, Occupant>,
    /// Lowercased bare JID → affiliation, from the room's affiliation lists (offline members
    /// and bans included), kept current by our own changes and occupant presence.
    affiliated: HashMap<String, String>,
}

/// Lowercased room bare jid → its state. Lowercased because the room JID reaches us from
/// different sources (bookmark/config vs. the server's presence `from`).
static ROOMS: LazyLock<Mutex<HashMap<String, Room>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// XEP-0045 affiliation rank: owner > admin > member > none > outcast.
fn rank(affiliation: &str) -> u8 {
    match affiliation {
        "owner" => 4,
        "admin" => 3,
        "member" => 2,
        "outcast" => 0,
        _ => 1,
    }
}

fn key(room: &str) -> String {
    room.to_ascii_lowercase()
}

/// We're (re)joining `room`: forget its occupants and our own standing — the room re-sends
/// every current occupant's presence, so anyone who left meanwhile doesn't linger. The room's
/// moderation support and affiliation lists are kept.
pub fn reset_room(room: &str) {
    if let Some(r) = ROOMS.lock().unwrap().get_mut(&key(room)) {
        r.occupants.clear();
        r.me = Occupant::default();
        r.self_nick = None;
    }
}

pub fn set_moderation(room: &str, supported: bool) {
    ROOMS.lock().unwrap().entry(key(room)).or_default().moderation = supported;
}

pub fn set_occupant_id(room: &str, supported: bool) {
    ROOMS.lock().unwrap().entry(key(room)).or_default().occupant_id = supported;
}

/// Whether our messages in `room` may be corrected (XEP-0308): only where the room stamps
/// occupant ids, else other clients show the correction as a new message (Conversations
/// 9b77fa682). Unknown rooms (disco not done yet) count as no.
pub fn can_correct(room: &str) -> bool {
    ROOMS.lock().unwrap().get(&key(room)).is_some_and(|r| r.occupant_id)
}

/// Record an occupant's presence. `nick_change` marks an unavailable presence that only
/// announces a new nick (status 303). Returns whether *our own* state changed (only that
/// re-gates the open chat's actions; other occupants are looked up when a menu opens).
pub fn update(room: &str, nick: &str, occupant: Occupant, is_self: bool, available: bool, nick_change: bool) -> bool {
    let mut rooms = ROOMS.lock().unwrap();
    let r = rooms.entry(key(room)).or_default();
    if is_self {
        if !available && nick_change {
            return false; // our new nick's presence follows
        }
        let me = if available { occupant.clone() } else { Occupant::default() };
        let changed = r.me != me;
        r.me = me;
        r.self_nick = available.then(|| nick.to_string());
        if !available {
            // We left or were removed: nobody's presence reaches us any more.
            r.occupants.clear();
        }
        changed
    } else {
        if available {
            // A present occupant's affiliation (e.g. just changed by someone) updates the list.
            if let Some(jid) = &occupant.real_jid {
                set_listed(r, jid, &occupant.affiliation);
            }
            r.occupants.insert(nick.to_string(), occupant);
        } else {
            r.occupants.remove(nick);
        }
        false
    }
}

/// Moderation (XEP-0425) needs room support and the moderator role — which owners and admins
/// always hold in XEP-0045, so their affiliation also counts (covers a role update that
/// hasn't arrived yet).
pub fn can_moderate(room: &str) -> bool {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return false };
    r.moderation && (r.me.role == "moderator" || rank(&r.me.affiliation) >= rank("admin"))
}

fn target<'a>(r: &'a Room, nick: &str) -> Option<&'a Occupant> {
    if r.self_nick.as_deref() == Some(nick) {
        return None; // never ourselves
    }
    r.occupants.get(nick)
}

/// XEP-0045 §8.2: a moderator may kick any present occupant except an admin or owner.
pub fn can_kick(room: &str, nick: &str) -> bool {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return false };
    let Some(t) = target(r, nick) else { return false };
    let we_moderate = r.me.role == "moderator" || rank(&r.me.affiliation) >= rank("admin");
    we_moderate && rank(&t.affiliation) < rank("admin")
}

/// Android's rule (XEP-0045 §9): an admin may change the affiliation of — and ban or unban —
/// anyone it outranks; an owner anyone's.
fn may_change(mine: u8, theirs: u8) -> bool {
    mine == rank("owner") || (mine >= rank("admin") && mine > theirs)
}

/// XEP-0045 §9.1: whether we may ban present occupant `nick`. Needs their real JID — a ban is
/// by JID, not nick.
pub fn can_ban(room: &str, nick: &str) -> bool {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return false };
    let Some(t) = target(r, nick) else { return false };
    t.real_jid.is_some() && may_change(rank(&r.me.affiliation), rank(&t.affiliation))
}

/// The membership/admin/owner changes (Android's "Manage permissions") from our affiliation
/// `mine` for someone with `theirs`, as `(action, new affiliation)`. Admin and owner rights
/// are an owner's to give or take, and fall back to member.
fn rights_choices(mine: u8, theirs: u8) -> Vec<(&'static str, &'static str)> {
    let owner = rank("owner");
    let mut out = Vec::new();
    if may_change(mine, theirs) {
        if theirs < rank("member") {
            out.push(("grant_membership", "member"));
        } else if theirs == rank("member") {
            out.push(("remove_membership", "none"));
        }
    }
    if mine == owner {
        if theirs < rank("admin") {
            out.push(("grant_admin", "admin"));
        } else if theirs == rank("admin") {
            out.push(("remove_admin", "member"));
        }
        if theirs < owner {
            out.push(("grant_owner", "owner"));
        } else {
            out.push(("remove_owner", "member"));
        }
    }
    out
}

/// The permission changes we may make for present occupant `nick`. Needs their real JID;
/// never ourselves.
pub fn affiliation_choices(room: &str, nick: &str) -> Vec<(&'static str, &'static str)> {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return Vec::new() };
    let Some(t) = target(r, nick).filter(|t| t.real_jid.is_some()) else { return Vec::new() };
    rights_choices(rank(&r.me.affiliation), rank(&t.affiliation))
}

/// Whether we may read and edit `room`'s member and ban lists (admin or owner).
pub fn can_manage_members(room: &str) -> bool {
    ROOMS.lock().unwrap().get(&key(room)).is_some_and(|r| rank(&r.me.affiliation) >= rank("admin"))
}

fn set_listed(r: &mut Room, jid: &str, affiliation: &str) {
    let key = jid.to_ascii_lowercase();
    if rank(affiliation) == rank("none") {
        r.affiliated.remove(&key);
    } else {
        r.affiliated.insert(key, affiliation.to_string());
    }
}

/// Replace `room`'s affiliation lists with a fresh fetch.
pub fn set_affiliations(room: &str, items: Vec<(String, String)>) {
    let mut rooms = ROOMS.lock().unwrap();
    let r = rooms.entry(key(room)).or_default();
    r.affiliated.clear();
    for (jid, aff) in items {
        set_listed(r, &jid, &aff);
    }
}

/// The room accepted our change of `jid`'s affiliation.
pub fn affiliation_changed(room: &str, jid: &str, affiliation: &str) {
    let mut rooms = ROOMS.lock().unwrap();
    set_listed(rooms.entry(key(room)).or_default(), jid, affiliation);
}

/// From the affiliation lists: the members/admins/owners not currently in the room, and the
/// banned JIDs — each sorted, as `(jid, affiliation)`.
pub fn offline_and_banned(room: &str) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return Default::default() };
    let present: std::collections::HashSet<String> =
        r.occupants.values().filter_map(|o| o.real_jid.as_ref()).map(|j| j.to_ascii_lowercase()).collect();
    let (mut offline, mut banned): (Vec<_>, Vec<_>) = r
        .affiliated
        .iter()
        .filter(|(jid, aff)| aff.as_str() == "outcast" || !present.contains(jid.as_str()))
        .map(|(jid, aff)| (jid.clone(), aff.clone()))
        .partition(|(_, aff)| aff != "outcast");
    // Owners first, then admins, then members; alphabetical within.
    offline.sort_by(|a, b| rank(&b.1).cmp(&rank(&a.1)).then_with(|| a.0.cmp(&b.0)));
    banned.sort();
    (offline, banned)
}

/// The changes we may make for a listed (possibly offline) `jid`: unban for an outcast; else
/// the rights changes plus ban.
pub fn jid_choices(room: &str, jid: &str) -> Vec<(&'static str, &'static str)> {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return Vec::new() };
    let theirs = r.affiliated.get(&jid.to_ascii_lowercase()).map(|a| rank(a)).unwrap_or(rank("none"));
    let mine = rank(&r.me.affiliation);
    if !may_change(mine, theirs) {
        return Vec::new();
    }
    if theirs == rank("outcast") {
        return vec![("unban", "none")];
    }
    let mut out = rights_choices(mine, theirs);
    out.push(("ban", "outcast"));
    out
}

/// A present occupant's state (for the ban JID and the "moderate recent" occupant-id).
pub fn occupant(room: &str, nick: &str) -> Option<Occupant> {
    ROOMS.lock().unwrap().get(&key(room))?.occupants.get(nick).cloned()
}

/// Role and affiliation of a present occupant, for display ("" when unknown).
pub fn describe(room: &str, nick: &str) -> (String, String) {
    let rooms = ROOMS.lock().unwrap();
    let Some(r) = rooms.get(&key(room)) else { return Default::default() };
    let o = if r.self_nick.as_deref() == Some(nick) { Some(&r.me) } else { r.occupants.get(nick) };
    o.map(|o| (o.role.clone(), o.affiliation.clone())).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occ(role: &str, aff: &str, jid: Option<&str>) -> Occupant {
        Occupant {
            role: role.into(),
            affiliation: aff.into(),
            real_jid: jid.map(str::to_string),
            occupant_id: None,
        }
    }

    #[test]
    fn moderator_role_or_admin_affiliation_may_moderate() {
        let room = "t1@muc";
        assert!(!can_moderate(room));
        set_moderation(room, true);
        assert!(update(room, "me", occ("participant", "member", None), true, true, false));
        assert!(!can_moderate(room));
        update(room, "me", occ("moderator", "member", None), true, true, false);
        assert!(can_moderate(room));
        update(room, "me", occ("participant", "admin", None), true, true, false);
        assert!(can_moderate(room));
        // Left the room → no rights.
        update(room, "me", occ("moderator", "owner", None), true, false, false);
        assert!(!can_moderate(room));
        // Room without XEP-0425.
        set_moderation(room, false);
        update(room, "me", occ("moderator", "owner", None), true, true, false);
        assert!(!can_moderate(room));
    }

    #[test]
    fn kick_and_ban_follow_xep_0045_ranks() {
        let room = "t2@muc";
        update(room, "me", occ("moderator", "admin", None), true, true, false);
        update(room, "bob", occ("participant", "member", Some("bob@x")), false, true, false);
        update(room, "anon", occ("participant", "none", None), false, true, false);
        update(room, "ann", occ("moderator", "admin", Some("ann@x")), false, true, false);
        update(room, "olga", occ("moderator", "owner", Some("olga@x")), false, true, false);

        assert!(can_kick(room, "bob") && can_ban(room, "bob"));
        // No real JID → kick only.
        assert!(can_kick(room, "anon") && !can_ban(room, "anon"));
        // An admin can't kick or ban a fellow admin or an owner.
        assert!(!can_kick(room, "ann") && !can_ban(room, "ann"));
        assert!(!can_kick(room, "olga") && !can_ban(room, "olga"));
        // Never ourselves, nor someone absent.
        assert!(!can_kick(room, "me") && !can_ban(room, "me"));
        assert!(!can_kick(room, "ghost") && !can_ban(room, "ghost"));

        // An owner may ban an admin.
        update(room, "me", occ("moderator", "owner", None), true, true, false);
        assert!(can_ban(room, "ann"));
        // A plain participant may do neither.
        update(room, "me", occ("participant", "member", None), true, true, false);
        assert!(!can_kick(room, "bob") && !can_ban(room, "bob"));

        // Permission choices: an admin toggles membership of those it outranks...
        update(room, "me", occ("moderator", "admin", None), true, true, false);
        update(room, "nina", occ("participant", "none", Some("nina@x")), false, true, false);
        assert_eq!(affiliation_choices(room, "nina"), vec![("grant_membership", "member")]);
        assert_eq!(affiliation_choices(room, "bob"), vec![("remove_membership", "none")]);
        assert!(affiliation_choices(room, "ann").is_empty());
        assert!(affiliation_choices(room, "anon").is_empty()); // no real JID
        // ...an owner also manages admin and owner rights.
        update(room, "me", occ("moderator", "owner", None), true, true, false);
        assert_eq!(
            affiliation_choices(room, "bob"),
            vec![("remove_membership", "none"), ("grant_admin", "admin"), ("grant_owner", "owner")]
        );
        assert_eq!(affiliation_choices(room, "ann"), vec![("remove_admin", "member"), ("grant_owner", "owner")]);
        assert_eq!(affiliation_choices(room, "olga"), vec![("remove_owner", "member")]);
        assert!(affiliation_choices(room, "me").is_empty());

        // Member and ban lists: present members are not "offline"; bans always listed.
        set_affiliations(
            room,
            vec![
                ("bob@x".into(), "member".into()),
                ("Zed@x".into(), "member".into()),
                ("olga@x".into(), "owner".into()),
                ("carl@x".into(), "admin".into()),
                ("spam@x".into(), "outcast".into()),
            ],
        );
        let (offline, banned) = offline_and_banned(room);
        assert_eq!(offline, vec![("carl@x".into(), "admin".into()), ("zed@x".into(), "member".into())]);
        assert_eq!(banned, vec![("spam@x".to_string(), "outcast".to_string())]);
        // As owner: unban a ban; for an offline member also the rights + ban.
        assert_eq!(jid_choices(room, "SPAM@x"), vec![("unban", "none")]);
        assert_eq!(jid_choices(room, "zed@x").last(), Some(&("ban", "outcast")));
        affiliation_changed(room, "spam@x", "none");
        assert!(offline_and_banned(room).1.is_empty());
        // As admin: no unbanning or banning of a fellow admin.
        update(room, "me", occ("moderator", "admin", None), true, true, false);
        assert!(jid_choices(room, "carl@x").is_empty());
        assert_eq!(jid_choices(room, "zed@x"), vec![("remove_membership", "none"), ("ban", "outcast")]);
        assert!(can_manage_members(room));

        // Rejoining forgets everyone (they're re-announced); our leaving does too.
        reset_room("T2@MUC");
        assert_eq!(occupant(room, "bob"), None);
        assert!(!can_manage_members(room));
        update(room, "me", occ("moderator", "owner", None), true, true, false);
        update(room, "bob", occ("participant", "member", Some("bob@x")), false, true, false);
        // A nick change of ours keeps them; leaving clears them.
        update(room, "me", Occupant::default(), true, false, true);
        assert!(can_manage_members(room) && occupant(room, "bob").is_some());
        update(room, "me", Occupant::default(), true, false, false);
        assert_eq!(occupant(room, "bob"), None);
        update(room, "bob", occ("participant", "member", Some("bob@x")), false, true, false);

        // Bob leaves.
        update(room, "bob", Occupant::default(), false, false, false);
        assert_eq!(occupant(room, "bob"), None);
    }
}
