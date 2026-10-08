//! Social feed — XEP-0472 / XEP-0277 microblogging, wire-compatible with monocles chat for
//! Android's "Feeds" (and Movim).
//!
//! Posts are Atom `<entry>` items in the author's `urn:xmpp:microblog:0` PEP node. Each post
//! names its comments node in `<link rel="replies" title="comments"
//! href="xmpp:<service>?;node=…">` — normally `urn:xmpp:microblog:0:comments/<post-id>` on the
//! author's own service, but Movim and others may put it elsewhere, so the link is what counts.
//! Comments are Atom entries in that node whose body is the `<title>`. Title and content are
//! Atom text constructs (text, html or xhtml) and are read as Markdown (see [`atom_text`]).
//! Items aren't cached in the store — the UI accumulates fetched lists in memory.

use async_channel::Sender;
use minidom::Element;

use mxc_store::{FeedPostRow, Store};

use crate::client::{AccountConfig, Writer};
use crate::event::{Event, FeedPost};
use crate::xeps::atom_text;
use crate::xeps::pep;
use crate::xeps::{iq, roster::new_id};

pub const NS_MICROBLOG: &str = "urn:xmpp:microblog:0";
pub const COMMENTS_NODE_PREFIX: &str = "urn:xmpp:microblog:0:comments/";
const NS_ATOM: &str = "http://www.w3.org/2005/Atom";
const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_XDATA: &str = "jabber:x:data";
const NS_NODE_CONFIG: &str = "http://jabber.org/protocol/pubsub#node_config";
const NS_DISCO_ITEMS: &str = "http://jabber.org/protocol/disco#items";

/// `pubsub#max_items` "max" (XEP-0060: no limit but the server's; required by XEP-0472).
/// Servers predating the keyword reject the whole form, so creation is retried with a number.
const MAX_ITEMS: &str = "max";
const FALLBACK_MAX_ITEMS: &str = "1000";

/// A "like" is a comment whose body is exactly this heart (matches monocles Android).
pub const HEART: &str = "♥";

fn comments_node(post_id: &str) -> String {
    format!("{COMMENTS_NODE_PREFIX}{post_id}")
}

// --- fetching ------------------------------------------------------------------------------

/// Fetch up to 100 of `jid`'s posts (None = our own); newest first. A missing node is an
/// empty feed; any other error is returned, so a failed fetch isn't taken for "no posts".
pub async fn fetch(w: &Writer, jid: Option<&str>, owner_bare: &str) -> anyhow::Result<Vec<FeedPost>> {
    let reply = match pep::items(w, jid, NS_MICROBLOG, Some(100)).await {
        Ok(reply) => reply,
        Err(e) if e.to_string().contains("item-not-found") => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut posts: Vec<FeedPost> = pep::extract_items(&reply)
        .iter()
        .filter_map(|(id, entry)| parse_post(id.as_deref(), entry, owner_bare))
        .collect();
    posts.sort_by_key(|p| std::cmp::Reverse(p.published));
    Ok(posts)
}

/// Fetch `jid`'s feed, cache it (replacing what was cached of that author) and emit
/// `Event::FeedPosts`. Failures are only logged: the cached posts stay.
pub async fn refresh(w: &Writer, store: &Store, account_id: i64, events: &Sender<Event>, jid: Option<&str>, owner_bare: &str) {
    match fetch(w, jid, owner_bare).await {
        Ok(posts) => {
            let rows: Vec<FeedPostRow> = posts.iter().map(to_row).collect();
            if let Err(e) = store.replace_feed(account_id, owner_bare, &rows).await {
                tracing::warn!(error = %e, "caching feed posts");
            }
            let public = !posts.is_empty() && feed_is_public(w, jid, owner_bare).await;
            let _ = events
                .send(Event::FeedPosts { account_id, jid: owner_bare.to_string(), posts, public })
                .await;
        }
        Err(e) => tracing::debug!(jid = %owner_bare, error = %e, "feed fetch failed"),
    }
}

/// Whether `owner_bare`'s feed is readable by anyone (access model "open"); `jid` None = our
/// own. Only then is a link to one of its posts worth sharing. Our own node's configuration is
/// read directly; for others, the node metadata (XEP-0060 §5.4). Unknown counts as private.
async fn feed_is_public(w: &Writer, jid: Option<&str>, owner_bare: &str) -> bool {
    const NS_DISCO_INFO: &str = "http://jabber.org/protocol/disco#info";
    let req = match jid {
        None => Element::builder("iq", "jabber:client")
            .attr(crate::ncname("type"), "get")
            .attr(crate::ncname("id"), new_id("pep-cfg"))
            .attr(crate::ncname("to"), owner_bare)
            .append(
                Element::builder("pubsub", pep::NS_PUBSUB_OWNER)
                    .append(
                        Element::builder("configure", pep::NS_PUBSUB_OWNER)
                            .attr(crate::ncname("node"), NS_MICROBLOG)
                            .build(),
                    )
                    .build(),
            )
            .build(),
        Some(j) => Element::builder("iq", "jabber:client")
            .attr(crate::ncname("type"), "get")
            .attr(crate::ncname("id"), new_id("disco-info"))
            .attr(crate::ncname("to"), j)
            .append(Element::builder("query", NS_DISCO_INFO).attr(crate::ncname("node"), NS_MICROBLOG).build())
            .build(),
    };
    let Ok(reply) = iq::request(w, req).await else { return false };
    let form = match jid {
        None => reply
            .get_child("pubsub", pep::NS_PUBSUB_OWNER)
            .and_then(|p| p.get_child("configure", pep::NS_PUBSUB_OWNER))
            .and_then(|c| c.get_child("x", NS_XDATA)),
        Some(_) => reply.get_child("query", NS_DISCO_INFO).and_then(|q| {
            q.children().find(|x| {
                x.is("x", NS_XDATA)
                    && form_values(x, "FORM_TYPE").first().map(String::as_str)
                        == Some("http://jabber.org/protocol/pubsub#meta-data")
            })
        }),
    };
    form.is_some_and(|f| form_values(f, "pubsub#access_model").first().map(String::as_str) == Some("open"))
}

/// A post as cached in the store, and back.
pub fn to_row(p: &FeedPost) -> FeedPostRow {
    FeedPostRow {
        author: p.author.clone(),
        id: p.id.clone(),
        title: p.title.clone(),
        content: p.content.clone(),
        published: p.published,
        link: p.link.clone(),
        attachment_url: p.attachment_url.clone(),
        attachment_type: p.attachment_type.clone(),
        comments_jid: p.comments_jid.clone(),
        comments_node: p.comments_node.clone(),
    }
}

pub fn from_row(r: FeedPostRow) -> FeedPost {
    FeedPost {
        id: r.id,
        author: r.author,
        title: r.title,
        content: r.content,
        published: r.published,
        link: r.link,
        attachment_url: r.attachment_url,
        attachment_type: r.attachment_type,
        comments_jid: r.comments_jid,
        comments_node: r.comments_node,
    }
}

/// Fetch a post's comments from its comments node `node` on `service`; oldest first.
pub async fn fetch_comments(w: &Writer, service: &str, node: &str) -> Vec<FeedPost> {
    let Ok(reply) = pep::items(w, Some(service), node, Some(100)).await else {
        return Vec::new();
    };
    let mut comments: Vec<FeedPost> = pep::extract_items_with_publisher(&reply)
        .iter()
        .filter_map(|(id, publisher, entry)| parse_comment(id.as_deref(), publisher.as_deref(), entry))
        .collect();
    comments.sort_by_key(|c| c.published);
    comments
}

// --- publishing ----------------------------------------------------------------------------

/// What a post carries besides its text.
#[derive(Debug, Clone, Default)]
pub struct PostExtras {
    /// An uploaded attachment (URL, MIME type).
    pub attachment: Option<(String, String)>,
    /// A related web link.
    pub link: Option<String>,
    /// When editing: the post id and its original publication time (unix seconds). XEP-0277:
    /// an edit keeps `<published>` (and the Atom id) and only moves `<updated>`.
    pub edit: Option<(String, i64)>,
}

/// Build the Atom entry of a post, as monocles Android does.
fn post_entry(cfg: &AccountConfig, post_id: &str, title: &str, content: &str, extras: &PostExtras) -> Element {
    let now = chrono::Utc::now();
    let published = extras
        .edit
        .as_ref()
        .and_then(|(_, ts)| chrono::DateTime::from_timestamp(*ts, 0))
        .unwrap_or(now);
    let fmt = |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let server = cfg.bare().split('@').nth(1).unwrap_or(cfg.bare());
    let owner = escape_jid(cfg.bare());
    let text = |name: &str, value: &str| {
        Element::builder(name, NS_ATOM).attr(crate::ncname("type"), "text").append(value).build()
    };

    let mut entry = Element::builder("entry", NS_ATOM)
        // The Atom id must stay the same across edits, so it is dated by the first publication.
        .append(
            Element::builder("id", NS_ATOM)
                .append(format!("tag:{server},{}:{post_id}", published.format("%Y-%m-%d")))
                .build(),
        )
        .append(link("alternate", &format!("xmpp:{owner}?;node={NS_MICROBLOG};item={post_id}"), None))
        .append(
            Element::builder("link", NS_ATOM)
                .attr(crate::ncname("rel"), "replies")
                .attr(crate::ncname("title"), "comments")
                .attr(crate::ncname("href"), format!("xmpp:{owner}?;node={}", comments_node(post_id)))
                .build(),
        )
        // Atom (and XEP-0277) require exactly one <title>, even when it is empty.
        .append(text("title", title));
    if !content.is_empty() {
        // The Markdown source (what we read back, so edits round-trip exactly) and the rendered
        // body: Movim only displays html/xhtml content and, like Android, gets both.
        entry = entry.append(text("content", content)).append(
            Element::builder("content", NS_ATOM)
                .attr(crate::ncname("type"), "xhtml")
                .append(atom_text::markdown_to_xhtml_div(content))
                .build(),
        );
    }
    // Hashtags as Atom categories, which is how Movim and XEP-0277 tag posts.
    for tag in atom_text::extract_hashtags(&format!("{title}\n{content}")) {
        entry = entry.append(Element::builder("category", NS_ATOM).attr(crate::ncname("term"), tag).build());
    }
    if let Some((url, mime)) = &extras.attachment {
        entry = entry.append(link("enclosure", url, Some(mime)));
    }
    if let Some(url) = extras.link.as_deref().filter(|l| !l.trim().is_empty()) {
        entry = entry.append(link("related", url.trim(), None));
    }
    entry
        .append(author_element(cfg))
        .append(Element::builder("published", NS_ATOM).append(fmt(published)).build())
        .append(Element::builder("updated", NS_ATOM).append(fmt(now)).build())
        .append(
            Element::builder("generator", NS_ATOM)
                .attr(crate::ncname("uri"), "https://monocles.chat")
                .attr(crate::ncname("version"), env!("CARGO_PKG_VERSION"))
                .append("monocles chat desktop")
                .build(),
        )
        .build()
}

fn link(rel: &str, href: &str, mime: Option<&str>) -> Element {
    let mut l = Element::builder("link", NS_ATOM)
        .attr(crate::ncname("rel"), rel)
        .attr(crate::ncname("href"), href);
    if let Some(m) = mime {
        l = l.attr(crate::ncname("type"), m);
    }
    l.build()
}

/// Publish a top-level post to our own feed (or replace one when `extras.edit` is set). A new
/// post also gets its comments node, readable by the same people as the feed.
pub async fn publish_post(
    w: &Writer,
    cfg: &AccountConfig,
    title: &str,
    content: &str,
    extras: &PostExtras,
) -> anyhow::Result<()> {
    let post_id = match &extras.edit {
        Some((id, _)) => id.clone(),
        None => {
            // Whether or not this works, publish: an existing node is the normal case, and
            // otherwise the server auto-creates one with its defaults.
            create_node_with_fallback(w, None, NS_MICROBLOG, |max| node_config(&post_config(max))).await;
            uuid_v4()
        }
    };
    let entry = post_entry(cfg, &post_id, title, content, extras);
    pep::publish(w, NS_MICROBLOG, Some(&post_id), entry, None).await?;
    if extras.edit.is_none() {
        create_own_comments_node(w, cfg, &post_id).await;
    }
    Ok(())
}

/// Publish a comment to the comments node `node` on `service`.
pub async fn publish_comment(
    w: &Writer,
    cfg: &AccountConfig,
    service: &str,
    node: &str,
    content: &str,
) -> anyhow::Result<()> {
    // Only the comments node of our own post is ours to (re)create, e.g. if that failed when
    // the post was published. Someone else's node is theirs; we just publish to it.
    if let Some(post_id) = node.strip_prefix(COMMENTS_NODE_PREFIX).filter(|id| !id.is_empty()) {
        if bare(service).eq_ignore_ascii_case(cfg.bare()) {
            create_own_comments_node(w, cfg, post_id).await;
        }
    }

    let now = crate::xeps::rfc3339_now();
    let item_id = uuid_v4();
    let server = cfg.bare().split('@').nth(1).unwrap_or(cfg.bare());
    let entry = Element::builder("entry", NS_ATOM)
        .append(Element::builder("title", NS_ATOM).attr(crate::ncname("type"), "text").append(content).build())
        .append(author_element(cfg))
        // tag: URI (RFC 4151): the date part is a plain date, not a full timestamp.
        .append(Element::builder("id", NS_ATOM).append(format!("tag:{server},{}:comments-{item_id}", &now[..10])).build())
        .append(Element::builder("published", NS_ATOM).append(now.as_str()).build())
        .append(Element::builder("updated", NS_ATOM).append(now.as_str()).build())
        .build();
    let item = Element::builder("item", NS_PUBSUB).attr(crate::ncname("id"), item_id).append(entry).build();
    let publish = Element::builder("publish", NS_PUBSUB).attr(crate::ncname("node"), node).append(item).build();
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("pep-cmt"))
        .attr(crate::ncname("to"), service)
        .append(Element::builder("pubsub", NS_PUBSUB).append(publish).build())
        .build();
    iq::request(w, req).await?;
    Ok(())
}

/// Retract a comment from the comments node `node` on `service` (ours, or any on our post).
pub async fn retract_comment(w: &Writer, service: &str, node: &str, comment_id: &str) -> anyhow::Result<()> {
    let retract = Element::builder("retract", NS_PUBSUB)
        .attr(crate::ncname("node"), node)
        .attr(crate::ncname("notify"), "true")
        .append(Element::builder("item", NS_PUBSUB).attr(crate::ncname("id"), comment_id).build())
        .build();
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("pep-cmt-del"))
        .attr(crate::ncname("to"), service)
        .append(Element::builder("pubsub", NS_PUBSUB).append(retract).build())
        .build();
    iq::request(w, req).await?;
    Ok(())
}

// --- node configuration --------------------------------------------------------------------

/// XEP-0472 microblog node config (presence access; only the owner publishes). Notifications
/// carry no payload (as with Movim and Android); receivers fetch the announced item.
fn post_config(max_items: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("pubsub#node_type", vec!["leaf".into()]),
        ("pubsub#type", vec![NS_MICROBLOG.into()]),
        ("pubsub#access_model", vec!["presence".into()]),
        ("pubsub#persist_items", vec!["1".into()]),
        ("pubsub#deliver_payloads", vec!["0".into()]),
        ("pubsub#send_last_published_item", vec!["never".into()]),
        ("pubsub#max_items", vec![max_items.into()]),
        ("pubsub#notify_retract", vec!["1".into()]),
        ("pubsub#deliver_notifications", vec!["1".into()]),
        ("pubsub#publish_model", vec!["publishers".into()]),
    ]
}

/// Who may read our microblog, as mirrored onto comments nodes.
#[derive(Debug, Clone, PartialEq)]
struct FeedAccess {
    model: String,
    roster_groups: Vec<String>,
}

/// Per-post comments node config: anyone who can read the post may comment (open publish),
/// but only the post's audience (`access`) may read the discussion.
fn comments_config(access: &FeedAccess, max_items: &str) -> Vec<(&'static str, Vec<String>)> {
    let mut fields = vec![
        ("pubsub#node_type", vec!["leaf".into()]),
        ("pubsub#type", vec!["urn:xmpp:microblog:0:comments".into()]),
        ("pubsub#access_model", vec![access.model.clone()]),
        ("pubsub#persist_items", vec!["1".into()]),
        ("pubsub#max_items", vec![max_items.into()]),
        ("pubsub#notify_retract", vec!["1".into()]),
        ("pubsub#deliver_notifications", vec!["1".into()]),
        ("pubsub#deliver_payloads", vec!["1".into()]),
        ("pubsub#send_last_published_item", vec!["on_sub".into()]),
        ("pubsub#publish_model", vec!["open".into()]),
        ("pubsub#itemreply", vec!["publisher".into()]),
        // Stamp each comment with its real publisher: anyone may publish here, so the Atom
        // <author> alone can't be trusted (checked in parse_comment).
        ("pubsub#itempublisher", vec!["1".into()]),
    ];
    if access.model == "roster" && !access.roster_groups.is_empty() {
        fields.push(("pubsub#roster_groups_allowed", access.roster_groups.clone()));
    }
    fields
}

fn node_config(fields: &[(&str, Vec<String>)]) -> Element {
    let mut x = Element::builder("x", NS_XDATA).attr(crate::ncname("type"), "submit").append(
        Element::builder("field", NS_XDATA)
            .attr(crate::ncname("var"), "FORM_TYPE")
            .attr(crate::ncname("type"), "hidden")
            .append(Element::builder("value", NS_XDATA).append(NS_NODE_CONFIG).build())
            .build(),
    );
    for (var, values) in fields {
        let mut field = Element::builder("field", NS_XDATA).attr(crate::ncname("var"), *var);
        for value in values {
            field = field.append(Element::builder("value", NS_XDATA).append(value.as_str()).build());
        }
        x = x.append(field.build());
    }
    x.build()
}

/// Create + configure a PubSub node. Ok if it exists afterwards (created, or already there).
async fn create_node(w: &Writer, to: Option<&str>, node: &str, config: Element) -> anyhow::Result<()> {
    let create = Element::builder("create", NS_PUBSUB).attr(crate::ncname("node"), node).build();
    let configure = Element::builder("configure", NS_PUBSUB).append(config).build();
    let pubsub = Element::builder("pubsub", NS_PUBSUB).append(create).append(configure).build();
    let mut req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("pep-create"));
    if let Some(j) = to {
        req = req.attr(crate::ncname("to"), j);
    }
    match iq::request(w, req.append(pubsub).build()).await {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("conflict") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Create `node` with max_items "max"; a server that predates that keyword rejects the whole
/// form (and would then auto-create the node on publish with its default, possibly tiny, item
/// limit), so any other error is retried once with a number. Returns whether the node exists.
async fn create_node_with_fallback(
    w: &Writer,
    to: Option<&str>,
    node: &str,
    config: impl Fn(&str) -> Element,
) -> bool {
    if create_node(w, to, node, config(MAX_ITEMS)).await.is_ok() {
        return true;
    }
    match create_node(w, to, node, config(FALLBACK_MAX_ITEMS)).await {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!(%node, error = %e, "could not create pubsub node");
            false
        }
    }
}

/// The comments node of our post `post_id`, readable by the post's audience. An open comments
/// node would let anyone read the discussion of a contacts-only post.
async fn create_own_comments_node(w: &Writer, cfg: &AccountConfig, post_id: &str) {
    let access = feed_access(w, cfg).await;
    create_node_with_fallback(w, None, &comments_node(post_id), |max| node_config(&comments_config(&access, max))).await;
}

/// Request the configuration form of `node` on our own service.
async fn node_configuration(w: &Writer, cfg: &AccountConfig, node: &str) -> Option<Element> {
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("id"), new_id("pep-cfg"))
        .attr(crate::ncname("to"), cfg.bare())
        .append(
            Element::builder("pubsub", pep::NS_PUBSUB_OWNER)
                .append(Element::builder("configure", pep::NS_PUBSUB_OWNER).attr(crate::ncname("node"), node).build())
                .build(),
        )
        .build();
    let reply = iq::request(w, req).await.ok()?;
    reply
        .get_child("pubsub", pep::NS_PUBSUB_OWNER)?
        .get_child("configure", pep::NS_PUBSUB_OWNER)?
        .get_child("x", NS_XDATA)
        .cloned()
}

fn form_values(form: &Element, var: &str) -> Vec<String> {
    form.children()
        .find(|f| f.name() == "field" && f.attr("var") == Some(var))
        .map(|f| f.children().filter(|v| v.name() == "value").map(|v| v.text()).collect())
        .unwrap_or_default()
}

/// Map an access model of our microblog onto one comments nodes can use. Falls back to
/// "presence" (contacts only), so comments are never more public than intended.
fn map_access(model: Option<&str>, groups: Vec<String>) -> FeedAccess {
    let model = match model {
        Some(m @ ("open" | "presence" | "whitelist" | "authorize")) => m.to_string(),
        Some("roster") if !groups.is_empty() => "roster".to_string(),
        _ => "presence".to_string(),
    };
    let roster_groups = if model == "roster" { groups } else { Vec::new() };
    FeedAccess { model, roster_groups }
}

async fn feed_access(w: &Writer, cfg: &AccountConfig) -> FeedAccess {
    match node_configuration(w, cfg, NS_MICROBLOG).await {
        Some(form) => {
            let model = form_values(&form, "pubsub#access_model").into_iter().next();
            map_access(model.as_deref(), form_values(&form, "pubsub#roster_groups_allowed"))
        }
        None => map_access(None, Vec::new()),
    }
}

/// Comments nodes used to be created open, regardless of the post's audience. Once per account,
/// give the existing ones on our PEP service the access model of the microblog (as Android's
/// `fixCommentsNodesAccessOnce`).
pub async fn align_comments_access_once(w: &Writer, store: &Store, cfg: &AccountConfig) {
    let key = format!("comments_nodes_access_fixed:{}", cfg.account_id);
    if store.flag(&key).await.unwrap_or(false) {
        return;
    }
    let access = feed_access(w, cfg).await;
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("id"), new_id("disco-items"))
        .attr(crate::ncname("to"), cfg.bare())
        .append(Element::builder("query", NS_DISCO_ITEMS).build())
        .build();
    let Ok(reply) = iq::request(w, req).await else { return };
    let Some(query) = reply.get_child("query", NS_DISCO_ITEMS) else { return };
    let mut count = 0;
    for item in query.children().filter(|c| c.name() == "item") {
        let Some(node) = item.attr("node").filter(|n| n.starts_with(COMMENTS_NODE_PREFIX)) else { continue };
        // Only nodes on our own PEP service are ours to reconfigure.
        if !item.attr("jid").is_some_and(|j| bare(j).eq_ignore_ascii_case(cfg.bare())) {
            continue;
        }
        count += 1;
        let Some(form) = node_configuration(w, cfg, node).await else { continue };
        if form_values(&form, "pubsub#access_model").first() == Some(&access.model) {
            continue;
        }
        let mut fields = vec![("pubsub#access_model", vec![access.model.clone()])];
        if access.model == "roster" {
            fields.push(("pubsub#roster_groups_allowed", access.roster_groups.clone()));
        }
        let set = Element::builder("iq", "jabber:client")
            .attr(crate::ncname("type"), "set")
            .attr(crate::ncname("id"), new_id("pep-cfg-set"))
            .attr(crate::ncname("to"), cfg.bare())
            .append(
                Element::builder("pubsub", pep::NS_PUBSUB_OWNER)
                    .append(
                        Element::builder("configure", pep::NS_PUBSUB_OWNER)
                            .attr(crate::ncname("node"), node)
                            .append(node_config(&fields))
                            .build(),
                    )
                    .build(),
            )
            .build();
        if let Err(e) = iq::request(w, set).await {
            tracing::debug!(%node, error = %e, "could not change comments node access model");
        }
    }
    tracing::info!(count, model = %access.model, "aligned comments nodes' access model with the microblog");
    let _ = store.set_flag(&key).await;
}

// --- incoming notifications ----------------------------------------------------------------

/// Handle a PEP/PubSub notification for a microblog or comments node. Returns true if it was
/// one (and thus consumed). Items without payload (XEP-0472 / Movim / Android nodes notify
/// without one) are fetched by id.
pub async fn handle_event(w: &Writer, store: &Store, cfg: &AccountConfig, events: &Sender<Event>, msg: &Element) -> bool {
    let Some(items) = msg
        .get_child("event", NS_PUBSUB_EVENT)
        .and_then(|e| e.get_child("items", NS_PUBSUB_EVENT))
    else {
        return false;
    };
    let Some(node) = items.attr("node").filter(|n| *n == NS_MICROBLOG || n.starts_with(COMMENTS_NODE_PREFIX))
    else {
        return false;
    };
    let Some(service) = msg.attr("from").map(bare).filter(|s| !s.is_empty()) else { return true };
    let account_id = cfg.account_id;

    if node.starts_with(COMMENTS_NODE_PREFIX) {
        // The UI matches the node against its posts' comments links and refetches.
        let _ = events
            .send(Event::FeedCommentsChanged { account_id, service: service.to_string(), node: node.to_string() })
            .await;
        return true;
    }

    for child in items.children() {
        let Some(id) = child.attr("id") else { continue };
        match child.name() {
            "item" => {
                let post = match child.get_child("entry", NS_ATOM) {
                    Some(entry) => parse_post(Some(id), entry, service),
                    None => fetch_item(w, service, id).await,
                };
                if let Some(post) = post {
                    let _ = store.upsert_feed_post(account_id, &to_row(&post)).await;
                    let _ = events.send(Event::FeedPostReceived { account_id, post }).await;
                }
            }
            "retract" => {
                // Only the node owner's own post (`service` = the event's sender).
                let _ = store.delete_feed_post(account_id, service, id).await;
                let _ = events
                    .send(Event::FeedPostRetracted { account_id, author: service.to_string(), post_id: id.to_string() })
                    .await;
            }
            _ => {}
        }
    }
    true
}

/// Fetch one announced post by id from `owner`'s microblog.
async fn fetch_item(w: &Writer, owner: &str, id: &str) -> Option<FeedPost> {
    let reply = pep::item(w, Some(owner), NS_MICROBLOG, id).await.ok()?;
    pep::extract_items(&reply)
        .iter()
        .filter(|(item_id, _)| item_id.as_deref() == Some(id))
        .find_map(|(item_id, entry)| parse_post(item_id.as_deref(), entry, owner))
}

// --- helpers -------------------------------------------------------------------------------

/// A random (v4) UUID, the item id format Android uses.
pub(crate) fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn bare(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

/// Escape a JID for an `xmpp:` URI (RFC 5122): percent-encode what isn't allowed in the path.
fn escape_jid(jid: &str) -> String {
    let mut out = String::with_capacity(jid.len());
    for b in jid.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,=:@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // From the bytes: slicing the str could split a multi-byte character and panic.
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `xmpp:<jid>?;node=<node>[;item=…]` → (bare JID, node).
fn parse_node_uri(href: &str) -> Option<(String, String)> {
    let rest = href.trim().strip_prefix("xmpp:")?;
    let (jid, query) = rest.split_once('?')?;
    let jid = percent_decode(jid);
    let node = query
        .split(';')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == "node")
        .map(|(_, v)| percent_decode(v))?;
    let jid = bare(&jid).to_string();
    (!jid.is_empty() && !node.is_empty()).then_some((jid, node))
}

/// Guess a MIME type from a URL's file extension (other clients may omit the enclosure type).
pub fn mime_from_url(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.rsplit('/').next().unwrap_or(path);
    if !name.contains('.') {
        return "application/octet-stream".into();
    }
    crate::xeps::http_upload::guess_mime(name).to_string()
}

fn author_element(cfg: &AccountConfig) -> Element {
    Element::builder("author", NS_ATOM)
        .append(Element::builder("name", NS_ATOM).append(cfg.bare()).build())
        .append(Element::builder("uri", NS_ATOM).append(format!("xmpp:{}", escape_jid(cfg.bare()))).build())
        .build()
}

// --- parsing -------------------------------------------------------------------------------

/// The bare JID claimed by the entry's Atom `<author><uri>xmpp:…</uri>`, if any. This is free
/// text written by whoever published the item - only a claim.
fn claimed_author(entry: &Element) -> Option<String> {
    entry
        .get_child("author", NS_ATOM)
        .and_then(|a| a.get_child("uri", NS_ATOM))
        .map(|u| u.text())
        .and_then(|uri| {
            uri.trim()
                .strip_prefix("xmpp:")
                .map(|s| percent_decode(s.split(['/', '?']).next().unwrap_or(s)))
        })
        .filter(|s| !s.is_empty())
}

/// The author of an item published by `publisher` (bare JID): the publisher itself. A claimed
/// `<author>` naming someone else makes the item invalid (None) - otherwise anyone could post
/// "as" one of our contacts on their own node (as in monocles Android's Post/Comment).
fn verified_author(entry: &Element, publisher: &str) -> Option<String> {
    let publisher = bare(publisher);
    match claimed_author(entry) {
        Some(claimed) if !claimed.eq_ignore_ascii_case(publisher) => {
            tracing::warn!(%claimed, %publisher, "ignoring feed item whose author isn't its publisher");
            None
        }
        _ => Some(publisher.to_string()),
    }
}

/// Unix seconds of `<published>`, else `<updated>` (edited entries keep `<published>`; entries
/// without it are dated by `<updated>`), else now.
fn published_of(entry: &Element) -> i64 {
    ["published", "updated"]
        .iter()
        .filter_map(|n| entry.get_child(n, NS_ATOM))
        .find_map(|e| chrono::DateTime::parse_from_rfc3339(e.text().trim()).ok())
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|| chrono::Utc::now().timestamp())
}

fn item_id_of(item_id: Option<&str>, entry: &Element) -> String {
    item_id
        .map(str::to_string)
        .or_else(|| {
            entry.get_child("id", NS_ATOM).map(|e| {
                let t = e.text();
                t.trim().strip_prefix("urn:uuid:").unwrap_or(t.trim()).to_string()
            })
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(uuid_v4)
}

/// Movim and monocles publish the Markdown source as `type="text"` next to the rendered
/// `type="xhtml"` body. The source is exact, so it wins; otherwise the first other one.
fn preferred_content(entry: &Element) -> Option<&Element> {
    let contents: Vec<&Element> = entry.children().filter(|c| c.is("content", NS_ATOM)).collect();
    contents
        .iter()
        .find(|c| matches!(c.attr("type"), None | Some("text")) && !c.text().trim().is_empty())
        .or_else(|| contents.first())
        .copied()
}

/// Atom `<category term>` tags (how Movim and XEP-0277 tag posts) as hashtags at the end of the
/// content, so they are visible like inline ones - minus those already in the text.
fn append_categories(entry: &Element, title: &str, content: String) -> String {
    let existing = format!("{title} {content}").to_lowercase();
    let mut tags: Vec<String> = Vec::new();
    for c in entry.children().filter(|c| c.is("category", NS_ATOM)) {
        let term: String = c.attr("term").unwrap_or_default().chars().filter(|ch| !ch.is_whitespace() && *ch != '#').collect();
        if term.is_empty() || existing.contains(&format!("#{}", term.to_lowercase())) || tags.contains(&format!("#{term}")) {
            continue;
        }
        tags.push(format!("#{term}"));
    }
    if tags.is_empty() {
        return content;
    }
    let line = tags.join(" ");
    if content.is_empty() { line } else { format!("{content}\n\n{line}") }
}

/// Parse one Atom `<entry>` from `owner_bare`'s microblog node into a top-level [`FeedPost`].
fn parse_post(item_id: Option<&str>, entry: &Element, owner_bare: &str) -> Option<FeedPost> {
    if entry.name() != "entry" {
        return None;
    }
    let title = entry.get_child("title", NS_ATOM).and_then(atom_text::to_markdown).unwrap_or_default();
    let content = preferred_content(entry).and_then(atom_text::to_markdown).unwrap_or_default();

    let mut link = String::new();
    let mut attachment: Option<(String, String)> = None;
    let mut comments: Option<(String, String)> = None;
    let mut comments_titled = false;
    for l in entry.children().filter(|c| c.is("link", NS_ATOM)) {
        let href = l.attr("href").unwrap_or_default().trim();
        if href.is_empty() {
            continue;
        }
        match l.attr("rel") {
            // XEP-0277 marks the comments node with title="comments"; a post may carry other
            // replies links too.
            Some("replies") => {
                let titled = l.attr("title") == Some("comments");
                if comments.is_none() || (titled && !comments_titled) {
                    if let Some(c) = parse_node_uri(href) {
                        comments = Some(c);
                        comments_titled = titled;
                    }
                }
            }
            // Keep the first enclosure (Movim can attach several pictures).
            Some("enclosure") if attachment.is_none() => {
                let mime = l.attr("type").filter(|t| !t.trim().is_empty()).map(str::to_string);
                attachment = Some((href.to_string(), mime.unwrap_or_else(|| mime_from_url(href))));
            }
            Some("related") if link.is_empty() => link = href.to_string(),
            _ => {}
        }
    }
    let content = append_categories(entry, &title, content);

    if title.trim().is_empty() && content.trim().is_empty() && attachment.is_none() {
        return None;
    }
    // A post on `owner_bare`'s microblog node is by `owner_bare`.
    let author = verified_author(entry, owner_bare)?;
    let (attachment_url, attachment_type) = attachment.unwrap_or_default();
    let (comments_jid, comments_node) = comments.unwrap_or_default();
    Some(FeedPost {
        id: item_id_of(item_id, entry),
        author,
        title,
        content,
        published: published_of(entry),
        link,
        attachment_url,
        attachment_type,
        comments_jid,
        comments_node,
    })
}

/// Parse one comment entry (its body is the `<title>`). Comments nodes are open for anyone to
/// publish to; when the service stamped the item's `publisher`, that is the author and a
/// different claimed `<author>` drops the comment. Without it (nodes created without
/// `pubsub#itempublisher`) the claim can't be verified and is shown as-is.
fn parse_comment(item_id: Option<&str>, publisher: Option<&str>, entry: &Element) -> Option<FeedPost> {
    if entry.name() != "entry" {
        return None;
    }
    // An Atom text construct (Movim may send xhtml); fall back to <content> for tolerance.
    let content = entry
        .get_child("title", NS_ATOM)
        .and_then(atom_text::to_markdown)
        .or_else(|| preferred_content(entry).and_then(atom_text::to_markdown))?;
    let author = match publisher {
        Some(p) => verified_author(entry, p)?,
        None => claimed_author(entry).unwrap_or_default(),
    };
    Some(FeedPost {
        id: item_id_of(item_id, entry),
        author,
        content,
        published: published_of(entry),
        ..FeedPost::default()
    })
}

#[cfg(test)]
mod authorship_tests {
    use super::*;

    fn entry(author: Option<&str>) -> Element {
        let mut e = Element::builder("entry", NS_ATOM)
            .append(Element::builder("title", NS_ATOM).append("hello").build());
        if let Some(a) = author {
            e = e.append(
                Element::builder("author", NS_ATOM)
                    .append(Element::builder("uri", NS_ATOM).append(a).build())
                    .build(),
            );
        }
        e.build()
    }

    #[test]
    fn post_must_be_by_node_owner() {
        let ok = parse_post(Some("p1"), &entry(Some("xmpp:alice@example.org")), "alice@example.org").unwrap();
        assert_eq!(ok.author, "alice@example.org");
        assert!(parse_post(Some("p1"), &entry(Some("xmpp:bob@example.org")), "alice@example.org").is_none());
        assert_eq!(parse_post(Some("p1"), &entry(None), "alice@example.org").unwrap().author, "alice@example.org");
    }

    #[test]
    fn comment_must_match_stamped_publisher() {
        assert!(parse_comment(Some("c1"), Some("mallory@evil.org/x"), &entry(Some("xmpp:alice@example.org"))).is_none());
        let ok = parse_comment(Some("c1"), Some("alice@example.org/web"), &entry(Some("xmpp:alice@example.org"))).unwrap();
        assert_eq!(ok.author, "alice@example.org");
        let anon = parse_comment(Some("c1"), Some("bob@example.org"), &entry(None)).unwrap();
        assert_eq!(anon.author, "bob@example.org");
        // Unstamped nodes: unverifiable claim kept (documented limitation).
        assert_eq!(parse_comment(Some("c1"), None, &entry(Some("xmpp:carol@example.org"))).unwrap().author, "carol@example.org");
    }
}

/// XEP-0277 entries as Movim and other clients publish them (ported from Android's
/// `PostParsingTest`).
#[cfg(test)]
mod parsing_tests {
    use super::*;

    fn movim_item() -> Element {
        format!(
            "<entry xmlns='{NS_ATOM}'>\
               <title type='text'>Hello from Movim</title>\
               <content type='xhtml'><div xmlns='http://www.w3.org/1999/xhtml'><p>Hello <strong>world</strong></p></div></content>\
               <author><name>Juliet</name><uri>xmpp:juliet@capulet.lit</uri></author>\
               <updated>2026-10-01T12:00:00Z</updated>\
               <link rel='alternate' href='xmpp:juliet@capulet.lit?;node=urn:xmpp:microblog:0;item=my-post-abc'/>\
               <link rel='replies' title='other' href='xmpp:elsewhere.lit?;node=x'/>\
               <link rel='replies' title='comments' href='xmpp:juliet@capulet.lit?;node=urn:xmpp:microblog:0:comments/my-post-abc'/>\
               <link rel='enclosure' href='https://upload.capulet.lit/a/photo.jpg'/>\
               <link rel='enclosure' href='https://upload.capulet.lit/b/second.png' type='image/png'/>\
               <category term='Balcony'/><category term='world'/>\
             </entry>"
        )
        .parse()
        .unwrap()
    }

    #[test]
    fn movim_entry_is_parsed() {
        let post = parse_post(Some("my-post-abc"), &movim_item(), "juliet@capulet.lit").unwrap();
        assert_eq!(post.id, "my-post-abc");
        assert_eq!(post.title, "Hello from Movim");
        assert!(post.content.starts_with("Hello **world**"), "{}", post.content);
        // Categories become hashtags, without repeating one already in the text.
        assert!(post.content.ends_with("#Balcony #world"), "{}", post.content);
        assert_eq!(post.comments_jid, "juliet@capulet.lit");
        assert_eq!(post.comments_node, "urn:xmpp:microblog:0:comments/my-post-abc");
        assert_eq!(post.attachment_url, "https://upload.capulet.lit/a/photo.jpg");
        assert_eq!(post.attachment_type, "image/jpeg");
        assert_eq!(post.published, 1_790_856_000);
        // The self-referencing alternate link isn't shown as the post's web link.
        assert!(post.link.is_empty());
    }

    #[test]
    fn entry_of_another_author_is_rejected() {
        assert!(parse_post(Some("x"), &movim_item(), "mallory@evil.lit").is_none());
    }

    #[test]
    fn markdown_source_wins_over_rendered_xhtml_and_round_trips() {
        let cfg = AccountConfig::new(1, "juliet@capulet.lit/desk".into(), String::new());
        let extras = PostExtras {
            attachment: Some(("https://u/p.jpg".into(), "image/jpeg".into())),
            link: Some("https://example.org".into()),
            edit: Some(("p1".into(), 1_700_000_000)),
        };
        let entry = post_entry(&cfg, "p1", "Title", "a\nb  *exact* source #Tag", &extras);
        let post = parse_post(Some("p1"), &entry, "juliet@capulet.lit").unwrap();
        assert_eq!(post.title, "Title");
        assert_eq!(post.content, "a\nb  *exact* source #Tag");
        assert_eq!(post.published, 1_700_000_000);
        assert_eq!(post.link, "https://example.org");
        assert_eq!(post.attachment_url, "https://u/p.jpg");
        assert_eq!(post.comments_jid, "juliet@capulet.lit");
        assert_eq!(post.comments_node, "urn:xmpp:microblog:0:comments/p1");
        assert!(entry.children().any(|c| c.name() == "category" && c.attr("term") == Some("tag")));
        assert!(entry.children().any(|c| c.name() == "content" && c.attr("type") == Some("xhtml")));
    }

    #[test]
    fn node_uris_are_parsed() {
        assert_eq!(
            parse_node_uri("xmpp:pubsub.movim.eu?;node=urn:xmpp:microblog:0:comments/abc"),
            Some(("pubsub.movim.eu".into(), "urn:xmpp:microblog:0:comments/abc".into()))
        );
        assert_eq!(parse_node_uri("xmpp:a%40b.org?;node=n%2Fx;item=1"), Some(("a@b.org".into(), "n/x".into())));
        assert_eq!(parse_node_uri("https://x"), None);
    }

    #[test]
    fn access_models_map_conservatively() {
        assert_eq!(map_access(Some("open"), vec![]).model, "open");
        assert_eq!(map_access(Some("roster"), vec![]).model, "presence");
        assert_eq!(map_access(Some("roster"), vec!["Friends".into()]).roster_groups, vec!["Friends"]);
        assert_eq!(map_access(Some("weird"), vec![]).model, "presence");
        assert_eq!(map_access(None, vec![]).model, "presence");
    }
}
