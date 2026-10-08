import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Window
import QtQuick.Dialogs
import de.monocles.chat
import "EmojiData.js" as EmojiData

ApplicationWindow {
    id: window
    visible: true
    width: 1000
    height: 680
    title: qsTr("monocles chat")

    // Modern Material look with the monocles brand palette: dark blue primary + light blue accent.
    Material.theme: Material.System
    Material.primary: "#283D6A"   // monocles dark blue (blacker_blue / secondary)
    Material.accent: "#7188C3"    // monocles light blue (blue / primaryContainer)

    // Bundled icon resources (see build.rs qrc_files).
    readonly property string iconBase: "qrc:/qt/qml/de/monocles/chat/icons/"

    // Chat background (persisted in Backend): resolved image URL + whether it tiles. The
    // bundled monocles doodle tile follows the theme and repeats; a custom photo crops to fill;
    // "none" yields an empty source (plain background).
    readonly property bool chatBgTile: backend.chatBgMode === "default"
    readonly property string chatBgSource: backend.chatBgMode === "none" ? ""
        : backend.chatBgMode === "custom"
            ? (backend.chatBgCustomPath.length > 0 ? "file://" + backend.chatBgCustomPath : "")
            : window.iconBase + (window.Material.theme === Material.Dark ? "chat-bg-dark.png"
                                                                        : "chat-bg-light.png")
    // One height for BOTH blue top bars (chats-list sidebar + conversation header), so they
    // line up; Material ToolButtons inside are constrained to 32px to fit.
    readonly property int headerHeight: 48

    // Session + currently-open conversation (the right pane follows these).
    property bool signedIn: false
    property string accountJid: ""
    property string currentPeerJid: ""
    property string currentPeerName: ""
    property bool currentPeerEncrypted: false
    property string currentPeerAvatar: ""
    property string currentPeerPresence: ""
    property bool currentPeerIsMuc: false
    property bool currentRoomOmemoCapable: false
    // Pending reply (XEP-0461): the target message's marker + a preview of its text.
    property string replyToMarker: ""
    property string replyToText: ""
    // Pending edit (XEP-0308): the target message's marker + its text before editing.
    property string editTargetMarker: ""
    property string editOriginalText: ""
    // Message search scope (Signal-style): empty JID = search every conversation; a set JID
    // scopes the chats-list search to that one chat, shown as an avatar chip in the search box.
    property string searchScopeJid: ""
    property string searchScopeName: ""
    property string searchScopeAvatar: ""

    // (Re)run the chats-list message search with the current query + scope.
    function runMessageSearch() {
        msgSearchModel.search(window.accountJid, window.searchScopeJid, chatSearchField.text)
    }

    // Scope the chats-list search to a conversation and focus the search box (the conversation
    // header's loupe calls this). Switches the sidebar to Chats so the box + results are visible.
    function scopeSearchTo(jid, name, avatar) {
        window.searchScopeJid = jid
        window.searchScopeName = name
        window.searchScopeAvatar = avatar
        shell.sectionIndex = 0
        chatSearchField.text = ""   // start fresh (also clears results via onTextChanged)
        window.runMessageSearch()
        chatSearchField.forceActiveFocus()
    }

    // Drop the scope chip → searches fall back to all conversations.
    function clearSearchScope() {
        window.searchScopeJid = ""
        window.searchScopeName = ""
        window.searchScopeAvatar = ""
        window.runMessageSearch()
    }

    // Sticker paths for the composer drawer (refreshed when it opens).
    property var stickerList: []

    // Open the shared reactions picker for the message `marker`, anchored to `button`.
    // ONE window-level popup (full emoji set ≈ 1900 entries) — a per-delegate picker would
    // instantiate its grid once per visible message row.
    function openReactPicker(button, marker) {
        reactPickerGlobal.targetMarker = marker
        reactPickerGlobal.parent = button
        reactPickerGlobal.open()
    }

    function startReply(marker, text) {
        window.clearEdit()
        window.replyToMarker = marker
        window.replyToText = text
    }
    function clearReply() {
        window.replyToMarker = ""
        window.replyToText = ""
    }
    // Load one of our own messages into the composer; the next send becomes a correction.
    function startEdit(marker, text) {
        window.clearReply()
        window.editTargetMarker = marker
        window.editOriginalText = text
        composer.text = text
        composer.cursorPosition = composer.length
        composer.forceActiveFocus()
    }
    function clearEdit() {
        if (window.editTargetMarker.length === 0)
            return
        window.editTargetMarker = ""
        window.editOriginalText = ""
        composer.clear()
    }
    function sendComposed() {
        if (composer.text.trim().length === 0)
            return
        // Editing: replace the original message (XEP-0308) instead of sending a new one.
        if (window.editTargetMarker.length > 0) {
            msgModel.correct(window.currentPeerJid, window.editTargetMarker, composer.text)
            window.editTargetMarker = ""
            window.editOriginalText = ""
            composer.clear()
            return
        }
        messageList.stickToEnd = true
        backend.sendMessage(window.currentPeerJid, composer.text, window.currentPeerEncrypted, window.replyToMarker)
        composer.clear()
        window.clearReply()
    }

    // Voice-message recording state.
    property bool recording: false
    property int recordSecs: 0
    function fmtSecs(s) {
        var m = Math.floor(s / 60), ss = s % 60
        return (m < 10 ? "0" : "") + m + ":" + (ss < 10 ? "0" : "") + ss
    }
    function beginVoice() {
        if (window.currentPeerJid.length === 0)
            return
        if (backend.startVoice()) {
            window.recordSecs = 0
            window.recording = true
            recordTimer.start()
        }
    }
    function cancelVoice() {
        recordTimer.stop()
        window.recording = false
        backend.cancelVoice()
    }
    function sendVoice() {
        recordTimer.stop()
        window.recording = false
        backend.stopVoiceAndSend(window.currentPeerJid)
    }
    Timer { id: recordTimer; interval: 1000; repeat: true; onTriggered: window.recordSecs++ }

    // Local file path of a story image/video chosen for posting (set by the file dialog).
    property string pendingStoryPath: ""
    /// Files picked in the attach dialog, awaiting their (shared) caption. More than one is
    /// sent as a single multi-file message.
    property var pendingAttachPaths: []

    // Friendly date-separator label from a "yyyy-MM-dd" day string.
    function dayLabel(day) {
        if (!day || day.length === 0) return ""
        var today = Qt.formatDateTime(new Date(), "yyyy-MM-dd")
        if (day === today) return qsTr("Today")
        var y = new Date(); y.setDate(y.getDate() - 1)
        if (day === Qt.formatDateTime(y, "yyyy-MM-dd")) return qsTr("Yesterday")
        var d = new Date(day + "T00:00:00")
        return isNaN(d.getTime()) ? day : Qt.formatDateTime(d, "MMMM d, yyyy")
    }

    // Bubble timestamp (local time): "hh:mm" for today's messages, date + time for older
    // ones, + year when it differs — like monocles chat Android.
    function msgTime(ts) {
        if (!ts || ts.length === 0) return ""
        var d = new Date(ts)
        if (isNaN(d.getTime())) return ""
        var now = new Date()
        if (d.toDateString() === now.toDateString())
            return Qt.formatDateTime(d, "hh:mm")
        if (d.getFullYear() === now.getFullYear())
            return Qt.formatDateTime(d, "d MMM, hh:mm")
        return Qt.formatDateTime(d, "d MMM yyyy, hh:mm")
    }

    // Relative-time label for a story's unix-seconds publish time.
    function agoText(unixSecs) {
        var d = Math.max(0, Math.floor(Date.now() / 1000) - unixSecs)
        if (d < 60) return qsTr("just now")
        if (d < 3600) return Math.floor(d / 60) + qsTr("m ago")
        if (d < 86400) return Math.floor(d / 3600) + qsTr("h ago")
        return Math.floor(d / 86400) + qsTr("d ago")
    }

    // Open the story viewer on `contact`'s stories (oldest first, as on Android), starting at
    // the story `uuid`.
    function openStoryViewer(contact, uuid) {
        storyViewer.openFor(contact, uuid)
    }

    // Open a link from feed content: only web and xmpp: links (never file: or other schemes a
    // post could smuggle in).
    function openSafeUrl(url) {
        var u = String(url).trim()
        if (/^(https?:\/\/|xmpp:)/i.test(u))
            Qt.openUrlExternally(u)
    }

    // Copy `text` to the clipboard (via an off-screen editor; QML has no clipboard API).
    TextEdit { id: clipboardHelper; visible: false }
    function copyText(text) {
        clipboardHelper.text = text
        clipboardHelper.selectAll()
        clipboardHelper.copy()
        clipboardHelper.text = ""
    }

    // Small red counter bubble for the nav rail (unread chats / new calls / stories / posts).
    component NavBadge: Rectangle {
        property int count: 0
        visible: count > 0
        z: 2
        color: "#e01b24"
        radius: height / 2
        width: Math.max(15, badgeLabel.implicitWidth + 7)
        height: 15
        border.width: 1
        border.color: Qt.darker(Material.background, 1.12)
        Label {
            id: badgeLabel
            textFormat: Text.PlainText
            anchors.centerIn: parent
            text: parent.count > 99 ? "99+" : parent.count
            color: "white"
            font.pixelSize: 9
            font.bold: true
        }
    }

    // The single live WebXDC app window (created dynamically on webxdcReady), like GTK/Android.
    property var webxdcWin: null
    // Transient toast text (WebXDC notifications); cleared by toastTimer.
    property string toastText: ""
    Timer { id: toastTimer; interval: 4000; onTriggered: window.toastText = "" }

    // vCard profile fields ([{label,value}]) for the open peer's details dialog.
    property var detailsFields: []
    // Whether our outgoing presence request is still awaiting the contact's approval.
    property bool presAskPending: false
    function openDetails() {
        window.detailsFields = []
        window.presAskPending = false
        presReceiveSwitch.checked = false
        presSendSwitch.checked = false
        backend.fetchVcard(window.currentPeerJid, window.currentPeerIsMuc)
        if (!window.currentPeerIsMuc) {
            contactDevices.load(window.currentPeerJid)
            backend.fetchSubscription(window.currentPeerJid)
        }
        detailsDialog.open()
    }

    // Currently-open feed post (for the detail/comments dialog). Copied from the feed row,
    // which a model reset may invalidate.
    property string feedPostId: ""
    property string feedPostAuthor: ""
    property string feedPostTitle: ""
    property string feedPostContent: ""
    property string feedPostHtml: ""
    property double feedPostPublished: 0
    property bool feedPostOwn: false
    property string feedPostLink: ""
    property string feedPostAttachmentUrl: ""
    property string feedPostAttachmentType: ""
    property string feedPostAttachmentPath: ""
    property bool feedPostCanComment: false
    property int feedPostLikes: 0
    property bool feedPostLiked: false
    // Public feed (open to anyone): only then is the post's link offered for sharing.
    property bool feedPostPublic: false
    function openPost(m) {
        window.feedPostId = m.postId
        window.feedPostAuthor = m.author
        window.feedPostTitle = m.title
        window.feedPostContent = m.content
        window.feedPostHtml = m.contentHtml
        window.feedPostPublished = m.published
        window.feedPostOwn = m.own
        window.feedPostLink = m.link
        window.feedPostAttachmentUrl = m.attachmentUrl
        window.feedPostAttachmentType = m.attachmentType
        window.feedPostAttachmentPath = m.attachmentPath
        window.feedPostCanComment = m.canComment
        window.feedPostLikes = m.likeCount
        window.feedPostLiked = m.liked
        window.feedPostPublic = m.isPublic
        commentModel.loadComments(m.author, m.postId)
        postScroll.contentY = 0
        postScroll.followNewComment = false
        postDetailDialog.open()
        // Pull this post's comments from its comments node (feedsChanged reloads them).
        backend.fetchComments(m.author, m.postId)
    }

    // Followed feeds / follow suggestions (Feeds section) and which list is expanded.
    property var followedList: []
    readonly property var suggestionList: backend.feedSuggestions.length > 0 ? backend.feedSuggestions.split("\n") : []
    property string feedPanel: ""
    function refreshFollowed() {
        var f = backend.followedFeeds()
        window.followedList = f.length > 0 ? f.split("\n") : []
        if (window.feedPanel === "following" && window.followedList.length === 0)
            window.feedPanel = ""
    }

    // Update the open post from the feed (an image finished downloading, the post was edited).
    function refreshOpenPost() {
        var a = window.feedPostAuthor, id = window.feedPostId
        var html = feedModel.fieldOf(a, id, "contentHtml")
        if (html === undefined)
            return    // not listed (any more)
        window.feedPostTitle = feedModel.fieldOf(a, id, "title")
        window.feedPostContent = feedModel.fieldOf(a, id, "content")
        window.feedPostHtml = html
        window.feedPostLink = feedModel.fieldOf(a, id, "link")
        window.feedPostAttachmentUrl = feedModel.fieldOf(a, id, "attachmentUrl")
        window.feedPostAttachmentType = feedModel.fieldOf(a, id, "attachmentType")
        window.feedPostAttachmentPath = feedModel.fieldOf(a, id, "attachmentPath")
        window.feedPostCanComment = feedModel.fieldOf(a, id, "canComment")
        window.feedPostLikes = feedModel.fieldOf(a, id, "likeCount")
        window.feedPostLiked = feedModel.fieldOf(a, id, "liked")
        window.feedPostPublic = feedModel.fieldOf(a, id, "isPublic")
    }

    // Post composer state: empty = a new post, else the id of our post being edited.
    property string editingPostId: ""
    property string pendingPostAttachment: ""
    property string editingPostAttachment: ""
    function openComposer(m) {
        window.pendingPostAttachment = ""
        if (m) {
            window.editingPostId = m.postId
            window.editingPostAttachment = m.attachmentUrl
            newPostTitle.text = m.title
            newPostContent.text = m.content
            newPostLink.text = m.link
        } else {
            window.editingPostId = ""
            window.editingPostAttachment = ""
            newPostTitle.text = ""
            newPostContent.text = ""
            newPostLink.text = ""
        }
        newPostDialog.open()
    }

    // Small "uploading" note while stories / posts are being prepared and published.
    component PublishingNote: RowLayout {
        visible: backend.publishing > 0
        spacing: 6
        BusyIndicator { running: parent.visible; implicitWidth: 18; implicitHeight: 18 }
        Label { textFormat: Text.PlainText; text: qsTr("Publishing…"); opacity: 0.7; font.pixelSize: 11 }
    }

    // Rust-backed objects (see src/backend.rs, src/model.rs, src/messages.rs, src/roster.rs).
    Backend { id: backend }
    ConversationModel { id: convModel }
    MessageModel { id: msgModel }
    MessageSearchModel { id: msgSearchModel }  // chats-list message search results
    RosterModel { id: rosterModel }
    OccupantModel { id: occupantModel }
    ConferenceModel { id: conferenceModel }   // active group-call participants (XEP-0272 Muji)
    DeviceModel { id: contactDevices }   // the open peer's OMEMO2 devices (keys dialog)
    DeviceModel { id: ownDevices }       // our own devices (account keys dialog)
    CallLogModel { id: callLogModel }    // call history (Calls section)
    StoryModel { id: storyModel }        // social-feed stories (Stories section)
    StoryModel { id: viewerStories }     // one publisher's stories, oldest first (story viewer)
    FeedModel { id: feedModel }          // XEP-0472 feed: top-level posts (Feeds section)
    FeedModel { id: commentModel }       // a post's replies (post detail)

    // Kick off a silent re-login from the saved account at startup.
    Component.onCompleted: backend.tryAutologin()

    Connections {
        target: backend
        // Auto-login (or any session start) sets the account JID → switch to the shell.
        function onAccountJidChanged() {
            // Logout empties the account JID → back to the login page, dropping open state.
            if (backend.accountJid.length === 0 && window.signedIn) {
                window.signedIn = false
                window.accountJid = ""
                window.currentPeerJid = ""
                window.currentPeerName = ""
                window.clearReply()
                window.clearEdit()
                return
            }
            if (backend.accountJid.length > 0 && !window.signedIn) {
                window.accountJid = backend.accountJid
                convModel.reload(window.accountJid)
                rosterModel.reload(window.accountJid)
                // Populate the nav badges right away (calls from the local log; stories +
                // feeds also fetch from the server so new posts since last run show up).
                callLogModel.reload(window.accountJid)
                storyModel.reload(window.accountJid)
                feedModel.reload(window.accountJid)
                backend.fetchStories()
                backend.fetchFeeds()
                window.signedIn = true
            }
        }
        function onConversationsChanged() {
            if (window.accountJid.length > 0) {
                convModel.reload(window.accountJid)
                rosterModel.reload(window.accountJid)
            }
        }
        function onMessageStored(conversationId) {
            msgModel.noteStored(conversationId)
        }
        function onRefreshOpen() {
            msgModel.reloadCurrent()
        }
        function onReactionsUpdated(messageId, reactions) {
            msgModel.applyReactions(messageId, reactions)
        }
        function onVcardReady(jid, fields) {
            if (jid !== window.currentPeerJid)
                return
            var rows = []
            if (fields.length > 0) {
                var lines = fields.split("\n")
                for (var i = 0; i < lines.length; i++) {
                    var p = lines[i].split("\t")
                    if (p[0] && p[0].length > 0)
                        rows.push({ "label": p[0], "value": p[1] || "" })
                }
            }
            window.detailsFields = rows
        }
        function onMucPrivacyChanged() {
            if (window.currentPeerIsMuc)
                window.currentRoomOmemoCapable = backend.mucOmemoCapable(window.currentPeerJid)
        }
        // RFC 6121 subscription state for the details dialog. Switches are set imperatively
        // (not bound) so a user toggle doesn't break the binding; the server's roster push
        // re-emits this and confirms (or reverts) the displayed state.
        function onSubscriptionChanged(jid, subscription, ask) {
            if (jid !== window.currentPeerJid)
                return
            var receiving = subscription === "to" || subscription === "both"
            presReceiveSwitch.checked = receiving
            presSendSwitch.checked = subscription === "from" || subscription === "both"
            window.presAskPending = ask === "subscribe" && !receiving
        }
        // Someone wants to see our presence → Allow/Decline prompt (Android's contact request).
        function onSubscriptionRequest(jid, nick) {
            if (subRequestDialog.visible && subRequestDialog.jid === jid)
                return
            subRequestDialog.jid = jid
            subRequestDialog.nick = nick
            subRequestDialog.open()
        }
        // WebXDC: the opened app is extracted + served → create its window (dynamically, so
        // the app still runs on systems without QtWebEngine installed).
        function onWebxdcReady(thread, host) {
            if (window.webxdcWin) {
                // destroy, not just close: a hidden app would keep running in the background
                window.webxdcWin.destroy()
                window.webxdcWin = null
            }
            var comp = Qt.createComponent("WebxdcWindow.qml")
            if (comp.status === Component.Error) {
                console.warn("WebXDC unavailable:", comp.errorString())
                return
            }
            window.webxdcWin = comp.createObject(window, { thread: thread, appHost: host })
            if (window.webxdcWin)
                window.webxdcWin.show()
        }
        function onWebxdcUpdates(thread, items) {
            if (window.webxdcWin && window.webxdcWin.thread === thread)
                window.webxdcWin.pushUpdates(items)
        }
        function onWebxdcRealtime(thread, dataB64) {
            if (window.webxdcWin && window.webxdcWin.thread === thread)
                window.webxdcWin.pushRealtime(dataB64)
        }
        function onWebxdcNotify(text) {
            window.toastText = text
            toastTimer.restart()
        }
        // A WebXDC app wants to send something into the chat: ask first (nothing is sent until
        // the user confirms). Shown in the main window, which the app can't draw over.
        function onWebxdcSendRequest(peer, fileName, fileSize, text) {
            webxdcSendDialog.ask(peer, fileName, fileSize, text)
        }
        // Passive feedback from the core (key verification, OMEMO resets, …).
        function onToast(text) {
            window.toastText = text
            toastTimer.restart()
        }
        // A downloaded file finished saving → open it with the system handler, but only plain
        // documents/media (`open`): the sender picks the file type, and opening e.g. a
        // .desktop/.jar/.exe file can run code. Everything else is just saved.
        function onFileSaved(path, open) {
            window.toastText = qsTr("Saved to ") + path
            toastTimer.restart()
            if (open)
                Qt.openUrlExternally("file://" + path)
        }
        // OMEMO2 device keys arrived → refresh whichever keys dialog is showing them.
        function onKeysChanged(jid) {
            if (jid === "__own__")
                ownDevices.reload()
            else if (jid === window.currentPeerJid)
                contactDevices.reload()
        }
        function onCallsChanged() {
            if (window.accountJid.length > 0)
                callLogModel.reload(window.accountJid)
        }
        function onStoriesChanged() {
            if (window.accountJid.length > 0)
                storyModel.reload(window.accountJid)
            if (storyViewer.opened)
                viewerStories.reloadSelf()
        }
        function onFeedsChanged() {
            window.refreshFollowed()
            if (window.accountJid.length > 0)
                feedModel.reload(window.accountJid)
            if (postDetailDialog.visible && window.feedPostId.length > 0)
                window.refreshOpenPost()
            if (postDetailDialog.visible && window.feedPostId.length > 0)
                commentModel.loadComments(window.feedPostAuthor, window.feedPostId)
        }
    }

    function openConversation(convId, name, jid, encrypted, avatar, presence, kind) {
        window.clearReply()
        window.clearEdit()
        window.currentPeerName = name
        window.currentPeerJid = jid
        window.currentPeerEncrypted = encrypted
        window.currentPeerAvatar = avatar
        window.currentPeerPresence = presence
        window.currentPeerIsMuc = (kind === "muc")
        window.currentRoomOmemoCapable = (kind === "muc") ? backend.mucOmemoCapable(jid) : true
        msgModel.open(convId)
    }

    // Open a conversation from a search hit and scroll to the matched message. Loads enough
    // history to include it (openAround), then the messageList's jumpReady handler centres +
    // flashes the row.
    function openConversationAtMessage(convId, name, jid, encrypted, kind, messageId, marker) {
        window.clearReply()
        window.clearEdit()
        window.currentPeerName = name
        window.currentPeerJid = jid
        window.currentPeerEncrypted = encrypted
        window.currentPeerAvatar = ""
        window.currentPeerPresence = ""
        window.currentPeerIsMuc = (kind === "muc")
        window.currentRoomOmemoCapable = (kind === "muc") ? backend.mucOmemoCapable(jid) : true
        // Set after the peer assignment above (which clears it) so the count-reset during
        // load doesn't snap to the bottom; jumpReady then scrolls to the message.
        messageList.pendingJumpMarker = marker
        msgModel.openAround(convId, messageId, marker)
    }

    function openContact(jid, name, avatar, presence) {
        window.clearReply()
        window.clearEdit()
        window.currentPeerName = name
        window.currentPeerJid = jid
        window.currentPeerEncrypted = true   // new 1:1 chats default to OMEMO2
        window.currentPeerAvatar = avatar
        window.currentPeerPresence = presence
        window.currentPeerIsMuc = false
        window.currentRoomOmemoCapable = true
        msgModel.openPeer(jid)
    }

    // Open a group chat (MUC) by room JID — used by the default support-room entry.
    function openMuc(room, name) {
        window.clearReply()
        window.clearEdit()
        window.currentPeerName = name
        window.currentPeerJid = room
        window.currentPeerEncrypted = false
        window.currentPeerAvatar = ""
        window.currentPeerPresence = ""
        window.currentPeerIsMuc = true
        window.currentRoomOmemoCapable = backend.mucOmemoCapable(room)
        msgModel.openPeerKind(room, "muc")
    }

    function openMucPm(occupantJid, nick) {
        window.clearReply()
        window.clearEdit()
        window.currentPeerName = nick
        window.currentPeerJid = occupantJid
        window.currentPeerEncrypted = false
        window.currentPeerAvatar = ""
        window.currentPeerPresence = ""
        window.currentPeerIsMuc = false
        window.currentRoomOmemoCapable = true
        msgModel.openPeerKind(occupantJid, "muc_pm")
    }

    // --- Login page ---------------------------------------------------------------
    Item {
        id: loginPage
        anchors.fill: parent
        visible: !window.signedIn

        ColumnLayout {
                anchors.centerIn: parent
                width: Math.min(parent.width - 64, 360)
                spacing: 18

                // Brand wordmark lockup (same asset as the GTK client / Android main_logo).
                Image {
                    source: window.iconBase + "monocles-wordmark.svg"
                    fillMode: Image.PreserveAspectFit
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredWidth: 300
                    Layout.preferredHeight: 130
                    sourceSize.width: 600
                    sourceSize.height: 260
                }
                Label {
                    textFormat: Text.PlainText
                    text: qsTr("Sign in to your XMPP account")
                    opacity: 0.7
                    Layout.alignment: Qt.AlignHCenter
                    Layout.bottomMargin: 8
                }

                TextField {
                    id: jidField
                    placeholderText: qsTr("you@monocles.eu")
                    inputMethodHints: Qt.ImhEmailCharactersOnly | Qt.ImhNoAutoUppercase
                    Layout.fillWidth: true
                }
                TextField {
                    id: passwordField
                    placeholderText: qsTr("Password")
                    echoMode: TextInput.Password
                    Layout.fillWidth: true
                    onAccepted: connectButton.clicked()
                }
                Button {
                    id: connectButton
                    text: qsTr("Connect")
                    highlighted: true
                    enabled: jidField.text.length > 0
                    Layout.fillWidth: true
                    onClicked: {
                        window.accountJid = jidField.text
                        backend.login(jidField.text, passwordField.text)
                        convModel.reload(jidField.text)
                        rosterModel.reload(jidField.text)
                        window.signedIn = true
                    }
                }
            }
    }

    // --- Main shell: [nav rail | sidebar] | chat pane ------------------------------
    Item {
        id: shell
        anchors.fill: parent
        visible: window.signedIn
        // 0 chats · 1 contacts · 2 calls · 3 stories · 4 feeds
        property int sectionIndex: 0
        // Opening a section clears its "new items" badge (the chats badge instead follows
        // the per-conversation unread counters, zeroed by the read markers on open).
        onSectionIndexChanged: {
            if (sectionIndex === 2)
                callLogModel.markSeen()
            else if (sectionIndex === 3)
                storyModel.markSeen()
            else if (sectionIndex === 4)
                feedModel.markSeen()
        }
        // Items arriving WHILE the section is open are seen immediately.
        Connections {
            target: callLogModel
            function onUnseenCountChanged() {
                if (shell.sectionIndex === 2 && callLogModel.unseenCount > 0)
                    callLogModel.markSeen()
            }
        }
        Connections {
            target: storyModel
            function onUnseenCountChanged() {
                if (shell.sectionIndex === 3 && storyModel.unseenCount > 0)
                    storyModel.markSeen()
            }
        }
        Connections {
            target: feedModel
            function onUnseenCountChanged() {
                if (shell.sectionIndex === 4 && feedModel.unseenCount > 0)
                    feedModel.markSeen()
            }
        }

        RowLayout {
                anchors.fill: parent
                spacing: 0

                // Navigation rail.
                Rectangle {
                    Layout.fillHeight: true
                    Layout.preferredWidth: 56
                    color: Qt.darker(Material.background, 1.12)

                    ColumnLayout {
                        anchors.top: parent.top
                        anchors.horizontalCenter: parent.horizontalCenter
                        anchors.topMargin: 8
                        spacing: 4

                        ToolButton {
                            id: navChats
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("Chats")
                            ToolTip.visible: hovered
                            onClicked: shell.sectionIndex = 0
                            readonly property bool sel: shell.sectionIndex === 0 || shell.sectionIndex === 1
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + (navChats.sel ? "nav-chats-symbolic.svg" : "nav-chats-outline-symbolic.svg")
                                color: navChats.sel ? Material.accent : Material.foreground
                            }
                            NavBadge {
                                count: convModel.unreadTotal
                                anchors.top: parent.top
                                anchors.right: parent.right
                                anchors.margins: 2
                            }
                        }
                        ToolButton {
                            id: navCalls
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("Calls")
                            ToolTip.visible: hovered
                            onClicked: {
                                shell.sectionIndex = 2
                                if (window.accountJid.length > 0)
                                    callLogModel.reload(window.accountJid)
                            }
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + (shell.sectionIndex === 2 ? "nav-calls-symbolic.svg" : "nav-calls-outline-symbolic.svg")
                                color: shell.sectionIndex === 2 ? Material.accent : Material.foreground
                            }
                            NavBadge {
                                count: callLogModel.unseenCount
                                anchors.top: parent.top
                                anchors.right: parent.right
                                anchors.margins: 2
                            }
                        }
                        ToolButton {
                            id: navStories
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("Stories")
                            ToolTip.visible: hovered
                            onClicked: {
                                shell.sectionIndex = 3
                                if (window.accountJid.length > 0) {
                                    storyModel.reload(window.accountJid)
                                    backend.fetchStories()
                                }
                            }
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + (shell.sectionIndex === 3 ? "nav-stories-symbolic.svg" : "nav-stories-outline-symbolic.svg")
                                color: shell.sectionIndex === 3 ? Material.accent : Material.foreground
                            }
                            NavBadge {
                                count: storyModel.unseenCount
                                anchors.top: parent.top
                                anchors.right: parent.right
                                anchors.margins: 2
                            }
                        }
                        ToolButton {
                            id: navFeeds
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("Feeds")
                            ToolTip.visible: hovered
                            onClicked: {
                                shell.sectionIndex = 4
                                if (window.accountJid.length > 0) {
                                    feedModel.reload(window.accountJid)
                                    backend.fetchFeeds()
                                }
                            }
                            NavBadge {
                                count: feedModel.unseenCount
                                anchors.top: parent.top
                                anchors.right: parent.right
                                anchors.margins: 2
                            }
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + (shell.sectionIndex === 4 ? "nav-feeds-symbolic.svg" : "nav-feeds-outline-symbolic.svg")
                                color: shell.sectionIndex === 4 ? Material.accent : Material.foreground
                            }
                        }
                    }

                    // Account actions pinned to the rail's bottom: profile + about + log out.
                    ColumnLayout {
                        anchors.bottom: parent.bottom
                        anchors.horizontalCenter: parent.horizontalCenter
                        anchors.bottomMargin: 8
                        spacing: 4

                        // My profile: status + encryption keys + blind-trust setting.
                        ToolButton {
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("My profile")
                            ToolTip.visible: hovered
                            onClicked: {
                                ownDevices.loadOwn()
                                ownKeysDialog.open()
                            }
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + "account-circle.svg"
                                color: Material.foreground
                            }
                        }
                        // About: version, copyright, links and license attributions.
                        ToolButton {
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("About monocles chat")
                            ToolTip.visible: hovered
                            onClicked: aboutDialog.open()
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + "info.svg"
                                color: Material.foreground
                            }
                        }
                        // Settings (more options coming soon).
                        ToolButton {
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("Settings")
                            ToolTip.visible: hovered
                            onClicked: settingsDialog.open()
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + "settings.svg"
                                color: Material.foreground
                            }
                        }
                        // Log out (clears the saved password + returns to the login page).
                        ToolButton {
                            Layout.alignment: Qt.AlignHCenter
                            ToolTip.text: qsTr("Log out")
                            ToolTip.visible: hovered
                            onClicked: logoutDialog.open()
                            contentItem: ColorIcon {
                                implicitWidth: 18
                                implicitHeight: 18
                                source: window.iconBase + "logout.svg"
                                color: Material.foreground
                            }
                        }
                    }
                }

                // Sidebar (fixed width, like the GTK Paned start child).
                ColumnLayout {
                    Layout.fillHeight: true
                    Layout.preferredWidth: 320
                    Layout.maximumWidth: 320
                    spacing: 0

                    Pane {
                        Layout.fillWidth: true
                        Layout.preferredHeight: window.headerHeight
                        Material.background: Material.primary
                        padding: 6
                        contentItem: RowLayout {
                            spacing: 4
                            ToolButton {
                                implicitWidth: 32
                                implicitHeight: 32
                                text: shell.sectionIndex === 1 ? "←" : "✎"
                                Material.foreground: "white"
                                onClicked: shell.sectionIndex = (shell.sectionIndex === 1 ? 0 : 1)
                            }
                            Label {
                                textFormat: Text.PlainText
                                Layout.fillWidth: true
                                color: "white"
                                font.bold: true
                                elide: Text.ElideRight
                                text: shell.sectionIndex === 1 ? qsTr("Contacts")
                                    : shell.sectionIndex === 2 ? qsTr("Calls")
                                    : shell.sectionIndex === 3 ? qsTr("Stories")
                                    : shell.sectionIndex === 4 ? qsTr("Feeds")
                                    : (backend.connected ? qsTr("Chats") : backend.status)
                            }
                            BusyIndicator {
                                running: !backend.connected
                                visible: !backend.connected
                                implicitWidth: 22
                                implicitHeight: 22
                            }
                            // Note to self: open (creating if needed) the 1:1 chat with our own
                            // account. Shown on the Chats / Contacts sections only.
                            ToolButton {
                                implicitWidth: 32
                                implicitHeight: 32
                                visible: (shell.sectionIndex === 0 || shell.sectionIndex === 1)
                                    && backend.accountJid.length > 0
                                ToolTip.text: qsTr("Note to self")
                                ToolTip.visible: hovered
                                onClicked: window.openContact(
                                    backend.accountJid, qsTr("Note to self"), "", "")
                                contentItem: ColorIcon {
                                    implicitWidth: 18
                                    implicitHeight: 18
                                    source: window.iconBase + "bookmark.svg"
                                    color: "white"
                                }
                            }
                        }
                    }

                    StackLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        currentIndex: shell.sectionIndex

                        // 0 — Chats (+ the donation banner pinned below, shown unless snoozed).
                        ColumnLayout {
                            spacing: 0

                            // Message search. Typing shows hits in searchResultsList (which
                            // replaces the chat list); clicking a hit opens that chat and jumps to
                            // the message. The conversation header's loupe scopes the search to one
                            // chat — shown as a leading avatar chip (Signal-style). Same pill as the
                            // composer.
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.margins: 6
                                implicitHeight: 34
                                radius: height / 2
                                color: Material.theme === Material.Dark ? Qt.rgba(1, 1, 1, 0.07)
                                                                        : Qt.rgba(0, 0, 0, 0.06)
                                TapHandler { onTapped: chatSearchField.forceActiveFocus() }
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 6
                                    anchors.rightMargin: 10
                                    spacing: 6

                                    // Scope chip — present only while searching within one chat.
                                    Rectangle {
                                        visible: window.searchScopeJid.length > 0
                                        Layout.preferredHeight: 26
                                        Layout.maximumWidth: 130
                                        implicitWidth: scopeChipRow.implicitWidth + 10
                                        radius: 13
                                        color: Material.theme === Material.Dark ? Qt.rgba(1, 1, 1, 0.12)
                                                                                : Qt.rgba(0, 0, 0, 0.10)
                                        RowLayout {
                                            id: scopeChipRow
                                            anchors.centerIn: parent
                                            spacing: 4
                                            Avatar {
                                                implicitWidth: 20
                                                implicitHeight: 20
                                                name: window.searchScopeName
                                                avatarPath: window.searchScopeAvatar
                                                presence: ""
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                text: window.searchScopeName
                                                font.pixelSize: 12
                                                elide: Text.ElideRight
                                                Layout.maximumWidth: 72
                                            }
                                            // ✕ removes the scope → search spans all chats again.
                                            ToolButton {
                                                implicitWidth: 20
                                                implicitHeight: 20
                                                padding: 0
                                                text: "✕"
                                                font.pixelSize: 11
                                                ToolTip.text: qsTr("Search all chats")
                                                ToolTip.visible: hovered
                                                onClicked: window.clearSearchScope()
                                            }
                                        }
                                    }

                                    TextField {
                                        id: chatSearchField
                                        Layout.fillWidth: true
                                        verticalAlignment: TextInput.AlignVCenter
                                        background: null
                                        placeholderText: window.searchScopeJid.length > 0
                                            ? qsTr("Search in %1…").arg(window.searchScopeName)
                                            : qsTr("Search messages…")
                                        onTextChanged: window.runMessageSearch()
                                    }
                                }
                            }

                        // Active whenever there's a query or a scope chip — drives which list shows.
                        property bool searchActive: chatSearchField.text.length > 0
                                                    || window.searchScopeJid.length > 0

                        ListView {
                            FastScroll {}
                            id: convList
                            visible: !parent.searchActive
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            model: convModel
                            ScrollBar.vertical: ThinScrollBar {}
                            delegate: ItemDelegate {
                                width: ListView.view.width
                                highlighted: model.jid === window.currentPeerJid
                                onClicked: window.openConversation(model.convId, model.name, model.jid, model.encrypted, model.avatarPath, model.presence, model.kind)
                                // Right-click → remove from list / leave group.
                                MouseArea {
                                    anchors.fill: parent
                                    acceptedButtons: Qt.RightButton
                                    onClicked: convMenu.popup()
                                }
                                Menu {
                                    id: convMenu
                                    MenuItem {
                                        text: model.kind === "muc" ? qsTr("Leave group") : qsTr("Remove from list")
                                        onTriggered: {
                                            if (model.kind === "muc")
                                                backend.leaveMuc(model.jid)
                                            else
                                                backend.deleteChat(model.jid)
                                            if (model.jid === window.currentPeerJid)
                                                window.currentPeerJid = ""
                                        }
                                    }
                                }
                                contentItem: RowLayout {
                                    spacing: 8
                                    Avatar {
                                        implicitWidth: 40
                                        implicitHeight: 40
                                        name: model.name
                                        avatarPath: model.avatarPath
                                        presence: model.presence
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 0
                                        Label {
                                            textFormat: Text.PlainText
                                            text: model.name
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                        // Kind caption — distinguishes groups + private group msgs from 1:1.
                                        Label {
                                            textFormat: Text.PlainText
                                            visible: model.kind !== "chat"
                                            text: model.kind === "muc" ? qsTr("Group")
                                                : model.kind === "muc_pm" ? qsTr("Private · ") + model.jid.split('/')[0].split('@')[0]
                                                : ""
                                            color: model.kind === "muc_pm" ? "#7188C3" : Material.foreground
                                            opacity: model.kind === "muc_pm" ? 1.0 : 0.55
                                            font.pixelSize: 11
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }
                                    Label {
                                        textFormat: Text.PlainText
                                        visible: model.encrypted
                                        text: "🔒"
                                        opacity: 0.7
                                    }
                                    Rectangle {
                                        visible: model.unread > 0
                                        radius: height / 2
                                        color: Material.accent
                                        implicitHeight: 22
                                        implicitWidth: Math.max(22, unreadLabel.implicitWidth + 12)
                                        Label {
                                            id: unreadLabel
                                            textFormat: Text.PlainText
                                            anchors.centerIn: parent
                                            text: model.unread
                                            color: "white"
                                            font.pixelSize: 12
                                        }
                                    }
                                }
                            }
                            Label {
                                textFormat: Text.PlainText
                                anchors.centerIn: parent
                                visible: convList.count === 0
                                text: qsTr("No conversations yet")
                                opacity: 0.6
                            }
                        }

                        // Message-search results — replaces the chat list while searching.
                        ListView {
                            FastScroll {}
                            id: searchResultsList
                            visible: parent.searchActive
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            model: msgSearchModel
                            ScrollBar.vertical: ThinScrollBar {}
                            delegate: ItemDelegate {
                                width: ListView.view.width
                                onClicked: window.openConversationAtMessage(
                                    model.convId, model.name, model.jid, model.encrypted,
                                    model.kind, model.messageId, model.marker)
                                contentItem: RowLayout {
                                    spacing: 8
                                    Avatar {
                                        implicitWidth: 40
                                        implicitHeight: 40
                                        name: model.name
                                        avatarPath: model.avatarPath
                                        presence: ""
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 0
                                        RowLayout {
                                            Layout.fillWidth: true
                                            spacing: 6
                                            Label {
                                                textFormat: Text.PlainText
                                                text: model.name
                                                font.bold: true
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                text: window.msgTime(model.timestamp)
                                                opacity: 0.55
                                                font.pixelSize: 11
                                            }
                                        }
                                        Label {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            // "You:" / sender prefix, like the chat-list previews.
                                            text: (model.outgoing ? qsTr("You: ")
                                                   : (model.kind === "muc" && model.sender.length > 0
                                                      ? model.sender + ": " : ""))
                                                  + model.snippet
                                            elide: Text.ElideRight
                                            maximumLineCount: 1
                                            opacity: 0.7
                                            font.pixelSize: 12
                                        }
                                    }
                                }
                            }
                            Label {
                                textFormat: Text.PlainText
                                anchors.centerIn: parent
                                width: parent.width - 32
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.Wrap
                                visible: searchResultsList.count === 0
                                // Prompt to type when a scope is set but nothing's been entered yet.
                                text: chatSearchField.text.length === 0 && window.searchScopeJid.length > 0
                                      ? qsTr("Type to search in %1").arg(window.searchScopeName)
                                      : qsTr("No messages found")
                                opacity: 0.6
                            }
                        }

                        // Donation banner — "Not now" snoozes it for a week (shared store key,
                        // so the GTK client's snooze is honoured too).
                        Pane {
                            visible: backend.donationDue && !parent.searchActive
                            Layout.fillWidth: true
                            // Derive from the WINDOW's background (self-reference would loop
                            // and fall back to the style's light default — wrong in dark mode).
                            Material.background: Qt.darker(window.Material.background, 1.18)
                            padding: 10
                            contentItem: ColumnLayout {
                                spacing: 4
                                Label {
                                    textFormat: Text.PlainText
                                    text: qsTr("Support monocles ♥")
                                    font.bold: true
                                }
                                Label {
                                    textFormat: Text.PlainText
                                    text: qsTr("monocles is free and open source. A small donation helps keep the project alive.")
                                    wrapMode: Text.Wrap
                                    opacity: 0.7
                                    font.pixelSize: 12
                                    Layout.fillWidth: true
                                }
                                RowLayout {
                                    Layout.alignment: Qt.AlignRight
                                    spacing: 6
                                    Button {
                                        text: qsTr("Not now")
                                        flat: true
                                        onClicked: backend.snoozeDonation()
                                    }
                                    Button {
                                        text: qsTr("Donate")
                                        highlighted: true
                                        onClicked: Qt.openUrlExternally("https://liberapay.com/monocles/donate")
                                    }
                                }
                            }
                        }
                        }

                        // 1 — Contacts (new chat) + add-contact / join-room actions.
                        ColumnLayout {
                            spacing: 0
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.margins: 6
                                spacing: 6
                                Button {
                                    Layout.fillWidth: true
                                    text: qsTr("Add contact…")
                                    onClicked: addContactDialog.open()
                                }
                                Button {
                                    Layout.fillWidth: true
                                    text: qsTr("Join group chat…")
                                    onClicked: joinDialog.open()
                                }
                            }
                            // Live substring search over the roster (name + JID), filtered
                            // in the Rust model so the scroll position survives a refresh.
                            // Rounded input pill matching the chat composer's style.
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 6
                                Layout.rightMargin: 6
                                Layout.bottomMargin: 6
                                implicitHeight: 34
                                radius: height / 2
                                color: Material.theme === Material.Dark ? Qt.rgba(1, 1, 1, 0.07)
                                                                        : Qt.rgba(0, 0, 0, 0.06)

                                // Clicking anywhere on the pill focuses the field.
                                TapHandler { onTapped: contactSearchField.forceActiveFocus() }

                                TextField {
                                    id: contactSearchField
                                    anchors.fill: parent
                                    leftPadding: 14
                                    rightPadding: 14
                                    verticalAlignment: TextInput.AlignVCenter
                                    background: null
                                    placeholderText: qsTr("Search contacts…")
                                    onTextChanged: rosterModel.setFilter(text)
                                }
                            }

                            // Default monocles support room — a pinned group at the top of the
                            // Contacts list. Click joins + opens it; right-click → Remove hides it
                            // for good (per-account flag in the store). Hidden while searching.
                            ItemDelegate {
                                id: supportRoomEntry
                                readonly property string room: "support@conference.monocles.eu"
                                readonly property string displayName: qsTr("monocles Support")
                                visible: backend.supportRoomVisible && contactSearchField.text.length === 0
                                Layout.fillWidth: true
                                onClicked: {
                                    var nick = window.accountJid.indexOf("@") > 0
                                        ? window.accountJid.split("@")[0] : "user"
                                    backend.joinMuc(room, nick)
                                    window.openMuc(room, displayName)
                                    shell.sectionIndex = 0
                                }
                                MouseArea {
                                    anchors.fill: parent
                                    acceptedButtons: Qt.RightButton
                                    onClicked: supportRoomMenu.popup()
                                }
                                Menu {
                                    id: supportRoomMenu
                                    MenuItem {
                                        text: qsTr("Remove")
                                        onTriggered: backend.dismissSupportRoom()
                                    }
                                }
                                contentItem: RowLayout {
                                    spacing: 8
                                    Avatar {
                                        implicitWidth: 40
                                        implicitHeight: 40
                                        name: supportRoomEntry.displayName
                                        avatarPath: ""
                                        presence: ""
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 0
                                        Label {
                                            textFormat: Text.PlainText
                                            text: supportRoomEntry.displayName
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                        Label {
                                            textFormat: Text.PlainText
                                            text: qsTr("Support group · tap to join")
                                            color: "#7188C3"
                                            font.pixelSize: 11
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }
                                }
                            }
                            // Divider separating the pinned room from the roster.
                            Rectangle {
                                visible: supportRoomEntry.visible
                                Layout.fillWidth: true
                                Layout.leftMargin: 8
                                Layout.rightMargin: 8
                                Layout.bottomMargin: 2
                                implicitHeight: 1
                                color: Qt.rgba(0.5, 0.5, 0.5, 0.18)
                            }

                            ListView {
                                FastScroll {}
                                id: rosterList
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                model: rosterModel
                                ScrollBar.vertical: ThinScrollBar {}
                            delegate: ItemDelegate {
                                width: ListView.view.width
                                onClicked: {
                                    window.openContact(model.jid, model.name, model.avatarPath, model.presence)
                                    shell.sectionIndex = 0
                                }
                                // Right-click → remove contact from the roster.
                                MouseArea {
                                    anchors.fill: parent
                                    acceptedButtons: Qt.RightButton
                                    onClicked: rosterMenu.popup()
                                }
                                Menu {
                                    id: rosterMenu
                                    MenuItem {
                                        text: qsTr("Remove contact…")
                                        onTriggered: {
                                            removeContactDialog.jid = model.jid
                                            removeContactDialog.name = model.name
                                            removeContactDialog.open()
                                        }
                                    }
                                }
                                contentItem: RowLayout {
                                    spacing: 8
                                    Avatar {
                                        implicitWidth: 40
                                        implicitHeight: 40
                                        name: model.name
                                        avatarPath: model.avatarPath
                                        presence: model.presence
                                    }
                                    Label {
                                        textFormat: Text.PlainText
                                        text: model.name
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                }
                            }
                            Label {
                                textFormat: Text.PlainText
                                anchors.centerIn: parent
                                visible: rosterList.count === 0
                                text: contactSearchField.text.length > 0 ? qsTr("No matching contacts")
                                                                         : qsTr("No contacts")
                                opacity: 0.6
                            }
                            }
                        }

                        // 2 — Calls (history) with call-again actions.
                        ListView {
                            FastScroll {}
                            id: callsList
                            clip: true
                            model: callLogModel
                            ScrollBar.vertical: ThinScrollBar {}
                            delegate: ItemDelegate {
                                width: ListView.view.width
                                // The log records every ending; `answered` = media connected.
                                // in+unanswered = missed/declined; out+unanswered = the peer
                                // rejected, we cancelled, or the call failed before connecting.
                                readonly property bool missed: model.direction === "in" && !model.answered
                                readonly property bool unanswered: !model.answered
                                onClicked: window.openContact(model.peer, model.peer.split('@')[0], "", "")
                                contentItem: RowLayout {
                                    spacing: 8
                                    ColorIcon {
                                        implicitWidth: 18
                                        implicitHeight: 18
                                        Layout.alignment: Qt.AlignVCenter
                                        source: window.iconBase + (model.direction === "out" ? "call-made.svg"
                                                                 : (missed ? "call-missed.svg" : "call-received.svg"))
                                        color: unanswered ? "#e53935"
                                             : (model.direction === "out" ? Material.accent : "#43a047")
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 0
                                        Label {
                                            textFormat: Text.PlainText
                                            text: model.peer.split('@')[0]
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                            color: missed ? "#e53935" : Material.foreground
                                        }
                                        Label {
                                            textFormat: Text.PlainText
                                            text: (model.video ? qsTr("Video") : qsTr("Audio"))
                                                  + (missed ? " · " + qsTr("Missed")
                                                            : (unanswered ? " · " + qsTr("Not answered") : ""))
                                                  + " · " + model.timestamp.replace("T", " ").substring(0, 16)
                                            opacity: 0.6
                                            font.pixelSize: 11
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }
                                    ToolButton {
                                        enabled: backend.connected && !backend.callActive
                                        ToolTip.text: qsTr("Call back (audio)")
                                        ToolTip.visible: hovered
                                        onClicked: backend.placeCall(model.peer, false)
                                        contentItem: ColorIcon {
                                            implicitWidth: 16; implicitHeight: 16
                                            source: window.iconBase + "call.svg"; color: Material.foreground
                                        }
                                    }
                                    ToolButton {
                                        enabled: backend.connected && !backend.callActive
                                        ToolTip.text: qsTr("Call back (video)")
                                        ToolTip.visible: hovered
                                        onClicked: backend.placeCall(model.peer, true)
                                        contentItem: ColorIcon {
                                            implicitWidth: 16; implicitHeight: 16
                                            source: window.iconBase + "videocam.svg"; color: Material.foreground
                                        }
                                    }
                                }
                            }
                            Label {
                                textFormat: Text.PlainText
                                anchors.centerIn: parent
                                visible: callsList.count === 0
                                text: qsTr("No calls yet")
                                opacity: 0.6
                            }
                        }

                        // 3 — Stories (social feed): post + the list of non-expired stories.
                        ColumnLayout {
                            spacing: 0
                            Button {
                                Layout.fillWidth: true
                                Layout.margins: 6
                                text: qsTr("Post a story…")
                                enabled: backend.connected
                                onClicked: storyFileDialog.open()
                            }
                            PublishingNote { Layout.leftMargin: 8 }
                            ListView {
                                FastScroll {}
                                id: storiesList
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                model: storyModel
                                ScrollBar.vertical: ThinScrollBar {}
                                delegate: ItemDelegate {
                                    width: ListView.view.width
                                    onClicked: window.openStoryViewer(model.contact, model.uuid)
                                    contentItem: RowLayout {
                                        spacing: 8
                                        Avatar {
                                            implicitWidth: 40
                                            implicitHeight: 40
                                            name: model.own ? qsTr("Me") : model.contact.split('@')[0]
                                            avatarPath: model.avatarPath
                                            presence: ""
                                        }
                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 0
                                            Label {
                                                textFormat: Text.PlainText
                                                text: model.own ? qsTr("My story") : model.contact.split('@')[0]
                                                font.bold: true
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                text: (model.mime.indexOf("video") === 0 ? "🎬 " : "📷 ")
                                                      + (model.title.length > 0 ? model.title + " · " : "")
                                                      + window.agoText(model.published)
                                                opacity: 0.6
                                                font.pixelSize: 11
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                            }
                                        }
                                        ToolButton {
                                            visible: model.own
                                            text: "✕"
                                            ToolTip.text: qsTr("Delete story")
                                            ToolTip.visible: hovered
                                            onClicked: { storyDeleteDialog.uuid = model.uuid; storyDeleteDialog.open() }
                                        }
                                    }
                                }
                                Label {
                                    textFormat: Text.PlainText
                                    anchors.centerIn: parent
                                    visible: storiesList.count === 0
                                    text: qsTr("No stories")
                                    opacity: 0.6
                                }
                            }
                        }

                        // 4 — Feeds (XEP-0472 social feed): posts from our own + followed feeds.
                        ColumnLayout {
                            spacing: 0
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.margins: 6
                                spacing: 6
                                Button {
                                    Layout.fillWidth: true
                                    text: qsTr("New post")
                                    enabled: backend.connected
                                    onClicked: window.openComposer(null)
                                }
                                Button {
                                    text: qsTr("Follow…")
                                    enabled: backend.connected
                                    onClicked: { followJidField.text = ""; followDialog.open() }
                                }
                            }
                            PublishingNote { Layout.leftMargin: 8 }

                            // Followed feeds (unfollow) and suggestions (Android: contacts sharing presence both
                            // ways whose feed isn't followed yet), each collapsible.
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.leftMargin: 6
                                Layout.rightMargin: 6
                                spacing: 6
                                Button {
                                    flat: true
                                    visible: window.followedList.length > 0
                                    text: (window.feedPanel === "following" ? "▾ " : "▸ ") + qsTr("Following (%1)").arg(window.followedList.length)
                                    onClicked: window.feedPanel = window.feedPanel === "following" ? "" : "following"
                                }
                                Button {
                                    flat: true
                                    visible: window.suggestionList.length > 0
                                    text: (window.feedPanel === "suggestions" ? "▾ " : "▸ ") + qsTr("Suggestions (%1)").arg(window.suggestionList.length)
                                    onClicked: window.feedPanel = window.feedPanel === "suggestions" ? "" : "suggestions"
                                }
                                Item { Layout.fillWidth: true }
                            }
                            ListView {
                                Layout.fillWidth: true
                                Layout.preferredHeight: Math.min(contentHeight, 200)
                                visible: window.feedPanel !== "" && count > 0
                                clip: true
                                model: window.feedPanel === "following" ? window.followedList
                                     : window.feedPanel === "suggestions" ? window.suggestionList : []
                                ScrollBar.vertical: ThinScrollBar {}
                                delegate: ItemDelegate {
                                    width: ListView.view.width
                                    contentItem: RowLayout {
                                        spacing: 8
                                        Avatar {
                                            implicitWidth: 28
                                            implicitHeight: 28
                                            name: modelData.split('@')[0]
                                            avatarPath: ""
                                            presence: ""
                                        }
                                        Label {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            text: modelData
                                            elide: Text.ElideRight
                                        }
                                        Button {
                                            text: window.feedPanel === "following" ? qsTr("Unfollow") : qsTr("Follow")
                                            enabled: backend.connected || window.feedPanel === "following"
                                            onClicked: {
                                                if (window.feedPanel === "following")
                                                    backend.unfollowFeed(modelData)
                                                else
                                                    backend.followFeed(modelData)
                                                window.refreshFollowed()
                                            }
                                        }
                                    }
                                }
                            }
                            ListView {
                                FastScroll {}
                                id: feedList
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                spacing: 2
                                model: feedModel
                                ScrollBar.vertical: ThinScrollBar {}
                                delegate: ItemDelegate {
                                    width: ListView.view.width
                                    onClicked: window.openPost(model)
                                    contentItem: RowLayout {
                                        spacing: 8
                                        Avatar {
                                            Layout.alignment: Qt.AlignTop
                                            implicitWidth: 40
                                            implicitHeight: 40
                                            name: model.own ? qsTr("Me") : model.author.split('@')[0]
                                            avatarPath: model.avatarPath
                                            presence: ""
                                        }
                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 2
                                            RowLayout {
                                                Layout.fillWidth: true
                                                Label {
                                                    textFormat: Text.PlainText
                                                    text: model.own ? qsTr("Me") : model.author.split('@')[0]
                                                    font.bold: true
                                                    elide: Text.ElideRight
                                                    Layout.fillWidth: true
                                                }
                                                Label {
                                                    textFormat: Text.PlainText
                                                    text: window.agoText(model.published)
                                                    opacity: 0.6
                                                    font.pixelSize: 10
                                                }
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                visible: model.title.length > 0
                                                text: model.title
                                                font.bold: true
                                                font.pixelSize: 13
                                                wrapMode: Text.Wrap
                                                Layout.fillWidth: true
                                            }
                                            // Markdown rendered in Rust to sanitized rich text
                                            // (no images or raw HTML, http(s)/xmpp links only).
                                            Label {
                                                visible: model.content.length > 0
                                                text: model.contentHtml
                                                textFormat: Text.RichText
                                                wrapMode: Text.Wrap
                                                maximumLineCount: 4
                                                clip: true
                                                Layout.fillWidth: true
                                                font.pixelSize: 12
                                                onLinkActivated: (url) => window.openSafeUrl(url)
                                            }
                                            // Image attachment (cached), else a note.
                                            Image {
                                                visible: model.attachmentPath.length > 0
                                                source: visible ? "file:" + model.attachmentPath : ""
                                                Layout.fillWidth: true
                                                Layout.maximumHeight: 220
                                                Layout.preferredHeight: visible && implicitWidth > 0
                                                    ? Math.min(220, width * implicitHeight / implicitWidth) : 0
                                                fillMode: Image.PreserveAspectFit
                                                horizontalAlignment: Image.AlignLeft
                                                asynchronous: true
                                                // Cached: the file is named by its URL's hash, so it never
                                                // changes under a path — and a re-created row then shows
                                                // the image at once instead of blanking while it reloads.
                                                cache: true
                                                // Decode at display size, not the full photo.
                                                sourceSize.width: 800
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                visible: model.attachmentUrl.length > 0 && model.attachmentPath.length === 0
                                                text: (model.attachmentType.indexOf("video") === 0 ? "🎬 " : "📎 ")
                                                      + decodeURIComponent(model.attachmentUrl.split('/').pop())
                                                elide: Text.ElideMiddle
                                                opacity: 0.7
                                                font.pixelSize: 11
                                                Layout.fillWidth: true
                                            }
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 12
                                                // Heart "like" (a "♥" comment, like the Android app).
                                                Label {
                                                    textFormat: Text.PlainText
                                                    visible: model.canComment
                                                    text: (model.liked ? "♥ " : "♡ ") + model.likeCount
                                                    color: model.liked ? "#e0245e" : Material.foreground
                                                    opacity: model.liked ? 1.0 : 0.6
                                                    font.pixelSize: 13
                                                    MouseArea {
                                                        anchors.fill: parent
                                                        cursorShape: Qt.PointingHandCursor
                                                        enabled: backend.connected
                                                        onClicked: backend.toggleLike(model.author, model.postId)
                                                    }
                                                }
                                                Label {
                                                    textFormat: Text.PlainText
                                                    visible: model.canComment
                                                    text: "💬 " + model.commentCount
                                                    opacity: 0.6
                                                    font.pixelSize: 12
                                                }
                                                Label {
                                                    textFormat: Text.PlainText
                                                    visible: model.link.length > 0
                                                    text: "🔗"
                                                    opacity: 0.6
                                                    font.pixelSize: 12
                                                }
                                            }
                                        }
                                        ColumnLayout {
                                            Layout.alignment: Qt.AlignTop
                                            visible: model.own
                                            spacing: 0
                                            ToolButton {
                                                text: "✎"
                                                enabled: backend.connected
                                                ToolTip.text: qsTr("Edit post")
                                                ToolTip.visible: hovered
                                                onClicked: window.openComposer(model)
                                            }
                                            ToolButton {
                                                text: "✕"
                                                enabled: backend.connected
                                                ToolTip.text: qsTr("Delete post")
                                                ToolTip.visible: hovered
                                                onClicked: { postDeleteDialog.postId = model.postId; postDeleteDialog.open() }
                                            }
                                        }
                                    }
                                }
                                Label {
                                    textFormat: Text.PlainText
                                    anchors.centerIn: parent
                                    width: parent.width - 24
                                    visible: feedList.count === 0
                                    horizontalAlignment: Text.AlignHCenter
                                    wrapMode: Text.Wrap
                                    text: qsTr("No posts yet. Use “Follow…” to add a feed, or “New post”.")
                                    opacity: 0.6
                                }
                            }
                        }
                    }
                }

                // Divider.
                Rectangle {
                    Layout.fillHeight: true
                    Layout.preferredWidth: 1
                    color: Qt.rgba(0.5, 0.5, 0.5, 0.25)
                }

                // Chat pane (fills remaining width).
                Item {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    // Placeholder when nothing is open.
                    Label {
                        textFormat: Text.PlainText
                        anchors.centerIn: parent
                        visible: window.currentPeerJid.length === 0
                        text: qsTr("Select a conversation")
                        opacity: 0.6
                    }

                    // Chat background, shown behind the open conversation (the header + composer
                    // paint over it; the transparent message list lets it show through). The
                    // bundled doodle tiles repeat; a custom photo crops to fill.
                    Image {
                        anchors.fill: parent
                        visible: window.currentPeerJid.length > 0 && window.chatBgSource.length > 0
                        source: window.chatBgSource
                        fillMode: window.chatBgTile ? Image.Tile : Image.PreserveAspectCrop
                        asynchronous: true
                        cache: true
                    }

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 0
                        visible: window.currentPeerJid.length > 0

                        Pane {
                            Layout.fillWidth: true
                            Layout.preferredHeight: window.headerHeight
                            Material.background: Material.primary
                            padding: 6
                            contentItem: RowLayout {
                                spacing: 10
                                Avatar {
                                    implicitWidth: 34
                                    implicitHeight: 34
                                    name: window.currentPeerName
                                    avatarPath: window.currentPeerAvatar
                                    presence: window.currentPeerPresence
                                    TapHandler { onTapped: window.openDetails() }
                                }
                                Label {
                                    textFormat: Text.PlainText
                                    text: window.currentPeerName
                                    color: "white"
                                    font.bold: true
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                    TapHandler { onTapped: window.openDetails() }
                                    ToolTip.text: qsTr("View details")
                                    ToolTip.visible: hovered
                                    HoverHandler { id: nameHover }
                                    property bool hovered: nameHover.hovered
                                }
                                // Search within this conversation — scopes the sidebar message
                                // search to this chat (shows an avatar chip; Signal-style).
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    ToolTip.text: qsTr("Search in conversation")
                                    ToolTip.visible: hovered
                                    onClicked: window.scopeSearchTo(window.currentPeerJid,
                                                                    window.currentPeerName,
                                                                    window.currentPeerAvatar)
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + "search.svg"
                                        color: "white"
                                    }
                                }

                                // PQ OMEMO2 encryption toggle. Disabled for MUCs that can't do it.
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    enabled: !window.currentPeerIsMuc || window.currentRoomOmemoCapable
                                    opacity: enabled ? 1.0 : 0.4
                                    ToolTip.text: window.currentPeerEncrypted ? qsTr("Encrypted (PQ OMEMO2) — click to disable")
                                        : (enabled ? qsTr("Not encrypted — click to enable PQ OMEMO2")
                                                   : qsTr("This room can't use PQ OMEMO2"))
                                    ToolTip.visible: hovered
                                    onClicked: {
                                        // Turning encryption OFF needs an explicit confirmation;
                                        // turning it on applies immediately.
                                        if (window.currentPeerEncrypted) {
                                            disableEncryptionDialog.open()
                                        } else {
                                            window.currentPeerEncrypted = true
                                            msgModel.setEncryption(true)
                                        }
                                    }
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + (window.currentPeerEncrypted ? "lock-omemo2.svg" : "lock-open.svg")
                                        color: "white"
                                    }
                                }

                                // Audio + video call buttons (1:1 only).
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    visible: !window.currentPeerIsMuc
                                    enabled: backend.connected && !backend.callActive
                                    opacity: enabled ? 1.0 : 0.4
                                    ToolTip.text: qsTr("Audio call")
                                    ToolTip.visible: hovered
                                    onClicked: backend.placeCall(window.currentPeerJid, false)
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + "call.svg"
                                        color: "white"
                                    }
                                }
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    visible: !window.currentPeerIsMuc
                                    enabled: backend.connected && !backend.callActive
                                    opacity: enabled ? 1.0 : 0.4
                                    ToolTip.text: qsTr("Video call")
                                    ToolTip.visible: hovered
                                    onClicked: backend.placeCall(window.currentPeerJid, true)
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + "videocam.svg"
                                        color: "white"
                                    }
                                }

                                // Group call button (private groups only — XEP-0272 Muji needs
                                // real JIDs, so it's gated to members-only + non-anonymous rooms).
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    visible: window.currentPeerIsMuc && window.currentRoomOmemoCapable
                                    enabled: backend.connected && !backend.callActive && !backend.conferenceActive
                                    opacity: enabled ? 1.0 : 0.4
                                    ToolTip.text: qsTr("Group call")
                                    ToolTip.visible: hovered
                                    onClicked: backend.placeGroupCall(window.currentPeerJid, false)
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + "call.svg"
                                        color: "white"
                                    }
                                }

                                // Group video call button (private groups only — XEP-0272 Muji).
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    visible: window.currentPeerIsMuc && window.currentRoomOmemoCapable
                                    enabled: backend.connected && !backend.callActive && !backend.conferenceActive
                                    opacity: enabled ? 1.0 : 0.4
                                    ToolTip.text: qsTr("Group video call")
                                    ToolTip.visible: hovered
                                    onClicked: backend.placeGroupCall(window.currentPeerJid, true)
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + "videocam.svg"
                                        color: "white"
                                    }
                                }

                                // Members button (MUC only) → occupants popup.
                                ToolButton {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    visible: window.currentPeerIsMuc
                                    onClicked: {
                                        occupantModel.load(window.currentPeerJid)
                                        occupantsPopup.open()
                                    }
                                    contentItem: ColorIcon {
                                        implicitWidth: 17
                                        implicitHeight: 17
                                        source: window.iconBase + "members.svg"
                                        color: "white"
                                    }

                                    Popup {
                                        id: occupantsPopup
                                        y: parent.height + 4
                                        x: parent.width - width
                                        width: 260
                                        height: Math.min(360, Math.max(48, occList.contentHeight + 12))
                                        padding: 6

                                        // Refresh occupants as presence changes while open.
                                        Connections {
                                            target: backend
                                            function onConversationsChanged() {
                                                if (occupantsPopup.opened)
                                                    occupantModel.load(window.currentPeerJid)
                                            }
                                        }

                                        ListView {
                                            FastScroll {}
                                            ScrollBar.vertical: ThinScrollBar {}
                                            id: occList
                                            anchors.fill: parent
                                            clip: true
                                            model: occupantModel
                                            delegate: ItemDelegate {
                                                width: ListView.view.width
                                                // Lazy avatar fetch: only rows that actually
                                                // appear ask the server (deduped) — fetching a
                                                // big room's whole list at once froze the app.
                                                Component.onCompleted: backend.fetchMucAvatar(model.jid)
                                                onClicked: {
                                                    backend.startPrivate(model.jid)
                                                    window.openMucPm(model.jid, model.nick)
                                                    occupantsPopup.close()
                                                }
                                                contentItem: RowLayout {
                                                    spacing: 8
                                                    Avatar {
                                                        implicitWidth: 30
                                                        implicitHeight: 30
                                                        name: model.nick
                                                        avatarPath: model.avatarPath
                                                        presence: model.presence
                                                    }
                                                    Label {
                                                        textFormat: Text.PlainText
                                                        text: model.nick
                                                        elide: Text.ElideRight
                                                        Layout.fillWidth: true
                                                    }
                                                }
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                anchors.centerIn: parent
                                                visible: occList.count === 0
                                                text: qsTr("No occupants")
                                                opacity: 0.6
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        ListView {
                            FastScroll { onScrolled: messageList.userScrolled() }
                            id: messageList
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            spacing: 2
                            model: msgModel
                            ScrollBar.vertical: ThinScrollBar {
                                id: msgScrollBar
                                onPressedChanged: if (!pressed) messageList.stickToEnd = messageList.nearEnd
                            }

                            // Keep the newest message in view while the user is at the bottom:
                            // new/sent messages and bubbles that grow while they lay out (images,
                            // estimated heights) would otherwise leave the view short of the end
                            // and it would visibly settle. Only the user's own scrolling (wheel /
                            // touchpad via FastScroll, drag, scroll bar) unsticks it; layout
                            // changes can only re-stick (reaching the end).
                            property bool stickToEnd: true
                            // Set while we position the view ourselves.
                            property bool positioning: false
                            // Within 2px of the end: with variable-height bubbles `atYEnd` can
                            // miss the end by a fraction.
                            readonly property bool nearEnd: contentY + height >= originY + contentHeight - 2
                            // The view is hidden while a freshly opened chat is first positioned,
                            // so it never shows the oldest messages before snapping to the end.
                            property bool settling: false
                            opacity: settling ? 0 : 1
                            function followEnd() {
                                if (stickToEnd && olderAnchor === -1 && pendingJumpMarker.length === 0 && count > 0) {
                                    positioning = true
                                    positionViewAtEnd()
                                    positioning = false
                                }
                            }
                            function userScrolled() {
                                stickToEnd = nearEnd
                                maybeLoadOlder()
                            }
                            // Deferred: a re-position from inside the view's own layout pass
                            // doesn't take, and the view settled short of the end.
                            function layoutChanged() {
                                if (!positioning && nearEnd)
                                    stickToEnd = true
                                Qt.callLater(followEnd)
                            }
                            onContentHeightChanged: layoutChanged()
                            onOriginYChanged: layoutChanged()
                            onHeightChanged: Qt.callLater(followEnd)
                            onMovementEnded: stickToEnd = nearEnd
                            // A freshly opened chat is shown once its messages have arrived and
                            // been positioned (see onModelReset below) - not after a fixed delay,
                            // which showed the previous chat and then redrew when loading took
                            // longer. The fallback covers an open that doesn't reset the model.
                            function finishSettling() {
                                followEnd()
                                settleTimer.restart()
                            }
                            Timer {
                                id: settleTimer
                                interval: 30
                                onTriggered: {
                                    // A search jump reveals the chat itself once it scrolled.
                                    if (messageList.pendingJumpMarker.length > 0)
                                        return
                                    messageList.followEnd()
                                    messageList.settling = false
                                    settleFallback.stop()
                                }
                            }
                            Timer {
                                id: settleFallback
                                interval: 1500
                                onTriggered: { messageList.followEnd(); messageList.settling = false }
                            }

                            // Date separators: group consecutive messages by local day.
                            section.property: "day"
                            section.criteria: ViewSection.FullString
                            section.delegate: Item {
                                width: messageList.width
                                height: 32
                                Rectangle {
                                    anchors.centerIn: parent
                                    radius: 11
                                    color: Qt.rgba(0.5, 0.5, 0.5, 0.22)
                                    implicitHeight: 22
                                    implicitWidth: daySepLabel.implicitWidth + 20
                                    Label {
                                        id: daySepLabel
                                        textFormat: Text.PlainText
                                        anchors.centerIn: parent
                                        text: window.dayLabel(section)
                                        font.pixelSize: 11
                                        opacity: 0.85
                                    }
                                }
                            }

                            // Jump-to-latest button — shown only while scrolled up.
                            RoundButton {
                                z: 3
                                anchors.right: parent.right
                                anchors.bottom: parent.bottom
                                anchors.rightMargin: 14
                                anchors.bottomMargin: 14
                                implicitWidth: 42
                                implicitHeight: 42
                                visible: messageList.count > 0 && !messageList.atYEnd
                                text: "↓"
                                font.pixelSize: 20
                                Material.background: Material.accent
                                Material.foreground: "white"
                                ToolTip.text: qsTr("Scroll to latest")
                                ToolTip.visible: hovered
                                onClicked: { messageList.stickToEnd = true; messageList.positionViewAtEnd() }
                            }

                            // Row index captured when a page-up is requested; lets us restore
                            // the viewport after older messages are prepended. -1 = idle.
                            property int olderAnchor: -1
                            // Set once a page-up returns no new rows (start of history reached).
                            property bool noMoreHistory: false
                            // Row briefly highlighted after jumping to a quoted message (-1 = none).
                            property int flashIndex: -1
                            // Marker to scroll to once a search-result openAround finishes (""=none).
                            property string pendingJumpMarker: ""

                            // Reset paging state when the open conversation changes.
                            Connections {
                                target: window
                                function onCurrentPeerJidChanged() {
                                    messageList.noMoreHistory = false
                                    messageList.olderAnchor = -1
                                    messageList.stickToEnd = true
                                    messageList.settling = true
                                    settleTimer.stop()
                                    settleFallback.restart()
                                    // A plain open cancels any in-flight search jump; the search
                                    // path re-sets this right after changing the peer.
                                    messageList.pendingJumpMarker = ""
                                }
                            }

                            // openAround (search jump) finished loading — scroll to the message.
                            // A short delay lets the freshly-reset delegates lay out so the
                            // centred position is accurate.
                            Connections {
                                target: msgModel
                                function onJumpReady(marker) {
                                    messageList.pendingJumpMarker = marker
                                    jumpTimer.restart()
                                }
                            }
                            Timer {
                                id: jumpTimer
                                interval: 70
                                onTriggered: {
                                    var idx = msgModel.indexOfMarker(messageList.pendingJumpMarker)
                                    if (idx >= 0) {
                                        messageList.stickToEnd = false
                                        messageList.positionViewAtIndex(idx, ListView.Center)
                                        messageList.flashIndex = idx
                                        flashClear.restart()
                                    } else {
                                        messageList.positionViewAtEnd()
                                    }
                                    messageList.pendingJumpMarker = ""
                                    // Search jump: reveal the chat once it is positioned.
                                    messageList.settling = false
                                    settleFallback.stop()
                                }
                            }

                            // Reaching the top by the user's own scrolling loads an older page.
                            // Not on any contentY change: a model reset (opening a chat) briefly
                            // puts the view at the top, and that used to load history, reload the
                            // whole view and hold it at the top until the page arrived.
                            function maybeLoadOlder() {
                                if (atYBeginning && olderAnchor === -1 && !noMoreHistory
                                        && contentHeight > height + 1) {
                                    olderAnchor = count
                                    msgModel.loadOlder()
                                    olderResetTimer.restart()
                                }
                            }
                            onContentYChanged: {
                                // Only the user's own scrolling (drag/wheel/scroll bar) counts —
                                // not layout changes or our own positioning.
                                if (!positioning && (moving || msgScrollBar.pressed)) {
                                    stickToEnd = nearEnd
                                    maybeLoadOlder()
                                }
                            }
                            onCountChanged: {
                                if (olderAnchor >= 0 && count > olderAnchor) {
                                    // Older page prepended — keep the previously-top message in view.
                                    positionViewAtIndex(count - olderAnchor, ListView.Beginning)
                                    olderAnchor = -1
                                    olderResetTimer.stop()
                                } else if (pendingJumpMarker.length > 0) {
                                    // A search jump is in flight — jumpTimer positions the view.
                                } else {
                                    followEnd()
                                }
                            }
                            // A reset (another chat) recreates the delegates; position once the
                            // view has processed it.
                            // Our own new message (sent, or from another device) always brings
                            // the view to the end — independent of how it was scrolled before.
                            Connections {
                                target: msgModel
                                function onOwnMessageAppended() {
                                    if (messageList.pendingJumpMarker.length > 0)
                                        return
                                    messageList.olderAnchor = -1
                                    messageList.stickToEnd = true
                                    Qt.callLater(messageList.followEnd)
                                }
                            }
                            Connections {
                                target: msgModel
                                function onModelReset() {
                                    if (messageList.settling)
                                        Qt.callLater(messageList.finishSettling)
                                    else
                                        Qt.callLater(messageList.followEnd)
                                }
                            }
                            Component.onCompleted: positionViewAtEnd()

                            Timer {
                                id: olderResetTimer
                                interval: 900
                                onTriggered: {
                                    if (messageList.olderAnchor >= 0) {
                                        // Page-up returned nothing new → start of history.
                                        messageList.noMoreHistory = true
                                        messageList.olderAnchor = -1
                                    }
                                }
                            }

                            Timer {
                                id: flashClear
                                interval: 1200
                                onTriggered: messageList.flashIndex = -1
                            }

                            delegate: Item {
                                id: msgDelegate
                                width: ListView.view.width
                                implicitHeight: bubble.height + 6
                                // Max content width — constant w.r.t. the bubble, so the
                                // bubble↔content width binding can't form a loop.
                                property real maxw: width * 0.72 - 24
                                // Show a per-message sender avatar for incoming group messages.
                                readonly property bool showAvatar: window.currentPeerIsMuc && !model.outgoing
                                // Captured here because the reaction-chip Repeater shadows `model`.
                                property string msgMarker: model.marker
                                // Retracted messages are tombstones: no chips, even if reactions linger in the store.
                                property var reactionChips: !model.retracted && model.reactions.length > 0 ? model.reactions.split("\n") : []

                                // Hover over the whole row reveals the quick-react bar.
                                HoverHandler { id: rowHover }

                                // A single react button appears in the gutter beside the bubble on
                                // hover; clicking it opens an emoji picker. Stays within the row.
                                Rectangle {
                                    id: reactBtn
                                    z: 2
                                    visible: (rowHover.hovered
                                              || (reactPickerGlobal.opened && reactPickerGlobal.parent === reactBtn))
                                             && !model.retracted
                                    width: 28
                                    height: 28
                                    radius: 14
                                    color: Qt.darker(Material.background, 1.25)
                                    border.width: 1
                                    border.color: Qt.rgba(0.5, 0.5, 0.5, 0.25)
                                    anchors.verticalCenter: bubble.verticalCenter
                                    x: model.outgoing ? Math.max(2, bubble.x - width - 6)
                                                      : Math.min(msgDelegate.width - width - 2, bubble.x + bubble.width + 6)

                                    ColorIcon {
                                        anchors.centerIn: parent
                                        width: 16
                                        height: 16
                                        source: window.iconBase + "reaction-smile-symbolic.svg"
                                        color: Material.foreground
                                    }
                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: window.openReactPicker(reactBtn, msgDelegate.msgMarker)
                                    }
                                }

                                // Sender avatar beside incoming group messages. Right-click →
                                // start a private message with that occupant.
                                Avatar {
                                    visible: msgDelegate.showAvatar
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    x: 10
                                    anchors.bottom: bubble.bottom
                                    name: model.sender
                                    avatarPath: model.senderAvatar
                                    presence: ""

                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        onClicked: senderMenu.popup()
                                    }
                                    Menu {
                                        id: senderMenu
                                        MenuItem {
                                            text: qsTr("Send private message")
                                            onTriggered: {
                                                var occupantJid = window.currentPeerJid + "/" + model.sender
                                                backend.startPrivate(occupantJid)
                                                window.openMucPm(occupantJid, model.sender)
                                            }
                                        }
                                    }
                                }

                                Rectangle {
                                    id: bubble
                                    y: 3
                                    x: model.outgoing ? msgDelegate.width - width - 10
                                                      : (msgDelegate.showAvatar ? 50 : 10)
                                    width: bubbleCol.width + 24
                                    height: bubbleCol.height + 16
                                    radius: 12
                                    color: model.outgoing ? "#283D6A" : "#7188C3"
                                    // Brief ring when this message is jumped to from a quote.
                                    border.width: index === messageList.flashIndex ? 2 : 0
                                    border.color: "#a8c7ff"

                                    // Right-click → message actions.
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        onClicked: bubbleMenu.popup()
                                    }
                                    Menu {
                                        id: bubbleMenu
                                        MenuItem {
                                            text: qsTr("Reply")
                                            enabled: !model.retracted
                                            onTriggered: window.startReply(model.marker, model.body)
                                        }
                                        // Own plain-text messages can be corrected (XEP-0308).
                                        MenuItem {
                                            text: qsTr("Edit")
                                            visible: model.outgoing && !model.retracted
                                                     && model.body.length > 0
                                                     && model.imagePath.length === 0
                                                     && model.audioPath.length === 0
                                            height: visible ? implicitHeight : 0
                                            onTriggered: window.startEdit(model.marker, model.body)
                                        }
                                        // Own messages can be retracted (XEP-0424), with confirmation.
                                        MenuItem {
                                            text: qsTr("Delete…")
                                            visible: model.outgoing && !model.retracted
                                                     && model.marker.length > 0
                                            height: visible ? implicitHeight : 0
                                            onTriggered: retractDialog.ask(model.marker)
                                        }
                                    }

                                    Column {
                                        id: bubbleCol
                                        x: 12
                                        y: 8
                                        spacing: 3

                                        // Sender nick (incoming MUC messages only).
                                        Label {
                                            textFormat: Text.PlainText
                                            visible: window.currentPeerIsMuc && !model.outgoing && model.sender.length > 0
                                            width: Math.min(implicitWidth, msgDelegate.maxw)
                                            text: model.sender
                                            color: "#FFC700"   // monocles accent (matches GTK muc-sender)
                                            font.pixelSize: 12
                                            font.bold: true
                                            elide: Text.ElideRight
                                        }

                                        // Quoted message this one replies to (XEP-0461): a lighter
                                        // block with a blue bar at the left (Android-style); click
                                        // jumps to (and flashes) the quoted message.
                                        Rectangle {
                                            visible: model.replyQuote.length > 0
                                            width: quoteText.width + 22
                                            height: quoteText.height + 12
                                            radius: 6
                                            color: Qt.rgba(1, 1, 1, 0.13)

                                            Rectangle {
                                                x: 5
                                                y: 5
                                                width: 3
                                                height: parent.height - 10
                                                radius: 1.5
                                                color: "#a8c7ff"
                                            }

                                            Label {
                                                id: quoteText
                                                textFormat: Text.PlainText
                                                x: 14
                                                y: 6
                                                width: Math.min(implicitWidth, msgDelegate.maxw - 22)
                                                text: model.replyQuote
                                                color: "white"
                                                opacity: 0.85
                                                font.pixelSize: 12
                                                renderType: Text.NativeRendering
                                                maximumLineCount: 2
                                                elide: Text.ElideRight
                                                wrapMode: Text.Wrap
                                            }

                                            MouseArea {
                                                anchors.fill: parent
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: {
                                                    var idx = msgModel.indexOfMarker(model.replyTo)
                                                    if (idx >= 0) {
                                                        messageList.stickToEnd = false
                                                        messageList.positionViewAtIndex(idx, ListView.Center)
                                                        messageList.flashIndex = idx
                                                        flashClear.restart()
                                                    }
                                                }
                                            }
                                        }

                                        // Several files shared in ONE message (XEP-0447, as
                                        // monocles Android sends them): a wrapping grid of
                                        // tiles — a thumbnail per image once it is cached, a
                                        // card for every other file. The caption, if any,
                                        // renders in bubbleText below. Single-file messages
                                        // leave this empty and use the rows underneath.
                                        Flow {
                                            id: attachmentGrid
                                            readonly property var files:
                                                model.attachments.length > 0 ? JSON.parse(model.attachments) : []
                                            readonly property real tile: 104
                                            visible: files.length > 0
                                            spacing: 6
                                            // Exactly as wide as the tiles shown, at most three
                                            // per row, so the bubble reserves no empty space.
                                            width: Math.min(msgDelegate.maxw,
                                                            Math.min(files.length, 3) * (tile + spacing) - spacing)
                                            Repeater {
                                                model: attachmentGrid.files
                                                delegate: Rectangle {
                                                    id: attachmentTile
                                                    readonly property bool cached: modelData.path.length > 0
                                                    readonly property bool inlineImage: modelData.kind === "image" && cached
                                                    width: attachmentGrid.tile
                                                    height: attachmentGrid.tile
                                                    radius: 6
                                                    color: attachmentTile.inlineImage ? "transparent" : Qt.rgba(1, 1, 1, 0.14)
                                                    clip: true

                                                    AnimatedImage {
                                                        anchors.fill: parent
                                                        visible: attachmentTile.inlineImage
                                                        source: attachmentTile.inlineImage ? "file:" + modelData.path : ""
                                                        fillMode: Image.PreserveAspectCrop
                                                        playing: true
                                                        cache: false
                                                    }

                                                    // Not (yet) an inline image: an icon, the
                                                    // file name, and what a click will do.
                                                    ColumnLayout {
                                                        anchors.fill: parent
                                                        anchors.margins: 6
                                                        spacing: 2
                                                        visible: !attachmentTile.inlineImage
                                                        Item { Layout.fillHeight: true }
                                                        Label {
                                                            textFormat: Text.PlainText
                                                            Layout.alignment: Qt.AlignHCenter
                                                            text: modelData.kind === "image" ? "🖼"
                                                                : modelData.kind === "audio" ? "🎤" : "📄"
                                                            font.family: "Noto Color Emoji"
                                                            font.pixelSize: 24
                                                            renderType: Text.NativeRendering
                                                        }
                                                        Label {
                                                            textFormat: Text.PlainText
                                                            Layout.fillWidth: true
                                                            horizontalAlignment: Text.AlignHCenter
                                                            text: modelData.name
                                                            color: "white"
                                                            font.pixelSize: 10
                                                            elide: Text.ElideMiddle
                                                        }
                                                        Label {
                                                            textFormat: Text.PlainText
                                                            Layout.alignment: Qt.AlignHCenter
                                                            visible: !attachmentTile.cached
                                                            text: qsTr("Download")
                                                            color: "white"
                                                            opacity: 0.7
                                                            font.pixelSize: 9
                                                        }
                                                        Item { Layout.fillHeight: true }
                                                    }

                                                    MouseArea {
                                                        anchors.fill: parent
                                                        cursorShape: Qt.PointingHandCursor
                                                        onClicked: {
                                                            if (attachmentTile.inlineImage) {
                                                                imageViewer.path = modelData.path
                                                                imageViewer.open()
                                                            } else if (attachmentTile.cached && modelData.kind === "audio") {
                                                                backend.audioToggle(modelData.path)
                                                            } else if (modelData.kind === "image" || modelData.kind === "audio") {
                                                                // Cache it, then it renders/plays in place.
                                                                msgModel.downloadAttachment(modelData.url)
                                                            } else {
                                                                // Save under its real name and open it.
                                                                backend.downloadFile(modelData.url, modelData.name)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Inline sticker / image — rendered from the on-disk cache
                                        // (BoB cid: or a downloaded upload URL). AnimatedImage so
                                        // GIF/WebP stickers animate; capped to a sensible size.
                                        AnimatedImage {
                                            id: bubbleImage
                                            readonly property real cap: 200
                                            visible: model.imagePath.length > 0
                                            source: model.imagePath.length > 0 ? "file:" + model.imagePath : ""
                                            fillMode: Image.PreserveAspectFit
                                            playing: true
                                            cache: false
                                            width: implicitWidth > 0 ? Math.min(implicitWidth, msgDelegate.maxw, cap) : 0
                                            height: implicitWidth > 0 ? implicitHeight * (width / implicitWidth) : 0
                                            // Click to open the image full-size.
                                            MouseArea {
                                                anchors.fill: parent
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: { imageViewer.path = model.imagePath; imageViewer.open() }
                                            }
                                        }

                                        // Voice / audio message player: play-pause + animated
                                        // progress + time, driven by the shared GStreamer player.
                                        RowLayout {
                                            id: audioRow
                                            visible: model.audioPath.length > 0
                                            spacing: 8
                                            readonly property bool active: backend.audioPath === model.audioPath
                                            readonly property bool playing: active && backend.audioPlaying
                                            readonly property real posMs: active ? backend.audioPos : 0
                                            readonly property real durMs: active && backend.audioDuration > 0 ? backend.audioDuration : 0

                                            // Outlined play/pause: transparent circle with a thin
                                            // white border, glyphs drawn as vectors (the ▶/⏸ font
                                            // glyphs render inconsistently across emoji fonts).
                                            Rectangle {
                                                Layout.preferredWidth: 36
                                                Layout.preferredHeight: 36
                                                radius: width / 2
                                                color: playMouse.pressed ? Qt.rgba(1, 1, 1, 0.18)
                                                     : playMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08)
                                                     : "transparent"
                                                border.color: "white"
                                                border.width: 1.5
                                                Behavior on color { ColorAnimation { duration: 100 } }

                                                Canvas {
                                                    anchors.centerIn: parent
                                                    width: 14
                                                    height: 14
                                                    property bool playing: audioRow.playing
                                                    onPlayingChanged: requestPaint()
                                                    onPaint: {
                                                        const ctx = getContext("2d")
                                                        ctx.reset()
                                                        ctx.fillStyle = "white"
                                                        if (playing) {
                                                            ctx.fillRect(1.5, 0.5, 3.5, height - 1)
                                                            ctx.fillRect(9, 0.5, 3.5, height - 1)
                                                        } else {
                                                            ctx.beginPath()
                                                            ctx.moveTo(3, 0.5)
                                                            ctx.lineTo(width - 1, height / 2)
                                                            ctx.lineTo(3, height - 0.5)
                                                            ctx.closePath()
                                                            ctx.fill()
                                                        }
                                                    }
                                                }

                                                MouseArea {
                                                    id: playMouse
                                                    anchors.fill: parent
                                                    hoverEnabled: true
                                                    cursorShape: Qt.PointingHandCursor
                                                    onClicked: backend.audioToggle(model.audioPath)
                                                }
                                            }
                                            ColumnLayout {
                                                spacing: 1
                                                Layout.preferredWidth: 160
                                                ProgressBar {
                                                    Layout.fillWidth: true
                                                    from: 0; to: 1
                                                    value: audioRow.durMs > 0 ? audioRow.posMs / audioRow.durMs : 0
                                                    Material.accent: "white"
                                                    Behavior on value { NumberAnimation { duration: 120 } }
                                                }
                                                Label {
                                                    textFormat: Text.PlainText
                                                    text: "🎤 " + window.fmtSecs(Math.floor(audioRow.posMs / 1000))
                                                          + (audioRow.durMs > 0 ? " / " + window.fmtSecs(Math.floor(audioRow.durMs / 1000)) : "")
                                                    color: "white"
                                                    opacity: 0.8
                                                    font.pixelSize: 10
                                                }
                                            }
                                        }

                                        // A shared WebXDC mini-app: name card + Open button.
                                        RowLayout {
                                            visible: model.webxdc
                                            spacing: 10
                                            Label {
                                                textFormat: Text.PlainText
                                                text: "🧩"
                                                font.family: "Noto Color Emoji"
                                                font.pixelSize: 26
                                                renderType: Text.NativeRendering
                                            }
                                            ColumnLayout {
                                                spacing: 4
                                                Label {
                                                    textFormat: Text.PlainText
                                                    text: qsTr("WebXDC app")
                                                    color: "white"
                                                    font.bold: true
                                                }
                                                Button {
                                                    text: qsTr("Open")
                                                    Material.background: Material.accent
                                                    onClicked: backend.openWebxdc(window.currentPeerJid,
                                                                                  model.xdcThread,
                                                                                  model.webxdcUrl)
                                                }
                                            }
                                        }

                                        // A shared non-image/audio file: name card + Open button
                                        // (downloads + decrypts on demand, then opens it). The
                                        // caption, if any, renders in bubbleText below.
                                        RowLayout {
                                            id: fileRow
                                            visible: model.fileUrl.length > 0
                                            spacing: 10
                                            Label {
                                                textFormat: Text.PlainText
                                                text: "📄"
                                                font.family: "Noto Color Emoji"
                                                font.pixelSize: 26
                                                renderType: Text.NativeRendering
                                            }
                                            ColumnLayout {
                                                spacing: 4
                                                Label {
                                                    textFormat: Text.PlainText
                                                    text: model.fileName.length > 0 ? model.fileName
                                                                                    : qsTr("File")
                                                    color: "white"
                                                    font.bold: true
                                                    elide: Text.ElideMiddle
                                                    Layout.maximumWidth: msgDelegate.maxw
                                                }
                                                Button {
                                                    text: qsTr("Download")
                                                    Material.background: Material.accent
                                                    onClicked: msgModel.downloadAttachment(model.fileUrl)
                                                }
                                            }
                                        }

                                        Label {
                                            id: bubbleText
                                            textFormat: Text.PlainText
                                            visible: model.body.length > 0
                                            // A caption wraps to the width of the media above it
                                            // (image / audio / file) so it never stretches the
                                            // bubble wider than the media; plain text uses maxw.
                                            // A 140px floor keeps a long caption on small media
                                            // from wrapping to a sliver.
                                            readonly property real captionCap:
                                                bubbleImage.visible && bubbleImage.width > 0 ? Math.max(bubbleImage.width, 140)
                                                : audioRow.visible && audioRow.width > 0 ? Math.max(audioRow.width, 140)
                                                : fileRow.visible && fileRow.width > 0 ? Math.max(fileRow.width, 140)
                                                : msgDelegate.maxw
                                            width: Math.min(implicitWidth, captionCap, msgDelegate.maxw)
                                            text: model.body
                                            color: "white"
                                            // Retracted messages render as a dimmed tombstone.
                                            font.italic: model.retracted
                                            opacity: model.retracted ? 0.6 : 1
                                            wrapMode: Text.Wrap
                                            // Colour emoji via the app font's emoji fallback (set in
                                            // main.rs) + the native renderer.
                                            renderType: Text.NativeRendering
                                        }

                                        // Reaction chips (XEP-0444), laid out beside each other.
                                        // Click a chip to toggle it.
                                        Row {
                                            visible: msgDelegate.reactionChips.length > 0
                                            spacing: 4
                                            Repeater {
                                                model: msgDelegate.reactionChips
                                                delegate: Rectangle {
                                                    radius: 10
                                                    color: Qt.rgba(1, 1, 1, 0.18)
                                                    implicitHeight: 20
                                                    implicitWidth: chipRow.implicitWidth + 12
                                                    // Reactor names (3rd tab field), shown on hover —
                                                    // as plain text: they are chosen by other users.
                                                    ToolTip {
                                                        id: chipTip
                                                        text: modelData.split("\t")[2] || ""
                                                        visible: chipMouse.containsMouse && text.length > 0
                                                        delay: 300
                                                        contentItem: Label {
                                                            textFormat: Text.PlainText
                                                            text: chipTip.text
                                                            wrapMode: Text.Wrap
                                                        }
                                                    }
                                                    Row {
                                                        id: chipRow
                                                        anchors.centerIn: parent
                                                        spacing: 3
                                                        Label { textFormat: Text.PlainText; text: modelData.split("\t")[0]; font.family: "Noto Color Emoji"; font.pixelSize: 13; renderType: Text.NativeRendering }
                                                        Label { textFormat: Text.PlainText; text: modelData.split("\t")[1]; font.pixelSize: 11; color: "white"; opacity: 0.85 }
                                                    }
                                                    MouseArea {
                                                        id: chipMouse
                                                        anchors.fill: parent
                                                        hoverEnabled: true
                                                        cursorShape: Qt.PointingHandCursor
                                                        onClicked: backend.react(window.currentPeerJid, msgDelegate.msgMarker, modelData.split("\t")[0])
                                                    }
                                                }
                                            }
                                        }

                                        // Footer: edited tag · time · OMEMO2 lock (if encrypted) · delivery state.
                                        RowLayout {
                                            spacing: 4
                                            Label {
                                                textFormat: Text.PlainText
                                                visible: model.edited && !model.retracted
                                                text: qsTr("edited")
                                                color: "white"
                                                opacity: 0.55
                                                font.pixelSize: 10
                                                font.italic: true
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                text: window.msgTime(model.timestamp)
                                                color: "white"
                                                opacity: 0.55
                                                font.pixelSize: 10
                                            }
                                            ColorIcon {
                                                visible: model.encrypted
                                                implicitWidth: 11
                                                implicitHeight: 11
                                                source: window.iconBase + "lock-omemo2.svg"
                                                color: "white"
                                                opacity: 0.7
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                visible: model.outgoing && model.state.length > 0
                                                text: model.state === "displayed" || model.state === "received" ? "✓✓"
                                                    : model.state === "sent" ? "✓"
                                                    : "🕓"
                                                color: "white"
                                                opacity: model.state === "displayed" ? 1.0 : 0.6
                                                font.pixelSize: 11
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Reply preview bar (shown while composing a reply): the same
                        // blue-bar quote block style as in-bubble quotes.
                        Pane {
                            Layout.fillWidth: true
                            visible: window.replyToMarker.length > 0
                            padding: 4
                            contentItem: RowLayout {
                                spacing: 6
                                Rectangle {
                                    Layout.fillWidth: true
                                    implicitHeight: replyPreviewText.implicitHeight + 12
                                    radius: 6
                                    color: Material.theme === Material.Dark ? Qt.rgba(1, 1, 1, 0.08)
                                                                            : Qt.rgba(0, 0, 0, 0.05)
                                    Rectangle {
                                        x: 5
                                        y: 5
                                        width: 3
                                        height: parent.height - 10
                                        radius: 1.5
                                        color: "#a8c7ff"
                                    }
                                    Label {
                                        id: replyPreviewText
                                        textFormat: Text.PlainText
                                        x: 14
                                        y: 6
                                        width: parent.width - 22
                                        text: window.replyToText
                                        elide: Text.ElideRight
                                        maximumLineCount: 1
                                        opacity: 0.8
                                    }
                                }
                                ToolButton {
                                    text: "✕"
                                    onClicked: window.clearReply()
                                }
                            }
                        }

                        // Edit banner (shown while editing a sent message; send applies the
                        // XEP-0308 correction).
                        Pane {
                            Layout.fillWidth: true
                            visible: window.editTargetMarker.length > 0
                            padding: 4
                            contentItem: RowLayout {
                                spacing: 6
                                Label { textFormat: Text.PlainText; text: "✎"; opacity: 0.7 }
                                Label {
                                    textFormat: Text.PlainText
                                    Layout.fillWidth: true
                                    text: qsTr("Editing: %1").arg(window.editOriginalText)
                                    elide: Text.ElideRight
                                    opacity: 0.7
                                }
                                ToolButton {
                                    text: "✕"
                                    onClicked: window.clearEdit()
                                }
                            }
                        }

                        Pane {
                            Layout.fillWidth: true
                            padding: 8
                            contentItem: Item {
                                implicitHeight: Math.max(composerRow.implicitHeight, recordRow.implicitHeight)

                                // Voice-recording bar — replaces the composer while recording.
                                RowLayout {
                                    id: recordRow
                                    anchors.fill: parent
                                    visible: window.recording
                                    spacing: 8

                                    Rectangle {
                                        Layout.fillWidth: true
                                        implicitHeight: 34
                                        radius: height / 2
                                        color: Material.theme === Material.Dark ? Qt.rgba(1, 1, 1, 0.07)
                                                                                : Qt.rgba(0, 0, 0, 0.06)
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 14
                                            anchors.rightMargin: 4
                                            spacing: 8
                                            Rectangle {
                                                width: 11; height: 11; radius: 5.5; color: "#e53935"
                                                SequentialAnimation on opacity {
                                                    running: window.recording; loops: Animation.Infinite
                                                    NumberAnimation { from: 1.0; to: 0.25; duration: 600 }
                                                    NumberAnimation { from: 0.25; to: 1.0; duration: 600 }
                                                }
                                            }
                                            Label {
                                                textFormat: Text.PlainText
                                                Layout.fillWidth: true
                                                text: qsTr("Recording… ") + window.fmtSecs(window.recordSecs)
                                            }
                                            ToolButton {
                                                text: "✕"
                                                ToolTip.text: qsTr("Cancel"); ToolTip.visible: hovered
                                                onClicked: window.cancelVoice()
                                            }
                                        }
                                    }

                                    // Circular send button, matching the composer's action button.
                                    Rectangle {
                                        Layout.preferredWidth: 38
                                        Layout.preferredHeight: 38
                                        radius: width / 2
                                        color: recordSendMouse.pressed ? Qt.darker(Material.accent, 1.25) : Material.accent
                                        Behavior on color { ColorAnimation { duration: 100 } }
                                        ColorIcon {
                                            anchors.centerIn: parent
                                            implicitWidth: 20; implicitHeight: 20
                                            source: window.iconBase + "send.svg"
                                            color: "white"
                                        }
                                        MouseArea {
                                            id: recordSendMouse
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: window.sendVoice()
                                        }
                                        ToolTip.text: qsTr("Send voice message")
                                        ToolTip.visible: recordSendMouse.containsMouse
                                    }
                                }

                            RowLayout {
                                id: composerRow
                                anchors.fill: parent
                                visible: !window.recording
                                spacing: 8

                                readonly property bool hasText: composer.text.trim().length > 0

                                // Rounded input pill: emoji | text | attach (Signal-desktop style).
                                Rectangle {
                                    Layout.fillWidth: true
                                    implicitHeight: Math.max(34, pillRow.implicitHeight + 2)
                                    // Fully round while single-line; stays softly rounded as
                                    // the input grows.
                                    radius: Math.min(height / 2, 17)
                                    color: Material.theme === Material.Dark ? Qt.rgba(1, 1, 1, 0.07)
                                                                            : Qt.rgba(0, 0, 0, 0.06)

                                    // Clicking anywhere on the pill focuses the text field.
                                    TapHandler { onTapped: composer.forceActiveFocus() }

                                    RowLayout {
                                        id: pillRow
                                        anchors.fill: parent
                                        anchors.leftMargin: 4
                                        anchors.rightMargin: 4
                                        spacing: 0

                                // Emoji & sticker picker.
                                ToolButton {
                                    id: emojiBtn
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    Layout.alignment: Qt.AlignBottom
                                    ToolTip.text: qsTr("Emoji & stickers")
                                    ToolTip.visible: hovered
                                    onClicked: {
                                        var s = backend.stickerFiles()
                                        window.stickerList = s.length > 0 ? s.split("\n") : []
                                        emojiPopup.open()
                                    }
                                    contentItem: ColorIcon {
                                        implicitWidth: 18
                                        implicitHeight: 18
                                        source: window.iconBase + "reaction-smile-symbolic.svg"
                                        color: Material.foreground
                                    }

                                    Popup {
                                        id: emojiPopup
                                        y: -height - 6
                                        width: 320
                                        height: 320
                                        padding: 6

                                        ColumnLayout {
                                            anchors.fill: parent
                                            spacing: 6

                                            TabBar {
                                                id: pickerTabs
                                                Layout.fillWidth: true
                                                TabButton { text: qsTr("Emoji") }
                                                TabButton { text: qsTr("Stickers") }
                                            }

                                            StackLayout {
                                                Layout.fillWidth: true
                                                Layout.fillHeight: true
                                                currentIndex: pickerTabs.currentIndex

                                                // Emoji — the full Unicode set, categorised like
                                                // Android; click to insert at the cursor.
                                                ColumnLayout {
                                                    spacing: 2
                                                    Row {
                                                        Layout.fillWidth: true
                                                        spacing: 0
                                                        Repeater {
                                                            model: EmojiData.categories
                                                            delegate: ToolButton {
                                                                implicitWidth: 33
                                                                implicitHeight: 30
                                                                text: modelData.icon
                                                                font.family: "Noto Color Emoji"
                                                                font.pixelSize: 14
                                                                opacity: emojiGrid.category === index ? 1.0 : 0.45
                                                                ToolTip.text: modelData.name
                                                                ToolTip.visible: hovered
                                                                onClicked: emojiGrid.category = index
                                                            }
                                                        }
                                                    }
                                                    GridView {
                                                        FastScroll {}
                                                        ScrollBar.vertical: ThinScrollBar {}
                                                        id: emojiGrid
                                                        property int category: 0
                                                        Layout.fillWidth: true
                                                        Layout.fillHeight: true
                                                        clip: true
                                                        cellWidth: 34
                                                        cellHeight: 34
                                                        model: EmojiData.categories[category].emojis
                                                        delegate: Label {
                                                            width: 34
                                                            height: 34
                                                            text: modelData
                                                            horizontalAlignment: Text.AlignHCenter
                                                            verticalAlignment: Text.AlignVCenter
                                                            font.family: "Noto Color Emoji"
                                                            font.pixelSize: 22
                                                            renderType: Text.NativeRendering
                                                            MouseArea {
                                                                anchors.fill: parent
                                                                cursorShape: Qt.PointingHandCursor
                                                                onClicked: {
                                                                    composer.insert(composer.cursorPosition, modelData)
                                                                    composer.forceActiveFocus()
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                // Stickers — click to send immediately.
                                                Item {
                                                    GridView {
                                                        FastScroll {}
                                                        ScrollBar.vertical: ThinScrollBar {}
                                                        id: stickerGrid
                                                        anchors.fill: parent
                                                        clip: true
                                                        visible: window.stickerList.length > 0
                                                        cellWidth: 76
                                                        cellHeight: 76
                                                        model: window.stickerList
                                                        delegate: ItemDelegate {
                                                            width: 76
                                                            height: 76
                                                            onClicked: {
                                                                { messageList.stickToEnd = true; backend.sendSticker(window.currentPeerJid, modelData) }
                                                                emojiPopup.close()
                                                            }
                                                            contentItem: AnimatedImage {
                                                                source: "file:" + modelData
                                                                fillMode: Image.PreserveAspectFit
                                                                playing: true
                                                                cache: false
                                                                width: 64
                                                                height: 64
                                                            }
                                                        }
                                                    }
                                                    Label {
                                                        textFormat: Text.PlainText
                                                        anchors.centerIn: parent
                                                        width: parent.width - 24
                                                        visible: window.stickerList.length === 0
                                                        horizontalAlignment: Text.AlignHCenter
                                                        wrapMode: Text.Wrap
                                                        opacity: 0.6
                                                        font.pixelSize: 12
                                                        text: qsTr("No stickers yet. Use the folder button below to add images.")
                                                    }
                                                    // Open the stickers folder to import more.
                                                    RoundButton {
                                                        anchors.right: parent.right
                                                        anchors.bottom: parent.bottom
                                                        anchors.margins: 4
                                                        z: 2
                                                        implicitWidth: 36
                                                        implicitHeight: 36
                                                        text: "📂"
                                                        font.family: "Noto Color Emoji"
                                                        font.pixelSize: 14
                                                        Material.background: Material.accent
                                                        ToolTip.text: qsTr("Open stickers folder")
                                                        ToolTip.visible: hovered
                                                        onClicked: Qt.openUrlExternally("file://" + backend.stickerDir())
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                        // Auto-growing multiline input: Enter sends,
                                        // Shift+Enter inserts a newline.
                                        ScrollView {
                                            Layout.fillWidth: true
                                            Layout.maximumHeight: 120
                                            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
                                            // No visible bar inside the input pill (Signal-style);
                                            // long drafts still scroll with the cursor.
                                            ScrollBar.vertical.policy: ScrollBar.AlwaysOff

                                            TextArea {
                                                id: composer
                                                placeholderText: qsTr("Message…")
                                                wrapMode: TextArea.Wrap
                                                // Render typed emoji in colour (see bubbleText / main.rs).
                                                renderType: Text.NativeRendering
                                                background: null
                                                // Material reserves extra bottom space for the
                                                // underline; equal padding recentres the cursor.
                                                topPadding: 6
                                                bottomPadding: 6
                                                leftPadding: 6
                                                rightPadding: 6
                                                Keys.onReturnPressed: (event) => {
                                                    if (event.modifiers & Qt.ShiftModifier) {
                                                        event.accepted = false
                                                    } else {
                                                        window.sendComposed()
                                                        event.accepted = true
                                                    }
                                                }
                                            }
                                        }

                                        // Attachment — inside the pill, rightmost.
                                        ToolButton {
                                            implicitWidth: 32
                                            implicitHeight: 32
                                            Layout.alignment: Qt.AlignBottom
                                            ToolTip.text: qsTr("Attach a file")
                                            ToolTip.visible: hovered
                                            onClicked: attachFileDialog.open()
                                            contentItem: ColorIcon {
                                                implicitWidth: 19; implicitHeight: 19
                                                source: window.iconBase + "attach.svg"
                                                color: Material.foreground
                                            }
                                        }
                                    }
                                }

                                // Circular accent button: mic when empty, send once there's text.
                                Rectangle {
                                    Layout.preferredWidth: 38
                                    Layout.preferredHeight: 38
                                    Layout.alignment: Qt.AlignBottom
                                    radius: width / 2
                                    color: actionMouse.pressed ? Qt.darker(Material.accent, 1.25) : Material.accent
                                    Behavior on color { ColorAnimation { duration: 100 } }
                                    ColorIcon {
                                        anchors.centerIn: parent
                                        implicitWidth: 20; implicitHeight: 20
                                        source: window.iconBase + (composerRow.hasText ? "send.svg" : "mic.svg")
                                        color: "white"
                                    }
                                    MouseArea {
                                        id: actionMouse
                                        anchors.fill: parent
                                        hoverEnabled: true
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: composerRow.hasText ? window.sendComposed()
                                                                       : window.beginVoice()
                                    }
                                    ToolTip.text: composerRow.hasText ? qsTr("Send")
                                                                      : qsTr("Record a voice message")
                                    ToolTip.visible: actionMouse.containsMouse
                                }
                            }
                            }
                        }
                    }
                }
            }
    }

    // Add-contact dialog: roster add + presence request (with pre-approval), then opens the
    // new 1:1 chat right away.
    Dialog {
        id: addContactDialog
        title: qsTr("Add contact")
        anchors.centerIn: parent
        modal: true
        width: 360
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAboutToShow: {
            contactJidField.text = ""
            contactNameField.text = ""
        }
        onAccepted: {
            var jid = contactJidField.text.trim()
            if (jid.indexOf("@") <= 0)
                return
            var name = contactNameField.text.trim()
            backend.addContact(jid, name)
            window.openContact(jid, name.length > 0 ? name : jid.split("@")[0], "", "")
            shell.sectionIndex = 0
        }
        contentItem: ColumnLayout {
            spacing: 8
            TextField {
                id: contactJidField
                placeholderText: qsTr("user@example.org")
                inputMethodHints: Qt.ImhNoAutoUppercase
                Layout.fillWidth: true
            }
            TextField {
                id: contactNameField
                placeholderText: qsTr("Name (optional)")
                Layout.fillWidth: true
            }
        }
    }

    // Join-room dialog (top-level → renders in the window overlay, not clipped).
    Dialog {
        id: joinDialog
        title: qsTr("Join group chat")
        anchors.centerIn: parent
        modal: true
        width: 360
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAboutToShow: {
            roomField.text = ""
            nickField.text = window.accountJid.indexOf("@") > 0 ? window.accountJid.split("@")[0] : ""
        }
        onAccepted: {
            if (roomField.text.trim().length > 0 && nickField.text.trim().length > 0) {
                backend.joinMuc(roomField.text.trim(), nickField.text.trim())
                shell.sectionIndex = 0
            }
        }
        contentItem: ColumnLayout {
            spacing: 8
            TextField {
                id: roomField
                placeholderText: qsTr("room@conference.example.org")
                inputMethodHints: Qt.ImhNoAutoUppercase
                Layout.fillWidth: true
            }
            TextField {
                id: nickField
                placeholderText: qsTr("Nickname")
                Layout.fillWidth: true
            }
        }
    }

    // --- Profile: pick a new own avatar (scaled + published via XEP-0084) ---------
    FileDialog {
        id: avatarFileDialog
        title: qsTr("Choose a profile photo")
        nameFilters: [qsTr("Images (*.png *.jpg *.jpeg *.webp *.gif)")]
        onAccepted: {
            var p = selectedFile.toString().replace(/^file:\/\//, "")
            if (p.length > 0)
                backend.publishAvatar(p)
        }
    }

    // --- Composer: attach a file (XEP-0363 upload) --------------------------------
    FileDialog {
        id: attachFileDialog
        title: qsTr("Attach files")
        // Several files can be picked at once; they are then shared in ONE message
        // (XEP-0447) with a single caption, the way monocles Android does it.
        fileMode: FileDialog.OpenFiles
        onAccepted: {
            var picked = []
            for (var i = 0; i < selectedFiles.length; ++i) {
                var p = selectedFiles[i].toString().replace(/^file:\/\//, "")
                if (p.length > 0)
                    picked.push(p)
            }
            if (picked.length > 0 && window.currentPeerJid.length > 0) {
                window.pendingAttachPaths = picked
                attachCaptionField.text = ""
                sendFileDialog.open()
            }
        }
    }
    // Caption prompt before sending. An empty caption sends the file(s) alone; a non-empty one
    // is delivered in the SAME message — encrypted inside the SCE envelope for OMEMO2 chats.
    // Several files become one multi-file message sharing that caption.
    Dialog {
        id: sendFileDialog
        title: window.pendingAttachPaths.length > 1 ? qsTr("Send %1 files").arg(window.pendingAttachPaths.length)
                                                    : qsTr("Send file")
        anchors.centerIn: parent
        modal: true
        width: 360
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: {
            if (window.pendingAttachPaths.length > 0 && window.currentPeerJid.length > 0) {
                messageList.stickToEnd = true
                backend.sendFiles(window.currentPeerJid, window.pendingAttachPaths.join("\n"),
                                  attachCaptionField.text.trim())
            }
            window.pendingAttachPaths = []
        }
        onRejected: window.pendingAttachPaths = []
        contentItem: ColumnLayout {
            spacing: 8
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: window.pendingAttachPaths.map(function (p) {
                    return p.split('/').pop()
                }).join(", ")
                elide: Text.ElideMiddle
                opacity: 0.7
            }
            TextField {
                id: attachCaptionField
                placeholderText: qsTr("Caption (optional)")
                Layout.fillWidth: true
                Keys.onReturnPressed: sendFileDialog.accept()
            }
        }
    }

    // --- Stories: pick media, add a title, then publish ---------------------------
    FileDialog {
        id: storyFileDialog
        title: qsTr("Choose a photo or video")
        // Formats whose location/device metadata can be removed before publishing.
        nameFilters: [qsTr("Media (*.png *.jpg *.jpeg *.gif *.webp *.mp4 *.m4v *.mov *.3gp *.webm *.mkv)")]
        onAccepted: {
            window.pendingStoryPath = selectedFile.toString().replace(/^file:\/\//, "")
            storyTitleField.text = ""
            postStoryDialog.open()
        }
    }
    Dialog {
        id: postStoryDialog
        title: qsTr("Post a story")
        anchors.centerIn: parent
        modal: true
        width: 360
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: {
            if (window.pendingStoryPath.length > 0)
                backend.publishStory(window.pendingStoryPath, storyTitleField.text.trim())
            window.pendingStoryPath = ""
        }
        contentItem: ColumnLayout {
            spacing: 8
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: window.pendingStoryPath.split('/').pop()
                elide: Text.ElideMiddle
                opacity: 0.7
            }
            TextField {
                id: storyTitleField
                placeholderText: qsTr("Caption (optional)")
                Layout.fillWidth: true
            }
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: qsTr("Visible to your contacts for 24 hours. Location and device data are removed from the file.")
                wrapMode: Text.Wrap
                opacity: 0.6
                font.pixelSize: 11
            }
        }
    }
    Dialog {
        id: storyDeleteDialog
        property string uuid: ""
        title: qsTr("Delete story?")
        anchors.centerIn: parent
        modal: true
        standardButtons: Dialog.Yes | Dialog.No
        onAccepted: if (uuid.length > 0) backend.retractStory(uuid)
        onClosed: storyViewer.dialogOpen = false
        Label { textFormat: Text.PlainText; text: qsTr("It will be removed for all your contacts.") }
    }
    // Story viewer: plays one publisher's stories oldest first (as on Android) with segmented
    // progress bars and a 6s auto-advance per image. The timer only runs while the image is
    // loaded, the window is active, no dialog is open and the user isn't holding it (press
    // and hold pauses). Videos are downloaded when they come up, then show a Play button (system
    // player; there is no Qt Multimedia here) and wait for a tap.
    Popup {
        id: storyViewer
        parent: Overlay.overlay
        modal: true
        width: window.width
        height: window.height
        padding: 0
        closePolicy: Popup.CloseOnEscape
        background: Rectangle { color: "#000000" }

        readonly property int seconds: 6
        property real progress: 0
        // The shown story, kept across model resets (a media download reloads the model).
        property string contact: ""
        property string uuid: ""
        property string shownUuid: ""
        property string currentPath: ""
        property string currentMime: ""
        property double currentPublished: 0
        property bool held: false
        property bool dialogOpen: false
        readonly property bool currentIsVideo: currentMime.indexOf("video") === 0
        // Runs once the image is on screen (as on Android), not merely downloaded.
        readonly property bool playing: opened && !currentIsVideo && currentPath.length > 0
            && pager.currentItem !== null && pager.currentItem.mediaShown
            && !held && !dialogOpen && Qt.application.state === Qt.ApplicationActive

        function openFor(c, u) {
            contact = c
            uuid = u
            shownUuid = ""
            progressAnim.stop()
            progress = 0
            currentPath = ""
            currentMime = ""
            open()
            viewerStories.loadContact(window.accountJid, c)
        }
        // The model was (re)loaded (opened, a media download landed, a story was removed).
        // `visible`, not `opened`: the stories usually arrive while the open transition still
        // runs, and skipping them then left the timer stopped until some later reload.
        function resync() {
            if (!visible)
                return
            if (pager.count === 0) {
                close()
                return
            }
            var i = viewerStories.indexOf(contact, uuid)
            if (i < 0)
                i = Math.min(Math.max(pager.currentIndex, 0), pager.count - 1)
            if (pager.currentIndex !== i)
                pager.currentIndex = i
            else
                refreshCurrent()
        }
        // `uuid` is the story to show; it only changes by navigation. A ListView moves its
        // currentIndex on a model reset, so an index that doesn't match is moved back (or, if
        // that story is gone, accepted).
        function refreshCurrent() {
            var i = pager.currentIndex
            if (!visible || i < 0)
                return
            var u = viewerStories.uuidAt(i)
            if (u !== uuid) {
                var j = viewerStories.indexOf(contact, uuid)
                if (j >= 0 && j !== i) {
                    pager.currentIndex = j
                    return
                }
                uuid = u
            }
            var changed = u !== shownUuid
            shownUuid = u
            currentMime = viewerStories.mimeAt(i)
            currentPath = viewerStories.pathAt(i)
            currentPublished = viewerStories.publishedAt(i)
            if (changed)
                restartProgress()
            else
                updatePlayback()
        }
        function goTo(i) {
            uuid = viewerStories.uuidAt(i)
            pager.currentIndex = i
        }
        function goNext() {
            if (pager.currentIndex + 1 < pager.count)
                goTo(pager.currentIndex + 1)
            else
                storyViewer.close()
        }
        function goPrev() {
            if (pager.currentIndex > 0)
                goTo(pager.currentIndex - 1)
            else
                restartProgress()
        }
        function restartProgress() {
            progressAnim.stop()
            progress = 0
            updatePlayback()
        }
        function updatePlayback() {
            if (playing) {
                if (progressAnim.paused)
                    progressAnim.resume()
                else if (!progressAnim.running)
                    progressAnim.start()
            } else if (progressAnim.running && !progressAnim.paused) {
                progressAnim.pause()
            }
        }

        onPlayingChanged: updatePlayback()
        onOpened: resync()
        onClosed: {
            progressAnim.stop()
            held = false
            contact = ""
            uuid = ""
            shownUuid = ""
        }

        // Deferred: the ListView handles the same reset after us and would undo a selection
        // made here (it restores its cleared currentIndex), leaving the timer stopped until
        // some later reload.
        Connections {
            target: viewerStories
            function onModelReset() { Qt.callLater(storyViewer.resync) }
        }

        NumberAnimation {
            id: progressAnim
            target: storyViewer
            property: "progress"
            from: 0; to: 1
            duration: storyViewer.seconds * 1000
            onFinished: if (storyViewer.progress >= 1) storyViewer.goNext()
        }

        contentItem: Item {
            // One story per page (driven by currentIndex; nav via the tap zones below).
            ListView {
                id: pager
                anchors.fill: parent
                orientation: ListView.Horizontal
                snapMode: ListView.SnapOneItem
                highlightRangeMode: ListView.StrictlyEnforceRange
                highlightMoveDuration: 150
                interactive: false
                model: viewerStories
                onCurrentIndexChanged: storyViewer.refreshCurrent()
                // Also covers a selection lost to a reset (see the Connections above).
                onCountChanged: if (storyViewer.visible) Qt.callLater(storyViewer.resync)

                delegate: Item {
                    width: pager.width
                    height: pager.height
                    readonly property bool isVideo: model.mime.indexOf("video") === 0
                    // Read by the overlay controls above the tap zones.
                    readonly property string storyPath: model.localPath
                    readonly property bool storyLoading: model.downloading
                    readonly property bool storyFailed: model.failed
                    readonly property bool mediaShown: isVideo || storyImage.status === Image.Ready
                    // Videos are downloaded when they come up (images are prefetched).
                    readonly property bool wantsFetch: ListView.isCurrentItem && storyViewer.visible
                        && model.localPath.length === 0 && !model.downloading && !model.failed
                    onWantsFetchChanged: if (wantsFetch) viewerStories.fetchMedia(index)
                    Component.onCompleted: if (wantsFetch) viewerStories.fetchMedia(index)

                    AnimatedImage {
                        id: storyImage
                        anchors.fill: parent
                        anchors.margins: 8
                        fillMode: Image.PreserveAspectFit
                        cache: false
                        playing: storyViewer.opened
                        visible: !isVideo && model.localPath.length > 0
                        source: (!isVideo && model.localPath.length > 0) ? "file:" + model.localPath : ""
                    }
                    Label {
                        textFormat: Text.PlainText
                        anchors.centerIn: parent
                        anchors.verticalCenterOffset: -70
                        visible: isVideo
                        text: "🎬"
                        font.pixelSize: 56
                        color: "white"
                    }
                    // Caption overlay.
                    Label {
                        textFormat: Text.PlainText
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        anchors.margins: 18
                        visible: model.title.length > 0
                        text: model.title
                        color: "white"
                        wrapMode: Text.Wrap
                        font.pixelSize: 14
                        style: Text.Outline
                        styleColor: "#80000000"
                    }
                }
            }

            // Navigation tap zones (above the pager): left third = previous, right = next.
            // Press and hold anywhere pauses.
            MouseArea {
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: parent.width * 0.33
                onClicked: storyViewer.goPrev()
                onPressAndHold: storyViewer.held = true
                onReleased: storyViewer.held = false
                onCanceled: storyViewer.held = false
            }
            MouseArea {
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: parent.width * 0.67
                onClicked: storyViewer.goNext()
                onPressAndHold: storyViewer.held = true
                onReleased: storyViewer.held = false
                onCanceled: storyViewer.held = false
            }

            // Loading / retry / play controls of the current story. Declared after (above) the
            // tap zones, so they get the clicks.
            ColumnLayout {
                id: storyControls
                anchors.centerIn: parent
                z: 6
                spacing: 10
                readonly property var cur: pager.currentItem
                readonly property bool ready: cur !== null && cur.storyPath.length > 0
                readonly property bool failed: cur !== null && !ready && cur.storyFailed
                BusyIndicator {
                    Layout.alignment: Qt.AlignHCenter
                    visible: storyControls.cur !== null && !storyControls.ready && !storyControls.failed
                    running: visible
                }
                Label {
                    textFormat: Text.PlainText
                    Layout.alignment: Qt.AlignHCenter
                    visible: storyControls.failed
                    text: qsTr("This story couldn't be loaded")
                    color: "white"
                }
                Button {
                    Layout.alignment: Qt.AlignHCenter
                    visible: storyControls.failed
                    text: qsTr("Retry")
                    onClicked: viewerStories.fetchMedia(pager.currentIndex)
                }
                Button {
                    Layout.alignment: Qt.AlignHCenter
                    visible: storyControls.ready && storyViewer.currentIsVideo
                    text: qsTr("▶ Play video")
                    font.pixelSize: 16
                    highlighted: true
                    onClicked: Qt.openUrlExternally("file://" + storyControls.cur.storyPath)
                }
            }

            // Segmented progress bars (one per story); the active one fills over 6s.
            Row {
                id: progressRow
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: 8
                spacing: 4
                Repeater {
                    model: viewerStories
                    delegate: Rectangle {
                        height: 3
                        radius: 1.5
                        color: Qt.rgba(1, 1, 1, 0.3)
                        width: (progressRow.width - Math.max(0, pager.count - 1) * 4) / Math.max(1, pager.count)
                        Rectangle {
                            height: parent.height
                            radius: 1.5
                            color: "white"
                            width: parent.width * (index < pager.currentIndex ? 1
                                                  : (index === pager.currentIndex
                                                     ? (storyViewer.currentIsVideo ? 1 : storyViewer.progress) : 0))
                        }
                    }
                }
            }

            // Header: publisher + age, delete (own), close — above the tap zones.
            RowLayout {
                anchors.top: progressRow.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: 8
                z: 5
                spacing: 8
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: pager.currentIndex < 0 ? ""
                          : (storyViewer.contact.toLowerCase() === window.accountJid.toLowerCase()
                             ? qsTr("My story") : storyViewer.contact.split('@')[0])
                            + " · " + window.agoText(storyViewer.currentPublished)
                    color: "white"
                    font.bold: true
                    elide: Text.ElideRight
                    style: Text.Outline
                    styleColor: "#80000000"
                }
                ToolButton {
                    visible: storyViewer.contact.toLowerCase() === window.accountJid.toLowerCase()
                             && pager.currentIndex >= 0
                    enabled: backend.connected
                    text: "🗑"
                    Material.foreground: "white"
                    ToolTip.text: qsTr("Delete story")
                    ToolTip.visible: hovered
                    onClicked: {
                        storyViewer.dialogOpen = true
                        storyDeleteDialog.uuid = storyViewer.uuid
                        storyDeleteDialog.open()
                    }
                }
                ToolButton {
                    text: "✕"
                    Material.foreground: "white"
                    onClicked: storyViewer.close()
                }
            }
        }
    }

    // --- Contact / group details (vCard4 + encryption keys) ---------------------
    Dialog {
        id: detailsDialog
        title: window.currentPeerIsMuc ? qsTr("Group details") : qsTr("Contact details")
        anchors.centerIn: parent
        modal: true
        width: Math.min(window.width - 80, 480)
        height: Math.min(window.height - 80, 640)
        standardButtons: Dialog.Close
        contentItem: ColumnLayout {
            spacing: 12
            RowLayout {
                Layout.fillWidth: true
                spacing: 12
                Avatar {
                    implicitWidth: 64
                    implicitHeight: 64
                    name: window.currentPeerName
                    avatarPath: window.currentPeerAvatar
                    presence: window.currentPeerIsMuc ? "" : window.currentPeerPresence
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 1
                    Label {
                        textFormat: Text.PlainText
                        text: window.currentPeerName
                        font.bold: true
                        font.pixelSize: 18
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                    Label {
                        textFormat: Text.PlainText
                        text: window.currentPeerJid
                        opacity: 0.6
                        font.pixelSize: 11
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }
                }
            }
            Flickable {
                FastScroll {}
                Layout.fillWidth: true
                Layout.fillHeight: true
                contentWidth: width
                contentHeight: detailsCol.implicitHeight
                clip: true
                ScrollBar.vertical: ThinScrollBar {}
                ColumnLayout {
                    id: detailsCol
                    width: parent.width
                    spacing: 8
                    // vCard4 fields (room name/description/occupants for a MUC).
                    Repeater {
                        model: window.detailsFields
                        delegate: ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label { textFormat: Text.PlainText; text: modelData.label; font.bold: true; font.pixelSize: 11; opacity: 0.65 }
                            Label {
                                textFormat: Text.PlainText
                                text: modelData.value
                                wrapMode: Text.Wrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                    Label {
                        textFormat: Text.PlainText
                        visible: window.detailsFields.length === 0
                        text: qsTr("No profile information yet…")
                        opacity: 0.6
                    }
                    // Presence subscriptions (1:1 only): the same two toggles as monocles chat
                    // Android — "Receive" = we see them (RFC 6121 to/both, sends subscribe/
                    // unsubscribe), "Send" = they see us (from/both, sends (un)subscribed).
                    MenuSeparator { Layout.fillWidth: true; visible: !window.currentPeerIsMuc }
                    Label {
                        textFormat: Text.PlainText
                        visible: !window.currentPeerIsMuc
                        text: qsTr("Presence")
                        font.bold: true
                        opacity: 0.8
                    }
                    RowLayout {
                        visible: !window.currentPeerIsMuc
                        Layout.fillWidth: true
                        spacing: 10
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 1
                            Label { textFormat: Text.PlainText; text: qsTr("Receive presence updates"); font.pixelSize: 13 }
                            Label {
                                textFormat: Text.PlainText
                                text: window.presAskPending
                                      ? qsTr("Requested — waiting for them to allow it")
                                      : qsTr("See when this contact is online")
                                font.pixelSize: 11
                                opacity: 0.6
                                wrapMode: Text.Wrap
                                Layout.fillWidth: true
                            }
                        }
                        Switch {
                            id: presReceiveSwitch
                            onToggled: backend.setSubscription(window.currentPeerJid,
                                                               checked ? "subscribe" : "unsubscribe")
                        }
                    }
                    RowLayout {
                        visible: !window.currentPeerIsMuc
                        Layout.fillWidth: true
                        spacing: 10
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 1
                            Label { textFormat: Text.PlainText; text: qsTr("Send presence updates"); font.pixelSize: 13 }
                            Label {
                                textFormat: Text.PlainText
                                text: qsTr("Let this contact see when you're online")
                                font.pixelSize: 11
                                opacity: 0.6
                                wrapMode: Text.Wrap
                                Layout.fillWidth: true
                            }
                        }
                        Switch {
                            id: presSendSwitch
                            onToggled: backend.setSubscription(window.currentPeerJid,
                                                               checked ? "subscribed" : "unsubscribed")
                        }
                    }
                    // Encryption keys (1:1 only) — verify/trust the contact's devices.
                    MenuSeparator { Layout.fillWidth: true; visible: !window.currentPeerIsMuc }
                    Label {
                        textFormat: Text.PlainText
                        visible: !window.currentPeerIsMuc
                        text: qsTr("Encryption keys")
                        font.bold: true
                        opacity: 0.8
                    }
                    Repeater {
                        model: window.currentPeerIsMuc ? 0 : contactDevices
                        delegate: RowLayout {
                            Layout.fillWidth: true
                            spacing: 10
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 1
                                Label {
                                    textFormat: Text.PlainText
                                    text: model.isOwn ? qsTr("This device")
                                        : (model.active ? qsTr("Device %1").arg(model.deviceId)
                                                        : qsTr("Device %1 (inactive)").arg(model.deviceId))
                                    font.bold: true
                                    font.pixelSize: 12
                                }
                                Label {
                                    textFormat: Text.PlainText
                                    Layout.fillWidth: true
                                    text: model.fingerprint
                                    font.family: "monospace"
                                    font.pixelSize: 10
                                    wrapMode: Text.WrapAnywhere
                                    opacity: 0.8
                                }
                            }
                            Switch {
                                visible: !model.isOwn
                                // 3 = manually verified (scanned code / verified call) is
                                // trusted too — it must not read as "off" and get downgraded
                                // to plain blind trust by a stray toggle.
                                checked: model.trust === 1 || model.trust === 3
                                onToggled: backend.setTrust(window.currentPeerJid, model.deviceId, checked ? 1 : 2)
                            }
                        }
                    }
                    // Out-of-band verification: paste the contact's verification link (the one
                    // behind their QR code — monocles Android can share it) and every device key
                    // in it that we hold is marked verified.
                    RowLayout {
                        visible: !window.currentPeerIsMuc
                        Layout.fillWidth: true
                        spacing: 8
                        TextField {
                            id: verifyLinkField
                            Layout.fillWidth: true
                            placeholderText: qsTr("Paste verification link (xmpp:…)")
                            onAccepted: verifyLinkButton.apply()
                        }
                        Button {
                            id: verifyLinkButton
                            text: qsTr("Verify")
                            enabled: verifyLinkField.text.length > 0
                            function apply() {
                                if (backend.verifyFromLink(window.currentPeerJid, verifyLinkField.text)) {
                                    verifyLinkField.text = ""
                                } else {
                                    window.toastText = qsTr("Not a verification link for this contact")
                                    toastTimer.restart()
                                }
                            }
                            onClicked: apply()
                        }
                    }
                }
            }
        }
    }

    // --- Remove-contact confirmation --------------------------------------------
    Dialog {
        id: removeContactDialog
        property string jid: ""
        property string name: ""
        title: qsTr("Remove contact")
        anchors.centerIn: parent
        modal: true
        width: 380
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: {
            backend.removeContact(removeContactDialog.jid)
            if (removeContactDialog.jid === window.currentPeerJid)
                window.currentPeerJid = ""
        }
        contentItem: Label {
            text: qsTr("Remove %1 from your contacts?\nThis cancels the presence subscription and deletes the local chat history.")
                    .arg(removeContactDialog.name.length > 0 ? removeContactDialog.name : removeContactDialog.jid)
            wrapMode: Text.Wrap
        }
    }

    // --- Full-size image viewer (tap a chat image) ------------------------------
    // Transient toast (bottom-center) — WebXDC notifications and similar passive feedback.
    Rectangle {
        visible: window.toastText.length > 0
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 24
        z: 1000
        radius: height / 2
        color: Qt.rgba(0, 0, 0, 0.8)
        width: toastLabel.implicitWidth + 32
        height: toastLabel.implicitHeight + 16
        Label {
            id: toastLabel
            textFormat: Text.PlainText
            anchors.centerIn: parent
            text: window.toastText
            color: "white"
        }
    }

    // Shared reactions picker: a quick-reaction row + the full Unicode emoji set. Re-anchored
    // to the hovered message's react button by `openReactPicker` (one instance app-wide).
    Popup {
        id: reactPickerGlobal
        property string targetMarker: ""
        width: 320
        height: 340
        padding: 6
        // Keep the popup on screen: open below the react button, flip above when the message
        // is near the bottom, and clamp into the window either way (QML Popups don't auto-flip).
        y: {
            if (!parent)
                return 0
            const top = parent.mapToItem(Overlay.overlay, 0, 0).y
            let gy = top + parent.height + 4
            if (gy + height > Overlay.overlay.height - 8)
                gy = top - height - 4
            gy = Math.max(8, Math.min(gy, Overlay.overlay.height - height - 8))
            return gy - top
        }
        x: {
            if (!parent)
                return 0
            const left = parent.mapToItem(Overlay.overlay, 0, 0).x
            const gx = Math.max(8, Math.min(left, Overlay.overlay.width - width - 8))
            return gx - left
        }

        function react(emoji) {
            backend.react(window.currentPeerJid, targetMarker, emoji)
            close()
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 4
            // Quick reactions (Android's first-row set).
            Row {
                Layout.alignment: Qt.AlignHCenter
                spacing: 4
                Repeater {
                    model: ["👍", "❤️", "😂", "😮", "😢", "🙏", "🎉", "🔥"]
                    delegate: Label {
                        text: modelData
                        font.family: "Noto Color Emoji"
                        font.pixelSize: 24
                        renderType: Text.NativeRendering
                        padding: 3
                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: reactPickerGlobal.react(modelData)
                        }
                    }
                }
            }
            MenuSeparator { Layout.fillWidth: true }
            // Everything else (recycled grid — ~1900 entries).
            GridView {
                FastScroll {}
                ScrollBar.vertical: ThinScrollBar {}
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                cellWidth: 34
                cellHeight: 34
                model: EmojiData.all
                delegate: Label {
                    width: 34
                    height: 34
                    text: modelData
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.family: "Noto Color Emoji"
                    font.pixelSize: 22
                    renderType: Text.NativeRendering
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: reactPickerGlobal.react(modelData)
                    }
                }
            }
        }
    }

    // Log-out confirmation: it also forgets the saved password (autologin stops working
    // until the next manual sign-in).
    Dialog {
        id: logoutDialog
        title: qsTr("Log out?")
        anchors.centerIn: parent
        modal: true
        width: 360
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: backend.logout()
        contentItem: Label {
            text: qsTr("This disconnects the account and removes the saved password from this device.")
            wrapMode: Text.Wrap
        }
    }

    // About: app identity, version, copyright, links and open-source license attributions —
    // mirrors the GTK client's AboutDialog. The app itself is GPLv3+, but it links the
    // AGPLv3 libsignal library, so the combined work carries the AGPL's obligations; AGPL
    // is shown as the headline license to reflect the shipped binary.
    Dialog {
        id: aboutDialog
        anchors.centerIn: parent
        modal: true
        width: 440
        height: Math.min(600, window.height - 64)
        standardButtons: Dialog.Close
        padding: 0

        contentItem: Flickable {
            contentWidth: width
            contentHeight: aboutColumn.implicitHeight + 32
            clip: true
            ScrollBar.vertical: ThinScrollBar {}

            ColumnLayout {
                id: aboutColumn
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: 24
                anchors.topMargin: 16
                spacing: 10

                // Brand wordmark lockup (same asset as the login page / Android main_logo).
                Image {
                    source: window.iconBase + "monocles-wordmark.svg"
                    fillMode: Image.PreserveAspectFit
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredWidth: 220
                    Layout.preferredHeight: 96
                    sourceSize.width: 440
                    sourceSize.height: 192
                }
                Label {
                    textFormat: Text.PlainText
                    text: "monocles chat"
                    font.pixelSize: 20
                    font.bold: true
                    Layout.alignment: Qt.AlignHCenter
                }
                // Version chip, like adw::AboutDialog's pill.
                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    radius: height / 2
                    color: Material.accent
                    implicitWidth: versionLabel.implicitWidth + 20
                    implicitHeight: versionLabel.implicitHeight + 8
                    Label {
                        id: versionLabel
                        textFormat: Text.PlainText
                        anchors.centerIn: parent
                        text: backend.appVersion
                        color: "white"
                        font.pixelSize: 12
                        font.bold: true
                    }
                }
                Label {
                    textFormat: Text.PlainText
                    text: qsTr("A native desktop client for monocles chat — XMPP messaging with PQ OMEMO2 (post-quantum) end-to-end encryption.")
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                    Layout.fillWidth: true
                    opacity: 0.8
                }
                Label {
                    textFormat: Text.PlainText
                    text: "© 2020–2026 Arne-Brün Vogelsang"
                    Layout.alignment: Qt.AlignHCenter
                    font.pixelSize: 12
                    opacity: 0.6
                }

                // Links: website, source, privacy policy.
                Label {
                    textFormat: Text.RichText
                    text: "<a href=\"https://monocles.eu/more/\">" + qsTr("Website") + "</a> · " +
                          "<a href=\"https://codeberg.org/monocles/monocles_chat_desktop\">" + qsTr("Source code") + "</a> · " +
                          "<a href=\"https://monocles.eu/legal-privacy/#policies-section\">" + qsTr("Privacy policy") + "</a>"
                    linkColor: Material.accent
                    onLinkActivated: link => Qt.openUrlExternally(link)
                    Layout.alignment: Qt.AlignHCenter
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                MenuSeparator { Layout.fillWidth: true }

                Label {
                    textFormat: Text.PlainText
                    text: qsTr("License")
                    font.bold: true
                }
                Label {
                    textFormat: Text.PlainText
                    text: qsTr("This application is licensed under the GNU GPL v3 or later. It bundles the AGPLv3 libsignal library, so the combined work is distributed under the terms of the GNU AGPL v3.")
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    font.pixelSize: 12
                    opacity: 0.8
                }

                Label {
                    textFormat: Text.PlainText
                    text: qsTr("Legal")
                    font.bold: true
                    Layout.topMargin: 6
                }
                Label {
                    textFormat: Text.RichText
                    text: "<b>libsignal</b> — © Signal Messenger, LLC · AGPLv3<br>" +
                          qsTr("PQ OMEMO2 / PQXDH cryptography") +
                          " · <a href=\"https://codeberg.org/monocles/pq-omemo-2\">codeberg.org/monocles/pq-omemo-2</a><br><br>" +
                          "<b>Qt</b> — © The Qt Company Ltd. and contributors · LGPLv3<br><br>" +
                          "<b>GStreamer</b> — © The GStreamer contributors · LGPL 2.1"
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    font.pixelSize: 12
                    opacity: 0.8
                    linkColor: Material.accent
                    onLinkActivated: link => Qt.openUrlExternally(link)
                }

                Label {
                    textFormat: Text.PlainText
                    text: qsTr("Built with")
                    font.bold: true
                    Layout.topMargin: 6
                }
                Label {
                    textFormat: Text.RichText
                    text: "CXX-Qt — <a href=\"https://github.com/KDAB/cxx-qt\">github.com/KDAB/cxx-qt</a><br>" +
                          "tokio-xmpp &amp; xmpp-parsers — <a href=\"https://gitlab.com/xmpp-rs/xmpp-rs\">gitlab.com/xmpp-rs/xmpp-rs</a><br>" +
                          "sqlx — <a href=\"https://github.com/launchbadge/sqlx\">github.com/launchbadge/sqlx</a><br>" +
                          "Tokio — <a href=\"https://tokio.rs\">tokio.rs</a>"
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    font.pixelSize: 12
                    opacity: 0.8
                    linkColor: Material.accent
                    onLinkActivated: link => Qt.openUrlExternally(link)
                }
            }
        }
    }

    // Settings — currently the chat-background chooser (more to come).
    Dialog {
        id: settingsDialog
        title: qsTr("Settings")
        anchors.centerIn: parent
        modal: true
        width: 380
        standardButtons: Dialog.Close
        // Camera picker options: [{name, path}] with "Automatic" first. Refreshed each open so
        // newly (un)plugged cameras show up.
        property var cameraOptions: []
        onOpened: {
            var arr = [{ name: qsTr("Automatic (recommended)"), path: "" }]
            try {
                var cams = JSON.parse(backend.cameraListJson())
                for (var i = 0; i < cams.length; i++)
                    arr.push(cams[i])
            } catch (e) {}
            settingsDialog.cameraOptions = arr
            var sel = 0
            for (var j = 0; j < arr.length; j++) {
                if (arr[j].path === backend.preferredCamera) { sel = j; break }
            }
            cameraCombo.currentIndex = sel
        }
        contentItem: ColumnLayout {
            spacing: 6
            Label {
                textFormat: Text.PlainText
                text: qsTr("Chat background")
                font.bold: true
            }
            // autoExclusive off: the visible state comes from the bound `checked`, and clicking
            // sets the persisted mode (which re-evaluates all three) — exactly one stays on.
            RadioButton {
                autoExclusive: false
                text: qsTr("Default monocles background")
                checked: backend.chatBgMode === "default"
                onClicked: backend.setChatBackgroundMode("default")
            }
            RadioButton {
                autoExclusive: false
                text: qsTr("None")
                checked: backend.chatBgMode === "none"
                onClicked: backend.setChatBackgroundMode("none")
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: 8
                RadioButton {
                    autoExclusive: false
                    text: qsTr("Custom image")
                    checked: backend.chatBgMode === "custom"
                    onClicked: {
                        backend.setChatBackgroundMode("custom")
                        if (backend.chatBgCustomPath.length === 0)
                            chatBgFileDialog.open()
                    }
                }
                Item { Layout.fillWidth: true }
                Button {
                    text: qsTr("Choose…")
                    enabled: backend.chatBgMode === "custom"
                    onClicked: chatBgFileDialog.open()
                }
            }
            Label {
                textFormat: Text.PlainText
                visible: backend.chatBgMode === "custom" && backend.chatBgCustomPath.length > 0
                Layout.fillWidth: true
                Layout.leftMargin: 12
                text: backend.chatBgCustomPath
                elide: Text.ElideMiddle
                opacity: 0.6
                font.pixelSize: 11
            }
            Rectangle {
                Layout.fillWidth: true
                Layout.topMargin: 6
                implicitHeight: 1
                color: Qt.rgba(0.5, 0.5, 0.5, 0.18)
            }
            // --- Camera (video calls) ---
            Label {
                textFormat: Text.PlainText
                text: qsTr("Camera")
                font.bold: true
            }
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: qsTr("Used for video calls. “Automatic” picks a working color camera and skips infrared / depth sensors.")
                wrapMode: Text.Wrap
                opacity: 0.6
                font.pixelSize: 11
            }
            ComboBox {
                id: cameraCombo
                Layout.fillWidth: true
                textRole: "name"
                valueRole: "path"
                model: settingsDialog.cameraOptions
                onActivated: backend.selectPreferredCamera(currentValue)
            }
            Rectangle {
                Layout.fillWidth: true
                Layout.topMargin: 6
                implicitHeight: 1
                color: Qt.rgba(0.5, 0.5, 0.5, 0.18)
            }
            Label {
                textFormat: Text.PlainText
                text: qsTr("More settings are coming soon.")
                opacity: 0.6
                font.pixelSize: 12
            }
        }
    }

    // Pick a custom chat-background image.
    FileDialog {
        id: chatBgFileDialog
        title: qsTr("Choose a chat background")
        nameFilters: [qsTr("Images (*.png *.jpg *.jpeg *.webp)")]
        onAccepted: {
            var p = selectedFile.toString().replace(/^file:\/\//, "")
            if (p.length > 0) {
                backend.setChatBackgroundImage(p)
                backend.setChatBackgroundMode("custom")
            }
        }
    }

    // Confirmation before turning OMEMO encryption off for the open chat — disabling means
    // messages from here on leave the device in cleartext. Abort (or dismissing) keeps it on.
    Dialog {
        id: disableEncryptionDialog
        title: qsTr("Disable encryption?")
        anchors.centerIn: parent
        modal: true
        width: 380
        contentItem: Label {
            text: qsTr("Messages in this chat will no longer be end-to-end encrypted. Anyone between you and %1 — including the servers — can read them.")
                  .arg(window.currentPeerName.length > 0 ? window.currentPeerName : window.currentPeerJid)
            wrapMode: Text.Wrap
        }
        footer: DialogButtonBox {
            Button {
                text: qsTr("Abort")
                flat: true
                DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
            }
            Button {
                text: qsTr("Disable encryption")
                flat: true
                highlighted: true
                Material.foreground: "#e01b24"
                DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            }
        }
        onAccepted: {
            window.currentPeerEncrypted = false
            msgModel.setEncryption(false)
        }
    }

    // XEP-0272 Muji: a member started a group call in a room we're in → one-tap join prompt.
    Dialog {
        id: groupCallInviteDialog
        title: qsTr("Group call")
        anchors.centerIn: parent
        modal: true
        width: 380
        closePolicy: Popup.NoAutoClose
        contentItem: Label {
            text: {
                var room = backend.conferenceInviteRoom.split('@')[0]
                var who = backend.conferenceInviteFrom
                return who.length > 0
                    ? qsTr("%1 started a group call in %2.").arg(who).arg(room)
                    : qsTr("A group call is in progress in %1.").arg(room)
            }
            wrapMode: Text.Wrap
        }
        footer: DialogButtonBox {
            Button {
                text: qsTr("Dismiss")
                flat: true
                onClicked: { backend.dismissGroupCallInvite(); groupCallInviteDialog.close() }
            }
            Button {
                text: qsTr("Join (video)")
                flat: true
                onClicked: { backend.joinGroupCall(true); groupCallInviteDialog.close() }
            }
            Button {
                text: qsTr("Join")
                flat: true
                highlighted: true
                onClicked: { backend.joinGroupCall(false); groupCallInviteDialog.close() }
            }
        }
        // Open when an invite arrives; close when it's cancelled (call ended / we joined).
        Connections {
            target: backend
            function onConferenceInviteRoomChanged() {
                if (backend.conferenceInviteRoom.length > 0)
                    groupCallInviteDialog.open()
                else
                    groupCallInviteDialog.close()
            }
        }
    }

    // RFC 6121 inbound presence-subscription request (Android's contact-request prompt):
    // Allow → `subscribed` (they see us); Decline / dismiss → `unsubscribed`. Asking to see
    // THEIR presence stays a separate step (the details dialog's "Receive" toggle), like
    // monocles chat Android.
    Dialog {
        id: subRequestDialog
        property string jid: ""
        property string nick: ""
        title: qsTr("Contact request")
        anchors.centerIn: parent
        modal: true
        width: 380
        contentItem: Label {
            text: qsTr("%1 would like to see when you're online.")
                  .arg(subRequestDialog.nick.length > 0
                       ? subRequestDialog.nick + " (" + subRequestDialog.jid + ")"
                       : subRequestDialog.jid)
            wrapMode: Text.Wrap
        }
        footer: DialogButtonBox {
            Button {
                text: qsTr("Decline")
                flat: true
                DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
            }
            Button {
                text: qsTr("Allow")
                flat: true
                highlighted: true
                DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            }
        }
        onAccepted: backend.setSubscription(jid, "subscribed")
        onRejected: backend.setSubscription(jid, "unsubscribed")
    }

    // WebXDC sendToChat confirmation. Everything shown comes from the (untrusted) app, so it is
    // rendered as plain text - rich text could disguise what is about to be sent.
    Dialog {
        id: webxdcSendDialog
        property string peer: ""
        property string fileName: ""
        property real fileSize: -1
        property string text: ""
        property bool answered: false
        function ask(p, name, size, t) {
            peer = p; fileName = name; fileSize = size; text = t; answered = false
            window.raise()
            window.requestActivate()
            open()
        }
        function sizeLabel(bytes) {
            if (bytes < 1024) return bytes + " B"
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB"
            return (bytes / (1024 * 1024)).toFixed(1) + " MB"
        }
        title: qsTr("Send from app?")
        anchors.centerIn: parent
        modal: true
        width: 420
        contentItem: ColumnLayout {
            spacing: 8
            Label {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                text: qsTr("A WebXDC app wants to send this to %1:").arg(webxdcSendDialog.peer)
            }
            Label {
                Layout.fillWidth: true
                visible: webxdcSendDialog.fileName.length > 0
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                font.bold: true
                text: qsTr("File: %1 (%2)").arg(webxdcSendDialog.fileName)
                      .arg(webxdcSendDialog.sizeLabel(webxdcSendDialog.fileSize))
            }
            Label {
                Layout.fillWidth: true
                visible: webxdcSendDialog.text.length > 0
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                maximumLineCount: 12
                elide: Text.ElideRight
                text: webxdcSendDialog.text.length > 600
                      ? webxdcSendDialog.text.substring(0, 600) + "…"
                      : webxdcSendDialog.text
            }
        }
        footer: DialogButtonBox {
            Button {
                text: qsTr("Cancel")
                flat: true
                DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
            }
            Button {
                text: qsTr("Send")
                flat: true
                highlighted: true
                DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            }
        }
        onAccepted: {
            if (answered) return
            answered = true
            backend.confirmWebxdcSend(true)
        }
        // Escape, clicking outside or Cancel: never sends. Deferred one turn so it can't beat
        // onAccepted whichever order Qt emits closed/accepted in for the Send button.
        onClosed: Qt.callLater(function() {
            if (!webxdcSendDialog.answered) {
                webxdcSendDialog.answered = true
                backend.confirmWebxdcSend(false)
            }
        })
    }

    // XEP-0424 retract confirmation (same wording as the GTK client) — deleting also asks
    // every other participant's client to delete its copy.
    Dialog {
        id: retractDialog
        property string targetMarker: ""
        function ask(marker) { targetMarker = marker; open() }
        title: qsTr("Delete message?")
        anchors.centerIn: parent
        modal: true
        width: 360
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: {
            if (targetMarker.length > 0)
                msgModel.retract(window.currentPeerJid, targetMarker)
            targetMarker = ""
        }
        contentItem: Label {
            text: qsTr("This asks everyone in the chat to delete it too, and can't be undone.")
            wrapMode: Text.Wrap
        }
    }

    Dialog {
        id: imageViewer
        property string path: ""
        anchors.centerIn: parent
        modal: true
        width: Math.min(window.width - 60, 900)
        height: Math.min(window.height - 60, 700)
        standardButtons: Dialog.Close
        contentItem: AnimatedImage {
            fillMode: Image.PreserveAspectFit
            playing: true
            cache: false
            source: imageViewer.path.length > 0 ? "file:" + imageViewer.path : ""
        }
    }

    // --- Feeds (XEP-0472): compose post, follow a feed, view a post + comments -----
    FileDialog {
        id: postAttachmentDialog
        title: qsTr("Attach a file")
        nameFilters: [qsTr("Media (*.png *.jpg *.jpeg *.gif *.webp *.mp4 *.m4v *.mov *.3gp *.webm *.mkv)"),
                      qsTr("All files (*)")]
        onAccepted: window.pendingPostAttachment = selectedFile.toString().replace(/^file:\/\//, "")
    }
    Dialog {
        id: newPostDialog
        title: window.editingPostId.length > 0 ? qsTr("Edit post") : qsTr("New post")
        anchors.centerIn: parent
        modal: true
        width: 440
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: {
            var title = newPostTitle.text.trim()
            var content = newPostContent.text.trim()
            var link = newPostLink.text.trim()
            var hasAttachment = window.pendingPostAttachment.length > 0 || window.editingPostAttachment.length > 0
            if (title.length > 0 || content.length > 0 || hasAttachment) {
                if (window.editingPostId.length > 0)
                    backend.editPost(window.editingPostId, title, content, window.pendingPostAttachment, link)
                else
                    backend.publishPost(title, content, window.pendingPostAttachment, link)
            }
            window.pendingPostAttachment = ""
            window.editingPostId = ""
        }
        contentItem: ColumnLayout {
            spacing: 8
            TextField {
                id: newPostTitle
                placeholderText: qsTr("Title (optional)")
                Layout.fillWidth: true
            }
            TextArea {
                id: newPostContent
                placeholderText: qsTr("What's on your mind? (Markdown and #hashtags work)")
                wrapMode: TextArea.Wrap
                Layout.fillWidth: true
                Layout.preferredHeight: 140
            }
            TextField {
                id: newPostLink
                placeholderText: qsTr("Link (optional)")
                inputMethodHints: Qt.ImhUrlCharactersOnly
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: window.pendingPostAttachment.length > 0 || window.editingPostAttachment.length > 0
                          ? qsTr("Replace attachment…") : qsTr("Attach…")
                    onClicked: postAttachmentDialog.open()
                }
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: window.pendingPostAttachment.length > 0
                          ? window.pendingPostAttachment.split('/').pop()
                          : decodeURIComponent(window.editingPostAttachment.split('/').pop())
                    elide: Text.ElideMiddle
                    opacity: 0.7
                }
                ToolButton {
                    visible: window.pendingPostAttachment.length > 0
                    text: "✕"
                    onClicked: window.pendingPostAttachment = ""
                }
            }
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                visible: window.pendingPostAttachment.length > 0
                text: qsTr("Location and device data are removed from photos and videos before upload.")
                wrapMode: Text.Wrap
                opacity: 0.6
                font.pixelSize: 11
            }
        }
    }
    Dialog {
        id: postDeleteDialog
        property string postId: ""
        title: qsTr("Delete post?")
        anchors.centerIn: parent
        modal: true
        standardButtons: Dialog.Yes | Dialog.No
        onAccepted: if (postId.length > 0) backend.retractPost(postId)
        Label { textFormat: Text.PlainText; text: qsTr("It will be removed for everyone who follows you.") }
    }
    Dialog {
        id: followDialog
        title: qsTr("Follow a feed")
        anchors.centerIn: parent
        modal: true
        width: 380
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: {
            if (followJidField.text.trim().length > 0)
                backend.followFeed(followJidField.text.trim())
            window.refreshFollowed()
        }
        contentItem: ColumnLayout {
            spacing: 8
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: qsTr("Enter the bare JID whose social feed you want to follow.")
                wrapMode: Text.Wrap
                opacity: 0.7
                font.pixelSize: 12
            }
            TextField {
                id: followJidField
                placeholderText: qsTr("user@example.org")
                inputMethodHints: Qt.ImhNoAutoUppercase
                Layout.fillWidth: true
            }
        }
    }
    Dialog {
        id: postDetailDialog
        anchors.centerIn: parent
        modal: true
        width: Math.min(window.width - 80, 600)
        height: Math.min(window.height - 80, 800)
        standardButtons: Dialog.Close
        title: window.feedPostTitle.length > 0 ? window.feedPostTitle
                                               : qsTr("%1's post").arg(window.feedPostAuthor.split('@')[0])
        // The title is the author's text: shown as plain text (the default header would
        // interpret markup, e.g. load remote images).
        header: Label {
            textFormat: Text.PlainText
            text: postDetailDialog.title
            font.bold: true
            font.pixelSize: 16
            elide: Text.ElideRight
            padding: 20
            bottomPadding: 0
        }
        contentItem: ColumnLayout {
            spacing: 8
            RowLayout {
                Layout.fillWidth: true
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: window.feedPostAuthor.split('@')[0] + " · " + window.agoText(window.feedPostPublished)
                    opacity: 0.6
                    font.pixelSize: 11
                }
                ToolButton {
                    // A link to a contacts-only post would only work for those who see it anyway.
                    visible: window.feedPostPublic
                    text: "🔗"
                    ToolTip.text: qsTr("Copy link to post")
                    ToolTip.visible: hovered
                    onClicked: {
                        window.copyText(backend.postUri(window.feedPostAuthor, window.feedPostId))
                        window.toastText = qsTr("Link copied")
                        toastTimer.restart()
                    }
                }
            }
            // The post and its comments scroll together (as on Android); only the reply field
            // below stays put, so it's reachable however large the post's image is.
            Flickable {
                id: postScroll
                FastScroll {}
                Layout.fillWidth: true
                Layout.fillHeight: true
                contentWidth: width
                contentHeight: postBodyColumn.implicitHeight
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ThinScrollBar {}
                // After sending a comment, follow the list down to it once it arrives.
                property bool followNewComment: false
                onContentHeightChanged: {
                    if (followNewComment && contentHeight > height) {
                        contentY = contentHeight - height
                        followNewComment = false
                    }
                }
                ColumnLayout {
                    id: postBodyColumn
                    // Leave room for the scroll bar.
                    width: postScroll.width - 10
                    spacing: 6
                    Label {
                        id: postBody
                        visible: window.feedPostContent.length > 0
                        Layout.fillWidth: true
                        text: window.feedPostHtml
                        textFormat: Text.RichText
                        wrapMode: Text.Wrap
                        onLinkActivated: (url) => window.openSafeUrl(url)
                    }
                    Image {
                        id: postImage
                        visible: window.feedPostAttachmentPath.length > 0
                        source: visible ? "file:" + window.feedPostAttachmentPath : ""
                        Layout.fillWidth: true
                        // At most half the visible area, so the comments start on screen; click
                        // for the full image.
                        Layout.preferredHeight: visible && implicitWidth > 0
                            ? Math.min(postScroll.height * 0.5, width * implicitHeight / implicitWidth) : 0
                        fillMode: Image.PreserveAspectFit
                        horizontalAlignment: Image.AlignLeft
                        asynchronous: true
                        cache: true
                        sourceSize.width: 1200
                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: { imageViewer.path = window.feedPostAttachmentPath; imageViewer.open() }
                        }
                    }
                    Label {
                        id: postFile
                        visible: window.feedPostAttachmentUrl.length > 0 && window.feedPostAttachmentPath.length === 0
                        Layout.fillWidth: true
                        text: "<a href=\"" + window.feedPostAttachmentUrl.replace(/"/g, "%22") + "\">"
                              + (window.feedPostAttachmentType.indexOf("video") === 0 ? "🎬 " : "📎 ")
                              + qsTr("Open attachment") + "</a>"
                        textFormat: Text.StyledText
                        onLinkActivated: (url) => window.openSafeUrl(url)
                    }
                    Label {
                        id: postLink
                        visible: window.feedPostLink.length > 0
                        Layout.fillWidth: true
                        text: "🔗 <a href=\"" + window.feedPostLink.replace(/"/g, "%22") + "\">"
                              + window.feedPostLink.replace(/&/g, "&amp;").replace(/</g, "&lt;") + "</a>"
                        textFormat: Text.StyledText
                        elide: Text.ElideRight
                        onLinkActivated: (url) => window.openSafeUrl(url)
                    }
                    // Heart "like" (a "♥" comment, as in the list and on Android).
                    ToolButton {
                        visible: window.feedPostCanComment
                        enabled: backend.connected
                        text: (window.feedPostLiked ? "♥ " : "♡ ") + window.feedPostLikes
                        font.pixelSize: 15
                        Material.foreground: window.feedPostLiked ? "#e0245e" : window.Material.foreground
                        ToolTip.text: window.feedPostLiked ? qsTr("Unlike") : qsTr("Like")
                        ToolTip.visible: hovered
                        onClicked: backend.toggleLike(window.feedPostAuthor, window.feedPostId)
                    }
                    MenuSeparator { Layout.fillWidth: true }
                    Label {
                        textFormat: Text.PlainText
                        text: window.feedPostCanComment
                              ? qsTr("Comments (%1)").arg(commentRepeater.count)
                              : qsTr("This post doesn't accept comments")
                        font.bold: window.feedPostCanComment
                        opacity: 0.8
                    }
                    Repeater {
                        id: commentRepeater
                        model: commentModel
                        delegate: ItemDelegate {
                            Layout.fillWidth: true
                            contentItem: ColumnLayout {
                                spacing: 0
                                RowLayout {
                                    Layout.fillWidth: true
                                    Label {
                                        textFormat: Text.PlainText
                                        text: model.own ? qsTr("Me") : model.author.split('@')[0]
                                        font.bold: true
                                        font.pixelSize: 12
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                    Label { textFormat: Text.PlainText; text: window.agoText(model.published); opacity: 0.5; font.pixelSize: 10 }
                                    ToolButton {
                                        visible: (model.own || window.feedPostOwn) && backend.connected
                                        text: "✕"
                                        implicitWidth: 24
                                        implicitHeight: 24
                                        ToolTip.text: qsTr("Delete comment")
                                        ToolTip.visible: hovered
                                        onClicked: backend.retractComment(window.feedPostAuthor, window.feedPostId, model.postId)
                                    }
                                }
                                Label {
                                    text: model.contentHtml
                                    textFormat: Text.RichText
                                    wrapMode: Text.Wrap
                                    font.pixelSize: 12
                                    Layout.fillWidth: true
                                    onLinkActivated: (url) => window.openSafeUrl(url)
                                }
                            }
                        }
                    }
                    Label {
                        textFormat: Text.PlainText
                        Layout.alignment: Qt.AlignHCenter
                        Layout.topMargin: 8
                        visible: commentRepeater.count === 0 && window.feedPostCanComment
                        text: qsTr("No comments yet")
                        opacity: 0.6
                    }
                }
            }
            RowLayout {
                Layout.fillWidth: true
                visible: window.feedPostCanComment
                spacing: 6
                TextField {
                    id: replyField
                    Layout.fillWidth: true
                    placeholderText: qsTr("Write a comment…")
                    onAccepted: sendReplyBtn.clicked()
                }
                Button {
                    id: sendReplyBtn
                    text: qsTr("Reply")
                    enabled: backend.connected && replyField.text.trim().length > 0
                    onClicked: {
                        backend.publishComment(window.feedPostAuthor, window.feedPostId, replyField.text.trim())
                        replyField.clear()
                        postScroll.followNewComment = true
                    }
                }
            }
        }
    }

    // --- Contact OMEMO2 keys (verify / trust) dialog ------------------------------
    Dialog {
        id: keysDialog
        title: qsTr("Encryption keys")
        anchors.centerIn: parent
        modal: true
        width: 460
        standardButtons: Dialog.Close
        contentItem: ColumnLayout {
            spacing: 8
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: qsTr("Compare these fingerprints with %1 over a trusted channel. Turn a device off to stop encrypting to it.").arg(window.currentPeerName)
                wrapMode: Text.Wrap
                opacity: 0.7
                font.pixelSize: 12
            }
            ListView {
                FastScroll {}
                ScrollBar.vertical: ThinScrollBar {}
                id: keysList
                Layout.fillWidth: true
                Layout.preferredHeight: Math.min(380, Math.max(40, contentHeight))
                clip: true
                spacing: 10
                model: contactDevices
                delegate: deviceRow
            }
            Label {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                visible: keysList.count === 0
                text: qsTr("No devices seen yet — send a message first to fetch their keys.")
                wrapMode: Text.Wrap
                opacity: 0.6
            }
        }
    }

    // --- My OMEMO2 keys + blind-trust setting dialog ------------------------------
    Dialog {
        id: ownKeysDialog
        title: qsTr("My profile")
        anchors.centerIn: parent
        modal: true
        // Stay within the window so the footer (Close) and the body's bottom (the reset button)
        // are always reachable; the body scrolls when the window is short.
        width: Math.min(460, (parent ? parent.width : 460) - 24)
        height: Math.min(implicitHeight, (parent ? parent.height : 700) - 48)
        standardButtons: Dialog.Close

        // Availability values matching the ComboBox order (RFC 6121 <show/>; "" = online).
        readonly property var showValues: ["", "chat", "away", "xa", "dnd"]
        // Cached own-avatar path; refreshed when the published photo round-trips.
        property string ownAvatarPath: ""
        function applyPresence() {
            backend.setPresence(showValues[ownShowBox.currentIndex], ownStatusField.text)
        }
        // Load the current values when opening; OwnKeys refreshes the backend properties.
        onOpened: {
            ownShowBox.currentIndex = Math.max(0, showValues.indexOf(backend.ownShow))
            ownStatusField.text = backend.ownStatus
            ownNickField.text = backend.ownNick
            ownAvatarPath = backend.avatarPathFor(window.accountJid)
            backend.fetchNick(window.accountJid)
        }
        Connections {
            target: backend
            function onOwnShowChanged() {
                if (ownKeysDialog.visible)
                    ownShowBox.currentIndex = Math.max(0, ownKeysDialog.showValues.indexOf(backend.ownShow))
            }
            function onOwnStatusChanged() {
                if (ownKeysDialog.visible && !ownStatusField.activeFocus)
                    ownStatusField.text = backend.ownStatus
            }
            function onOwnNickChanged() {
                if (ownKeysDialog.visible && !ownNickField.activeFocus)
                    ownNickField.text = backend.ownNick
            }
            // A (re)published avatar arrives back as a cached file → repaint the preview.
            function onConversationsChanged() {
                if (ownKeysDialog.visible)
                    ownKeysDialog.ownAvatarPath = backend.avatarPathFor(window.accountJid)
            }
        }

        contentItem: ScrollView {
            id: ownKeysScroll
            clip: true
            // Only ever scroll vertically; the body lays out to the available width.
            contentWidth: availableWidth
            ColumnLayout {
            width: ownKeysScroll.availableWidth
            spacing: 10
            // Who we are: click the avatar (or the camera chip) to publish a new photo.
            RowLayout {
                Layout.fillWidth: true
                spacing: 12
                Item {
                    implicitWidth: 56
                    implicitHeight: 56
                    Avatar {
                        anchors.fill: parent
                        name: backend.ownNick.length > 0 ? backend.ownNick : window.accountJid
                        avatarPath: ownKeysDialog.ownAvatarPath
                        presence: ownKeysDialog.showValues[ownShowBox.currentIndex] === "" ? "online"
                                : ownKeysDialog.showValues[ownShowBox.currentIndex]
                    }
                    // Camera chip, bottom-left (the presence dot owns bottom-right).
                    Rectangle {
                        anchors.left: parent.left
                        anchors.bottom: parent.bottom
                        width: 20
                        height: 20
                        radius: 10
                        color: Material.accent
                        Label { textFormat: Text.PlainText; anchors.centerIn: parent; text: "📷"; font.pixelSize: 10; font.family: "Noto Color Emoji"; renderType: Text.NativeRendering }
                    }
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: avatarFileDialog.open()
                    }
                    ToolTip.text: qsTr("Change profile photo")
                    ToolTip.visible: avatarHover.hovered
                    HoverHandler { id: avatarHover }
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 1
                    Label {
                        textFormat: Text.PlainText
                        text: backend.ownNick.length > 0 ? backend.ownNick
                                                         : window.accountJid.split("@")[0]
                        font.bold: true
                        font.pixelSize: 17
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                    Label {
                        textFormat: Text.PlainText
                        text: window.accountJid
                        opacity: 0.6
                        font.pixelSize: 11
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }
                }
            }
            // Display name, published to contacts (XEP-0172).
            TextField {
                id: ownNickField
                Layout.fillWidth: true
                placeholderText: qsTr("Display name (Enter to apply)")
                onAccepted: backend.setNick(text)
                onEditingFinished: backend.setNick(text)
            }
            MenuSeparator { Layout.fillWidth: true }

            // Status: availability + free-text message, broadcast to all contacts.
            Label { textFormat: Text.PlainText; text: qsTr("Status"); font.bold: true; opacity: 0.8 }
            ComboBox {
                id: ownShowBox
                Layout.fillWidth: true
                model: [qsTr("Online"), qsTr("Free to chat"), qsTr("Away"),
                        qsTr("Extended away"), qsTr("Do not disturb")]
                onActivated: ownKeysDialog.applyPresence()
            }
            TextField {
                id: ownStatusField
                Layout.fillWidth: true
                placeholderText: qsTr("Status message (Enter to apply)")
                onAccepted: ownKeysDialog.applyPresence()
                onEditingFinished: ownKeysDialog.applyPresence()
            }
            MenuSeparator { Layout.fillWidth: true }

            Label { textFormat: Text.PlainText; text: qsTr("Encryption"); font.bold: true; opacity: 0.8 }
            // Blind-trust toggle (XEP-0384 trust management).
            RowLayout {
                Layout.fillWidth: true
                spacing: 10
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 1
                    Label { textFormat: Text.PlainText; text: qsTr("Auto-trust new keys"); font.bold: true }
                    Label {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        text: qsTr("Automatically trust new devices (blind trust). Turn off to approve each device manually.")
                        wrapMode: Text.Wrap
                        opacity: 0.6
                        font.pixelSize: 11
                    }
                }
                Switch {
                    checked: backend.autoTrust
                    onToggled: backend.toggleAutoTrust(checked)
                }
            }
            MenuSeparator { Layout.fillWidth: true; visible: verificationCode.visible }
            // Our own verification code: the same xmpp: URI monocles Android puts in its QR,
            // so a contact can scan this device's key off the screen instead of comparing the
            // fingerprint by hand. Drawn from the module matrix — no image plugin involved.
            ColumnLayout {
                id: verificationCode
                Layout.fillWidth: true
                spacing: 6
                visible: backend.ownVerificationUri !== ""
                Label { textFormat: Text.PlainText; text: qsTr("Verification code"); font.bold: true }
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: qsTr("Let a contact scan this in monocles chat to verify this device's key. The same key, as a link, is below.")
                    wrapMode: Text.Wrap
                    opacity: 0.6
                    font.pixelSize: 11
                }
                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    // Always light: a QR needs dark-on-light contrast to scan, whatever the
                    // app theme is doing.
                    color: "white"
                    radius: 4
                    width: 232
                    height: 232
                    Canvas {
                        id: ownQrCanvas
                        anchors.fill: parent
                        anchors.margins: 8
                        // "<size>:<0/1 per module, row-major>", empty when not encodable.
                        property string matrix: backend.qrMatrix(backend.ownVerificationUri)
                        onMatrixChanged: requestPaint()
                        onPaint: {
                            var ctx = getContext("2d")
                            ctx.reset()
                            ctx.fillStyle = "white"
                            ctx.fillRect(0, 0, width, height)
                            var sep = matrix.indexOf(":")
                            if (sep < 1)
                                return
                            var size = parseInt(matrix.substring(0, sep))
                            var bits = matrix.substring(sep + 1)
                            if (!size || bits.length < size * size)
                                return
                            var scale = width / size
                            ctx.fillStyle = "black"
                            for (var y = 0; y < size; ++y) {
                                for (var x = 0; x < size; ++x) {
                                    if (bits.charAt(y * size + x) === "1")
                                        // Round outward so neighbouring modules never leave a
                                        // hairline gap the scanner reads as a light module.
                                        ctx.fillRect(Math.floor(x * scale), Math.floor(y * scale),
                                                     Math.ceil(scale), Math.ceil(scale))
                                }
                            }
                        }
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8
                    TextArea {
                        id: ownVerificationLink
                        Layout.fillWidth: true
                        text: backend.ownVerificationUri
                        readOnly: true
                        wrapMode: TextArea.WrapAnywhere
                        font.family: "monospace"
                        font.pixelSize: 10
                    }
                    Button {
                        text: qsTr("Copy")
                        onClicked: {
                            ownVerificationLink.selectAll()
                            ownVerificationLink.copy()
                            ownVerificationLink.deselect()
                            window.toastText = qsTr("Verification link copied")
                            toastTimer.restart()
                        }
                    }
                }
            }
            MenuSeparator { Layout.fillWidth: true }
            ListView {
                id: ownKeysList
                Layout.fillWidth: true
                // Lay out all rows at full height; the dialog's ScrollView does the scrolling
                // (a nested interactive list would fight it and could still hide the button).
                Layout.preferredHeight: contentHeight
                interactive: false
                clip: true
                spacing: 10
                model: ownDevices
                delegate: deviceRow
            }
            // Verify our OTHER devices (e.g. monocles on a phone) from their verification link.
            RowLayout {
                Layout.fillWidth: true
                spacing: 8
                TextField {
                    id: ownVerifyLinkField
                    Layout.fillWidth: true
                    placeholderText: qsTr("Paste another device's verification link (xmpp:…)")
                    onAccepted: ownVerifyLinkButton.apply()
                }
                Button {
                    id: ownVerifyLinkButton
                    text: qsTr("Verify")
                    enabled: ownVerifyLinkField.text.length > 0
                    function apply() {
                        if (backend.verifyFromLink(window.accountJid, ownVerifyLinkField.text)) {
                            ownVerifyLinkField.text = ""
                        } else {
                            window.toastText = qsTr("Not a verification link for this account")
                            toastTimer.restart()
                        }
                    }
                    onClicked: apply()
                }
            }
            MenuSeparator { Layout.fillWidth: true }
            // Recovery action for stale OMEMO2 state (e.g. after a key migration): forget all
            // stored peer keys/sessions and rebuild them on the next exchange. Our own key is kept.
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Label { textFormat: Text.PlainText; text: qsTr("Reset encryption keys"); font.bold: true }
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: qsTr("Forget all stored contact device keys and sessions and rebuild them as you exchange messages. Your own key (fingerprint) is kept. Use this only if encryption gets stuck.")
                    wrapMode: Text.Wrap
                    opacity: 0.6
                    font.pixelSize: 11
                }
                Button {
                    text: qsTr("Reset PQ OMEMO2 identities")
                    onClicked: resetOmemoConfirm.open()
                }
            }
            MenuSeparator { Layout.fillWidth: true }
            // LAST RESORT (suspected key compromise): regenerate our OWN hybrid identity —
            // new key pairs, new device id, NEW FINGERPRINT. Contacts must re-verify us.
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Label { textFormat: Text.PlainText; text: qsTr("Regenerate own identity (last resort)"); font.bold: true; color: "#d32f2f" }
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: qsTr("Generate a completely new encryption identity for this device. Your fingerprint changes and all your contacts have to verify you again. Use this only if you suspect your keys were compromised.")
                    wrapMode: Text.Wrap
                    opacity: 0.6
                    font.pixelSize: 11
                }
                Button {
                    text: qsTr("Regenerate own identity")
                    onClicked: regenerateOmemoConfirm.open()
                }
            }
            }
        }
    }

    // Confirm before wiping cached OMEMO2 peer state.
    Dialog {
        id: resetOmemoConfirm
        title: qsTr("Reset PQ OMEMO2 identities?")
        anchors.centerIn: parent
        modal: true
        width: 420
        standardButtons: Dialog.Cancel | Dialog.Ok
        contentItem: Label {
            text: qsTr("This forgets all stored contact device keys and sessions. They rebuild automatically as you exchange messages. Your own identity and fingerprint are unchanged.")
            wrapMode: Text.Wrap
        }
        onAccepted: backend.resetOmemo2Identities()
    }

    // Confirm before the LAST-RESORT own-identity regeneration (fingerprint changes!).
    Dialog {
        id: regenerateOmemoConfirm
        title: qsTr("Regenerate own identity?")
        anchors.centerIn: parent
        modal: true
        width: 420
        standardButtons: Dialog.Cancel | Dialog.Ok
        contentItem: Label {
            text: qsTr("This PERMANENTLY deletes this device's encryption identity and generates a new one. Your fingerprint changes — all your contacts have to verify you again — and stored contact keys and sessions are wiped too. Only use this as a last resort, e.g. on suspected key compromise.")
            wrapMode: Text.Wrap
        }
        onAccepted: backend.regenerateOmemo2Identity()
    }

    // Shared device row: name + fingerprint + a trust switch (hidden for *this* device).
    // `isOwn` here means "this very device"; both dialogs reuse it, sending trust changes to
    // the right JID (the open peer for the contact dialog, our account for the own dialog).
    Component {
        id: deviceRow
        RowLayout {
            width: ListView.view ? ListView.view.width : implicitWidth
            spacing: 10
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Label {
                    textFormat: Text.PlainText
                    text: model.isOwn ? qsTr("This device")
                        : (model.active ? qsTr("Device %1").arg(model.deviceId)
                                        : qsTr("Device %1 (inactive)").arg(model.deviceId))
                    font.bold: true
                }
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: model.fingerprint
                    font.family: "monospace"
                    font.pixelSize: 11
                    wrapMode: Text.WrapAnywhere
                    opacity: 0.85
                }
            }
            Switch {
                visible: !model.isOwn
                // 3 = manually verified counts as on; otherwise a verified key would show as
                // disabled and a stray toggle would downgrade it to plain blind trust.
                checked: model.trust === 1 || model.trust === 3
                ToolTip.text: qsTr("Encrypt to / accept from this device")
                ToolTip.visible: hovered
                onToggled: {
                    var jid = (ownKeysDialog.visible ? window.accountJid : window.currentPeerJid)
                    backend.setTrust(jid, model.deviceId, checked ? 1 : 2)
                }
            }
        }
    }

    // --- 1:1 call screen (JMI/Jingle) — its own resizable top-level window, opened
    // automatically on call activity. Closing it (✕) hangs up.
    Window {
        id: callDialog
        width: 480
        height: backend.callVideo ? 600 : 440
        minimumWidth: 380
        minimumHeight: 360
        title: backend.callPeer.length > 0 ? backend.callPeer : qsTr("Call")
        color: window.Material.background
        Material.theme: window.Material.theme
        Material.primary: window.Material.primary
        Material.accent: window.Material.accent

        // Active-call duration (seconds) + local mute / camera state.
        property int seconds: 0
        property bool localMuted: false
        property bool localCameraOn: true
        function fmt(s) {
            var m = Math.floor(s / 60), ss = s % 60
            return (m < 10 ? "0" : "") + m + ":" + (ss < 10 ? "0" : "") + ss
        }
        function toggleFullscreen() {
            callDialog.visibility = callDialog.visibility === Window.FullScreen
                                    ? Window.Windowed : Window.FullScreen
        }

        // Closing via the window manager (✕) ends the call.
        onClosing: {
            if (backend.callActive)
                backend.hangUpCall()
        }
        Shortcut {
            sequence: "Esc"
            enabled: callDialog.visibility === Window.FullScreen
            onActivated: callDialog.visibility = Window.Windowed
        }

        Connections {
            target: backend
            function onCallActiveChanged() {
                if (backend.callActive) {
                    callDialog.localMuted = false
                    callDialog.localCameraOn = true
                    callDialog.seconds = 0
                    callDialog.visibility = Window.Windowed
                    callDialog.show()
                    callDialog.raise()
                    callDialog.requestActivate()
                } else {
                    callTimer.stop()
                    callDialog.hide()
                }
            }
            function onCallStateChanged() {
                if (backend.callState === "active") {
                    callDialog.seconds = 0
                    callTimer.restart()
                }
            }
        }
        Timer { id: callTimer; interval: 1000; repeat: true; onTriggered: callDialog.seconds++ }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 12
            spacing: 12

            // Video surfaces (video calls) or a big avatar (audio calls) — grows with the window.
            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true

                Rectangle {
                    anchors.fill: parent
                    visible: backend.callVideo
                    color: "black"
                    radius: 8
                    clip: true
                    Image {
                        anchors.fill: parent
                        fillMode: Image.PreserveAspectFit
                        cache: false
                        // Decode off the UI thread and keep the current frame on screen until the
                        // next one is ready — avoids the blank-flash flicker when swapping source.
                        asynchronous: true
                        retainWhileLoading: true
                        source: backend.remoteFrame
                        visible: backend.remoteFrame.length > 0
                    }
                    Label {
                        textFormat: Text.PlainText
                        anchors.centerIn: parent
                        visible: backend.remoteFrame.length === 0
                        text: qsTr("Waiting for video…")
                        color: "white"
                        opacity: 0.7
                    }
                    // Local camera preview, bottom-right (hidden while our camera is off).
                    Image {
                        width: 140
                        height: 105
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        anchors.margins: 8
                        fillMode: Image.PreserveAspectCrop
                        cache: false
                        // Off-thread decode + keep the current frame until the next is ready.
                        asynchronous: true
                        retainWhileLoading: true
                        source: backend.localFrame
                        visible: callDialog.localCameraOn && backend.localFrame.length > 0
                    }
                    // "Camera off" chip where the local preview would be, bottom-right.
                    Rectangle {
                        width: 140
                        height: 105
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        anchors.margins: 8
                        radius: 6
                        color: Qt.rgba(1, 1, 1, 0.08)
                        visible: backend.callState === "active" && !callDialog.localCameraOn
                        ColumnLayout {
                            anchors.centerIn: parent
                            spacing: 4
                            ColorIcon {
                                Layout.alignment: Qt.AlignHCenter
                                implicitWidth: 22
                                implicitHeight: 22
                                source: window.iconBase + "videocam-off.svg"
                                color: "white"
                            }
                            Label {
                                textFormat: Text.PlainText
                                Layout.alignment: Qt.AlignHCenter
                                text: qsTr("Camera off")
                                color: "white"
                                opacity: 0.7
                                font.pixelSize: 11
                            }
                        }
                    }
                }

                Avatar {
                    anchors.centerIn: parent
                    visible: !backend.callVideo
                    implicitWidth: 96
                    implicitHeight: 96
                    name: backend.callPeer
                    avatarPath: ""
                    presence: ""
                }
            }

            Label {
                textFormat: Text.PlainText
                Layout.alignment: Qt.AlignHCenter
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                text: backend.callPeer
                font.bold: true
                font.pixelSize: 18
                elide: Text.ElideRight
            }
            Label {
                textFormat: Text.PlainText
                Layout.alignment: Qt.AlignHCenter
                opacity: 0.7
                text: backend.callState === "incoming"
                        ? qsTr("Incoming %1 call…").arg(backend.callVideo ? qsTr("video") : qsTr("audio"))
                    : backend.callState === "outgoing" ? qsTr("Calling…")
                    : backend.callState === "connecting" ? qsTr("Connecting…")
                    : backend.callState === "active" ? qsTr("On call · ") + callDialog.fmt(callDialog.seconds)
                    : ""
            }

            // PQ OMEMO2 call trust indicator (the DTLS was authenticated via OMEMO2, MITM-protected
            // like the Android client). callTrust: 1 = BTBV-trusted → lock; 2 = manually verified
            // → shield. A "Verify" action upgrades a trusted key to verified.
            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: 6
                visible: backend.callTrust > 0
                readonly property bool callVerified: backend.callTrust >= 2
                readonly property color trustColor: callVerified ? "#2e9d4f" : "#3a7bd5"
                ColorIcon {
                    implicitWidth: 16
                    implicitHeight: 16
                    source: window.iconBase + (parent.callVerified ? "verified.svg" : "lock-omemo2.svg")
                    color: parent.trustColor
                }
                Label {
                    textFormat: Text.PlainText
                    text: parent.callVerified ? qsTr("Verified · PQ OMEMO2")
                                              : qsTr("Encrypted · PQ OMEMO2")
                    color: parent.trustColor
                    font.pixelSize: 12
                    ToolTip.text: backend.callVerifiedFp.length > 0
                                  ? qsTr("Peer key: ") + backend.callVerifiedFp : ""
                    ToolTip.visible: hovered && backend.callVerifiedFp.length > 0
                    HoverHandler { id: shieldHover }
                    property bool hovered: shieldHover.hovered
                }
                // Offer manual verification (compare fingerprints out-of-band) when the call is
                // only BTBV-trusted; upgrades the key to verified (shield) for this and future use.
                Button {
                    visible: backend.callTrust === 1 && backend.callVerifiedDevice !== 0
                    flat: true
                    font.pixelSize: 11
                    topPadding: 2; bottomPadding: 2
                    text: qsTr("Verify")
                    onClicked: backend.verifyCallKey()
                    ToolTip.text: qsTr("Mark this peer's PQ OMEMO2 key as manually verified")
                    ToolTip.visible: hovered
                }
            }

            // Incoming video-upgrade consent prompt (peer wants to enable video).
            Pane {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignHCenter
                visible: backend.callVideoRequest
                Material.background: Qt.darker(window.Material.background, 1.15)
                padding: 10
                contentItem: ColumnLayout {
                    spacing: 8
                    Label {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                        text: qsTr("%1 wants to turn on video").arg(backend.callPeer)
                        font.bold: true
                    }
                    RowLayout {
                        Layout.alignment: Qt.AlignHCenter
                        spacing: 10
                        Button {
                            text: qsTr("Decline")
                            flat: true
                            onClicked: backend.declineVideoUpgrade()
                        }
                        Button {
                            text: qsTr("Accept")
                            highlighted: true
                            onClicked: backend.acceptVideoUpgrade()
                        }
                    }
                }
            }

            // Controls — vary by state.
            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 4
                spacing: 18

                // Mute (active call only): red while muted, so the state is unmistakable.
                RoundButton {
                    id: muteBtn
                    visible: backend.callState === "active"
                    checkable: true
                    checked: callDialog.localMuted
                    Material.background: checked ? "#c62828" : undefined
                    ToolTip.text: checked ? qsTr("Unmute microphone") : qsTr("Mute microphone")
                    ToolTip.visible: hovered
                    onToggled: { callDialog.localMuted = checked; backend.setCallMute(checked) }
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + "mic-off.svg"
                        color: muteBtn.checked ? "white" : Material.foreground
                    }
                }

                // Switch to video (active audio calls only) — upgrades the call to video.
                RoundButton {
                    visible: backend.callState === "active" && !backend.callVideo
                    ToolTip.text: qsTr("Switch to video")
                    ToolTip.visible: hovered
                    onClicked: backend.upgradeCallToVideo()
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + "videocam.svg"
                        color: Material.foreground
                    }
                }

                // Camera on/off (active video calls only): red while off.
                RoundButton {
                    id: camBtn
                    visible: backend.callState === "active" && backend.callVideo
                    checkable: true
                    checked: !callDialog.localCameraOn
                    Material.background: checked ? "#c62828" : undefined
                    ToolTip.text: checked ? qsTr("Turn camera on") : qsTr("Turn camera off")
                    ToolTip.visible: hovered
                    onToggled: {
                        callDialog.localCameraOn = !checked
                        backend.setCallCamera(callDialog.localCameraOn)
                    }
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + (camBtn.checked ? "videocam-off.svg" : "videocam.svg")
                        color: camBtn.checked ? "white" : Material.foreground
                    }
                }

                // Screen share (active calls): the shared screen replaces the camera as our video
                // (an audio call is upgraded to video first). Green while sharing.
                RoundButton {
                    id: shareBtn
                    visible: backend.callState === "active"
                    checkable: true
                    checked: backend.callScreenSharing
                    Material.background: checked ? "#2e7d32" : undefined
                    ToolTip.text: checked ? qsTr("Stop sharing screen") : qsTr("Share screen")
                    ToolTip.visible: hovered
                    onToggled: backend.setCallScreenShare(checked)
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + (shareBtn.checked ? "screen-share-off.svg" : "screen-share.svg")
                        color: shareBtn.checked ? "white" : Material.foreground
                    }
                }

                // Full screen (most useful on video calls; Esc leaves it too).
                RoundButton {
                    id: fsBtn
                    readonly property bool fs: callDialog.visibility === Window.FullScreen
                    ToolTip.text: fs ? qsTr("Exit full screen") : qsTr("Full screen")
                    ToolTip.visible: hovered
                    onClicked: callDialog.toggleFullscreen()
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + (fsBtn.fs ? "fullscreen-exit.svg" : "fullscreen.svg")
                        color: Material.foreground
                    }
                }

                // Accept (incoming call only) — green.
                RoundButton {
                    visible: backend.callState === "incoming"
                    Material.background: "#2e7d32"
                    ToolTip.text: qsTr("Accept")
                    ToolTip.visible: hovered
                    onClicked: backend.acceptCall()
                    contentItem: ColorIcon {
                        implicitWidth: 24
                        implicitHeight: 24
                        source: window.iconBase + "call.svg"
                        color: "white"
                    }
                }

                // Decline / Cancel / Hang up — red.
                RoundButton {
                    Material.background: "#c62828"
                    ToolTip.text: backend.callState === "incoming" ? qsTr("Decline") : qsTr("Hang up")
                    ToolTip.visible: hovered
                    onClicked: backend.callState === "incoming" ? backend.declineCall() : backend.hangUpCall()
                    contentItem: ColorIcon {
                        implicitWidth: 24
                        implicitHeight: 24
                        source: window.iconBase + "call-end.svg"
                        color: "white"
                    }
                }
            }
        }
    }

    // --- group call screen (XEP-0272 Muji) — its own top-level window, opened automatically
    // while a group call is active. Closing it (✕) leaves the call. Audio-only for now: shows a
    // grid of participant avatars with their per-pair connection state.
    Window {
        id: conferenceDialog
        width: backend.conferenceVideo ? 640 : 480
        height: backend.conferenceVideo ? 620 : 540
        minimumWidth: 360
        minimumHeight: 360
        title: {
            var r = backend.conferenceRoom
            var local = r.split('/')[0].split('@')[0]
            return local.length > 0 ? qsTr("Group call · ") + local : qsTr("Group call")
        }
        color: window.Material.background
        Material.theme: window.Material.theme
        Material.primary: window.Material.primary
        Material.accent: window.Material.accent

        property int seconds: 0
        function fmt(s) {
            var m = Math.floor(s / 60), ss = s % 60
            return (m < 10 ? "0" : "") + m + ":" + (ss < 10 ? "0" : "") + ss
        }

        onClosing: {
            if (backend.conferenceActive)
                backend.leaveGroupCall()
        }

        Connections {
            target: backend
            function onConferenceActiveChanged() {
                if (backend.conferenceActive) {
                    conferenceModel.load()
                    conferenceDialog.seconds = 0
                    confTimer.restart()
                    conferenceDialog.show()
                    conferenceDialog.raise()
                    conferenceDialog.requestActivate()
                } else {
                    confTimer.stop()
                    conferenceDialog.hide()
                }
            }
            // Participants / their states changed → refresh the grid.
            function onConferenceChanged() {
                if (backend.conferenceActive)
                    conferenceModel.load()
            }
        }
        Timer { id: confTimer; interval: 1000; repeat: true; onTriggered: conferenceDialog.seconds++ }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 12

            // Header: room + duration + participant count.
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    font.pixelSize: 18
                    font.bold: true
                    elide: Text.ElideRight
                    text: backend.conferenceRoom.split('@')[0]
                }
                Label {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    opacity: 0.7
                    text: conferenceDialog.fmt(conferenceDialog.seconds) + " · "
                          + (confGrid.count === 1
                             ? qsTr("1 participant")
                             : qsTr("%1 participants").arg(confGrid.count))
                }
            }

            // Participant grid: avatars + connection state for audio calls; per-participant
            // video tiles for video calls (each tile's frame is keyed by the participant's sid).
            GridView {
                id: confGrid
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                cellWidth: backend.conferenceVideo ? 200 : 120
                cellHeight: backend.conferenceVideo ? 160 : 130
                model: conferenceModel
                ScrollBar.vertical: ThinScrollBar {}

                delegate: Item {
                    width: confGrid.cellWidth
                    height: confGrid.cellHeight
                    // Latest video frame (data: URL) for this participant, set from conferenceFrame.
                    property string frameUrl: ""
                    // Fetch this occupant's avatar lazily (by occupant JID), like the member list.
                    Component.onCompleted: backend.fetchMucAvatar(model.jid)
                    // Update this tile when a frame arrives for our participant's session.
                    Connections {
                        target: backend
                        enabled: backend.conferenceVideo
                        function onConferenceFrame(sid, url) {
                            if (sid === model.sid)
                                frameUrl = url
                        }
                    }

                    // Video tile.
                    Rectangle {
                        visible: backend.conferenceVideo
                        anchors.fill: parent
                        anchors.margins: 4
                        radius: 8
                        color: "black"
                        clip: true
                        Image {
                            anchors.fill: parent
                            fillMode: Image.PreserveAspectCrop
                            cache: false
                            asynchronous: true
                            retainWhileLoading: true
                            source: frameUrl
                            visible: frameUrl.length > 0
                        }
                        Avatar {
                            anchors.centerIn: parent
                            implicitWidth: 56
                            implicitHeight: 56
                            visible: frameUrl.length === 0
                            name: model.name
                            avatarPath: model.avatarPath
                            opacity: model.state === "active" ? 1.0 : 0.5
                        }
                        // Name + state caption over the bottom of the tile.
                        Label {
                            textFormat: Text.PlainText
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            anchors.margins: 4
                            horizontalAlignment: Text.AlignHCenter
                            elide: Text.ElideRight
                            font.pixelSize: 11
                            color: "white"
                            style: Text.Outline
                            styleColor: "black"
                            text: model.state === "active" ? model.name : model.name + " · " +
                                  (model.state === "ended" ? qsTr("left") : qsTr("connecting…"))
                        }
                    }

                    // Audio tile (avatar + name + state).
                    ColumnLayout {
                        visible: !backend.conferenceVideo
                        anchors.centerIn: parent
                        spacing: 6
                        Avatar {
                            Layout.alignment: Qt.AlignHCenter
                            implicitWidth: 64
                            implicitHeight: 64
                            name: model.name
                            avatarPath: model.avatarPath
                            // Dim avatars whose media isn't connected yet.
                            opacity: model.state === "active" ? 1.0 : 0.5
                        }
                        Label {
                            textFormat: Text.PlainText
                            Layout.alignment: Qt.AlignHCenter
                            Layout.maximumWidth: confGrid.cellWidth - 12
                            horizontalAlignment: Text.AlignHCenter
                            elide: Text.ElideRight
                            text: model.name
                        }
                        Label {
                            textFormat: Text.PlainText
                            Layout.alignment: Qt.AlignHCenter
                            horizontalAlignment: Text.AlignHCenter
                            font.pixelSize: 11
                            opacity: 0.6
                            color: model.state === "active" ? "#2e9d4f" : Material.foreground
                            text: model.state === "active" ? qsTr("Connected")
                                  : model.state === "ended" ? qsTr("Left")
                                  : qsTr("Connecting…")
                        }
                    }
                }

                // "Waiting" placeholder when we're the only one so far.
                Label {
                    textFormat: Text.PlainText
                    anchors.centerIn: parent
                    visible: confGrid.count === 0
                    opacity: 0.6
                    text: qsTr("Waiting for participants to join…")
                }

                // Our own camera self-preview (video calls), bottom-right corner.
                Rectangle {
                    visible: backend.conferenceVideo && backend.localFrame.length > 0
                    width: 120
                    height: 90
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    anchors.margins: 6
                    radius: 6
                    color: "black"
                    clip: true
                    Image {
                        anchors.fill: parent
                        fillMode: Image.PreserveAspectCrop
                        cache: false
                        asynchronous: true
                        retainWhileLoading: true
                        source: backend.localFrame
                    }
                }
            }

            // Controls: mute toggle + leave.
            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: 18

                RoundButton {
                    id: confMuteBtn
                    checkable: true
                    checked: backend.conferenceMuted
                    ToolTip.text: checked ? qsTr("Unmute") : qsTr("Mute")
                    ToolTip.visible: hovered
                    Material.background: checked ? "#c62828" : undefined
                    onToggled: backend.setConferenceMute(checked)
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + (confMuteBtn.checked ? "mic-off.svg" : "mic.svg")
                        color: confMuteBtn.checked ? "white" : Material.foreground
                    }
                }

                // Camera on/off (video group calls): red while off.
                RoundButton {
                    id: confCamBtn
                    visible: backend.conferenceVideo
                    checkable: true
                    checked: !backend.conferenceCameraOn
                    Material.background: checked ? "#c62828" : undefined
                    ToolTip.text: checked ? qsTr("Turn camera on") : qsTr("Turn camera off")
                    ToolTip.visible: hovered
                    onToggled: backend.setConferenceCamera(!checked)
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + (confCamBtn.checked ? "videocam-off.svg" : "videocam.svg")
                        color: confCamBtn.checked ? "white" : Material.foreground
                    }
                }

                // Screen share (video group calls): the shared screen replaces the camera for all
                // peers. Green while sharing.
                RoundButton {
                    id: confShareBtn
                    visible: backend.conferenceVideo
                    checkable: true
                    checked: backend.conferenceScreenSharing
                    Material.background: checked ? "#2e7d32" : undefined
                    ToolTip.text: checked ? qsTr("Stop sharing screen") : qsTr("Share screen")
                    ToolTip.visible: hovered
                    onToggled: backend.setConferenceScreenShare(checked)
                    contentItem: ColorIcon {
                        implicitWidth: 22
                        implicitHeight: 22
                        source: window.iconBase + (confShareBtn.checked ? "screen-share-off.svg" : "screen-share.svg")
                        color: confShareBtn.checked ? "white" : Material.foreground
                    }
                }

                RoundButton {
                    Material.background: "#c62828"
                    ToolTip.text: qsTr("Leave call")
                    ToolTip.visible: hovered
                    onClicked: backend.leaveGroupCall()
                    contentItem: ColorIcon {
                        implicitWidth: 24
                        implicitHeight: 24
                        source: window.iconBase + "call-end.svg"
                        color: "white"
                    }
                }
            }
        }
    }
}
