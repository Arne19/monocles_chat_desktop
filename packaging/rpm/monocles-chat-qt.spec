# RPM spec for the monocles chat Qt client. The heavy build (pinned-nightly Rust + vendored
# libsignal + bundled SQLCipher) is done by build-rpm.sh *outside* rpmbuild; this spec just
# packages the already-built binary + data files (staged into SOURCES). Build it via
# packaging/rpm/build-rpm.sh ON A FEDORA MACHINE.

# Prebuilt, stripped binary → no separate -debuginfo subpackage.
%global debug_package %{nil}

# When build-rpm.sh bundles a patched libnice (the default), don't let that private copy satisfy
# other packages' libnice deps, and skip auto-Requires generated from inside the private libdir
# (its glib/gnutls deps are already pulled by gstreamer/Qt).
%if %{defined bundle_libnice}
%global __provides_exclude_from ^%{_libdir}/monocles-chat-qt/.*\\.so.*$
%global __requires_exclude_from ^%{_libdir}/monocles-chat-qt/.*$
%endif

Name:           monocles-chat-qt
Version:        %{appversion}
# Bump Release (same Version) to ship a new build of the same upstream release so dnf offers
# the upgrade — e.g. 0.1.0-2.
Release:        1%{?dist}
Summary:        Encrypted XMPP desktop client with post-quantum PQ OMEMO2 (Qt)

License:        AGPL-3.0-only
URL:            https://github.com/Arne19/monocles_chat_desktop

Source0:        monocles-chat-qt
Source1:        de.monocles.chat.qt.desktop
Source2:        de.monocles.chat.qt.metainfo.xml
Source3:        de.monocles.chat.qt.svg
Source4:        de.monocles.chat.qt.png

# GUI: the QML engine + modules are loaded at runtime, so list them explicitly — rpm's auto
# dependency finder only catches directly-linked libraries.
Requires:       qt6-qtbase-gui
Requires:       qt6-qtdeclarative
Requires:       qt6-qtsvg
Requires:       qt6-qtimageformats
# WebXDC mini-apps: QtWebEngine QML module + the QtWebEngineProcess helper/resources.
Requires:       qt6-qtwebengine
# Audio/video calls + voice messages (GStreamer WebRTC / opus; plugins are dlopen'd).
Requires:       gstreamer1
Requires:       gstreamer1-plugins-base
Requires:       gstreamer1-plugins-good
Requires:       gstreamer1-plugins-bad-free
Requires:       libnice-gstreamer1
# For the encrypted password/OMEMO2 key store (Secret Service over D-Bus).
Recommends:     gnome-keyring

%description
monocles chat is a cross-platform Qt/QML XMPP client, wire- and feature-compatible with
monocles chat for Android. Conversations are protected with post-quantum PQ OMEMO2
(PQXDH + SPQR) end-to-end encryption and the local database is encrypted at rest with
SQLCipher. Supports 1:1 and group chats, reactions, replies, corrections, retraction,
read markers, audio/video calls, voice messages, stickers, WebXDC mini-apps,
encrypted file sharing, Stories and social Feeds.

%prep
# Nothing to unpack — the binary is prebuilt and staged into SOURCES.

%build
# Nothing to compile — see build-rpm.sh.

%install
%if %{defined bundle_libnice}
# Bundled: the real binary + patched libnice live in a private libdir; %{_bindir} gets a launcher
# wrapper that loads the patched libnice and enables TCP/TLS relays for group calls.
install -Dm0755 %{SOURCE0} %{buildroot}%{_libdir}/monocles-chat-qt/monocles-chat-qt
cp -a %{_sourcedir}/libnice/libnice.so.10* %{buildroot}%{_libdir}/monocles-chat-qt/
install -Dm0755 %{_sourcedir}/monocles-chat-qt.sh %{buildroot}%{_bindir}/monocles-chat-qt
%else
install -Dm0755 %{SOURCE0} %{buildroot}%{_bindir}/monocles-chat-qt
%endif
install -Dm0644 %{SOURCE1} %{buildroot}%{_datadir}/applications/de.monocles.chat.qt.desktop
install -Dm0644 %{SOURCE2} %{buildroot}%{_datadir}/metainfo/de.monocles.chat.qt.metainfo.xml
install -Dm0644 %{SOURCE3} %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/de.monocles.chat.qt.svg
install -Dm0644 %{SOURCE4} %{buildroot}%{_datadir}/icons/hicolor/512x512/apps/de.monocles.chat.qt.png

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/de.monocles.chat.qt.desktop || :

%files
%{_bindir}/monocles-chat-qt
%if %{defined bundle_libnice}
%dir %{_libdir}/monocles-chat-qt
%{_libdir}/monocles-chat-qt/monocles-chat-qt
%{_libdir}/monocles-chat-qt/libnice.so.10*
%endif
%{_datadir}/applications/de.monocles.chat.qt.desktop
%{_datadir}/metainfo/de.monocles.chat.qt.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/de.monocles.chat.qt.svg
%{_datadir}/icons/hicolor/512x512/apps/de.monocles.chat.qt.png

%changelog
* Sat Jun 20 2026 monocles <arne@monocles.eu> - 0.1.0-1
- Bundle a patched libnice + launcher wrapper (when built with --define "bundle_libnice 1",
  the build-rpm.sh default) so group calls work over TCP/TLS relays without the libnice
  mesh-nomination crash.

* Thu Jun 11 2026 monocles <arne@monocles.eu> - 0.1.0-1
- Initial RPM packaging of the Qt client.
