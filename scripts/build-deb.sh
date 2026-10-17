#!/usr/bin/env bash
# Assemble a .deb for the monocles chat Qt client from the release binary.
#
#   ./scripts/build-deb.sh            # expects target/release/monocles-chat-qt to exist
#
# Build the binary first with:  cargo build --release -p mxc-app-qt
#
# Group calls: by default this bundles a patched libnice into /usr/lib/monocles-chat-qt and ships
# a /usr/bin launcher wrapper that loads it and sets MONOCLES_MUJI_TCP_RELAY=1, so group (Muji)
# calls work over TCP/TLS relays (e.g. a participant on a UDP-blocking network) without the
# libnice mesh-nomination crash. Building it needs: meson ninja-build pkg-config gcc
# libglib2.0-dev libgnutls28-dev git python3. Set BUNDLE_LIBNICE=0 to build a plain package on the
# distro's libnice instead (group calls then use UDP-only relays). See packaging/libnice/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."

PKG="monocles-chat-qt"
VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
# Debian package revision: bump this (keeping the same upstream VERSION) to ship a new build
# of the same release so dpkg/apt offer the upgrade — e.g. "0.1.0-2".
REVISION="1"
DEBVER="${VERSION}-${REVISION}"
ARCH="$(dpkg --print-architecture)"
BIN="target/release/monocles-chat-qt"
STAGE="target/deb/${PKG}_${DEBVER}_${ARCH}"
# Bundle a patched libnice + launcher wrapper so group calls work over TCP/TLS relays without the
# libnice mesh-nomination crash. Set BUNDLE_LIBNICE=0 to build a plain package on the system
# libnice instead (group calls then use UDP-only relays — see packaging/libnice/README.md).
BUNDLE_LIBNICE="${BUNDLE_LIBNICE:-1}"
PRIVDIR="usr/lib/monocles-chat-qt"   # Debian private libdir (relative to $STAGE)

[ -f "$BIN" ] || { echo "error: $BIN not found — run: cargo build --release -p mxc-app-qt"; exit 1; }

echo "Packaging $PKG $DEBVER ($ARCH)"
rm -rf "$STAGE"
install -Dm0644 data/de.monocles.chat.qt.desktop      "$STAGE/usr/share/applications/de.monocles.chat.qt.desktop"
install -Dm0644 data/de.monocles.chat.qt.metainfo.xml "$STAGE/usr/share/metainfo/de.monocles.chat.qt.metainfo.xml"
install -Dm0644 data/icons/de.monocles.chat.qt.svg    "$STAGE/usr/share/icons/hicolor/scalable/apps/de.monocles.chat.qt.svg"
install -Dm0644 data/icons/de.monocles.chat.qt.png    "$STAGE/usr/share/icons/hicolor/512x512/apps/de.monocles.chat.qt.png"

if [ "$BUNDLE_LIBNICE" = 1 ]; then
  echo "==> Bundling patched libnice + launcher wrapper"
  LNBUILD="$PWD/target/deb/libnice-prefix"
  rm -rf "$LNBUILD"
  PREFIX="$LNBUILD" packaging/libnice/build-patched-libnice.sh
  # Real binary + patched libnice.so.10 live in the private libdir; /usr/bin holds a wrapper that
  # points the loader at them and enables TCP/TLS relays for group calls (safe: the bundled
  # libnice nominates ICE pairs gracefully instead of aborting).
  install -Dm0755 "$BIN" "$STAGE/$PRIVDIR/monocles-chat-qt"
  cp -a "$LNBUILD/lib/"libnice.so.10* "$STAGE/$PRIVDIR/"
  strip --strip-unneeded "$STAGE/$PRIVDIR/monocles-chat-qt" 2>/dev/null || true
  install -d "$STAGE/usr/bin"
  cat > "$STAGE/usr/bin/monocles-chat-qt" <<'EOF'
#!/bin/sh
# monocles chat (Qt) launcher. Loads the bundled patched libnice (graceful ICE nomination so
# group calls don't abort on TCP-relay pairs in a mesh) and enables TCP/TLS relays for group
# calls. See /usr/share/doc/monocles-chat-qt for details.
PRIV=/usr/lib/monocles-chat-qt
export LD_LIBRARY_PATH="$PRIV:${LD_LIBRARY_PATH:-}"
export MONOCLES_MUJI_TCP_RELAY=1
exec "$PRIV/monocles-chat-qt" "$@"
EOF
  chmod 0755 "$STAGE/usr/bin/monocles-chat-qt"
  SHLIBDEPS_OBJS="$STAGE/$PRIVDIR/monocles-chat-qt $(ls "$STAGE/$PRIVDIR/"libnice.so.10.* 2>/dev/null | head -1)"
else
  install -Dm0755 "$BIN" "$STAGE/usr/bin/monocles-chat-qt"
  strip --strip-unneeded "$STAGE/usr/bin/monocles-chat-qt" 2>/dev/null || true
  SHLIBDEPS_OBJS="$STAGE/usr/bin/monocles-chat-qt"
fi

# copyright (AGPL-3.0-only)
install -d "$STAGE/usr/share/doc/$PKG"
cat > "$STAGE/usr/share/doc/$PKG/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: monocles chat desktop (Qt)
Source: https://github.com/Arne19/monocles_chat_desktop

Files: *
Copyright: Arne-Brün Vogelsang <arne@monocles.eu>
License: AGPL-3.0-only
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU Affero General Public License version 3 only, as published
 by the Free Software Foundation. The full text is at
 https://www.gnu.org/licenses/agpl-3.0.txt and in the LICENSE file of the source.
 .
 The application bundles libsignal (AGPL-3.0-only) for PQ OMEMO2 — the monocles
 pq-omemo-2 fork of signalapp/libsignal; see https://codeberg.org/monocles/pq-omemo-2
 for its source. The combined work is therefore distributed under AGPL-3.0-only.
 .
 Note: this package also bundles a patched libnice (LGPL-2.1-or-later) in
 /usr/lib/monocles-chat-qt — libnice 0.1.23 with a graceful-nomination fix for group calls
 (packaging/libnice/patch-conncheck.py); upstream: https://gitlab.freedesktop.org/libnice/libnice.
EOF

# Linked libraries via dpkg-shlibdeps (Qt core/gui/qml, gstreamer core, openssl, …).
SHLIB_DEPENDS="libc6, libqt6core6 (>= 6.4), libqt6gui6 (>= 6.4), libqt6qml6 (>= 6.4)"
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
  mkdir -p debian && touch debian/control 2>/dev/null || true
  # Scan the real binary (and, when bundled, the patched libnice so its glib/gnutls deps are
  # pulled in) — $SHLIBDEPS_OBJS is intentionally unquoted to pass each as a separate arg.
  if SHLIBS="$(dpkg-shlibdeps -O --ignore-missing-info $SHLIBDEPS_OBJS 2>/dev/null)"; then
    SHLIB_DEPENDS="${SHLIBS#shlibs:Depends=}"
  fi
  rm -rf debian
fi
# Runtime pieces the linker can't see (all loaded at runtime, so listed explicitly):
#  - QML modules (the UI imports QtQuick/Controls+Material/Layouts/Dialogs/Effects/Window),
#  - the SVG + WebP image plugins (icons, stickers, animated avatars),
#  - WebXDC: the QtWebEngine QML module + the out-of-process QtWebEngineProcess helper
#    and its resources/locales (shlibdeps only sees the linked libQt6WebEngine* libs),
#  - GStreamer plugins (calls: webrtcbin/nice/opus/vpx; voice messages: opusenc/oggmux/pulse).
QML_DEPENDS="qml6-module-qtquick, qml6-module-qtquick-controls, qml6-module-qtquick-layouts, qml6-module-qtquick-dialogs, qml6-module-qtquick-effects, qml6-module-qtquick-window, qml6-module-qtquick-templates, qml6-module-qtqml-workerscript, libqt6svg6, qt6-image-formats-plugins"
WEBENGINE_DEPENDS="qml6-module-qtwebengine, qml6-module-qtwebengine-controlsdelegates, libqt6webenginecore6-bin, libqt6webengine6-data"
GST_DEPENDS="gstreamer1.0-plugins-base, gstreamer1.0-plugins-good, gstreamer1.0-plugins-bad, gstreamer1.0-nice"
DEPENDS="$SHLIB_DEPENDS, $QML_DEPENDS, $WEBENGINE_DEPENDS, $GST_DEPENDS"
echo "Depends: $DEPENDS"

INSTALLED_KB="$(du -ks "$STAGE" | cut -f1)"

install -d "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $DEBVER
Architecture: $ARCH
Maintainer: Arne-Brün Vogelsang <arne@monocles.eu>
Section: net
Priority: optional
Installed-Size: $INSTALLED_KB
Depends: $DEPENDS
Recommends: gnome-keyring
Homepage: https://github.com/Arne19/monocles_chat_desktop
Description: monocles chat (Qt) - encrypted XMPP desktop client
 Cross-platform Qt/QML XMPP client, wire- and feature-compatible with
 monocles chat for Android. Features post-quantum PQ OMEMO2 (PQXDH + SPQR)
 end-to-end encryption, audio/video calls, voice messages, reactions,
 replies, corrections, WebXDC mini-apps, Stories and more.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

OUT="target/deb/${PKG}_${DEBVER}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo
echo "Built: $OUT"
dpkg-deb --info "$OUT"
