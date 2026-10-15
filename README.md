# monocles chat desktop — Qt/QML client (Linux · Windows · macOS)

A cross-platform desktop client for **monocles chat** (XMPP), built with **Qt 6 / QML
(Material style)** and [CXX-Qt](https://github.com/KDAB/cxx-qt). It uses the proven Rust
backend — the same XMPP wire stack and **PQ OMEMO2** crypto (libsignal) as the other
monocles clients, for byte-level interop with monocles chat for Android.

## Features

- 1:1 and group chats with **post-quantum OMEMO2** end-to-end encryption (including
  encrypted MUCs), reactions, corrections, retraction, replies
- **Audio/video calls** (Jingle + Jingle Message Initiation, GStreamer/webrtcbin)
- **Stories** (social feed over PEP), **stickers**, voice messages, file transfer
- **WebXDC mini-apps** (QtWebEngine) with realtime/status-update sync
- Offline support: cached conversations on startup, outbox for messages sent while offline

## Architecture

```
monocles_chat_desktop/                # self-contained Cargo workspace
├─ crates/mxc-app-qt/   # Qt/QML front-end
│  ├─ src/main.rs       # QGuiApplication + QML engine, Material style
│  ├─ src/backend.rs    # CXX-Qt bridge: the `Backend` QObject QML imports
│  ├─ src/session.rs    # tokio runtime + mxc-proto spawn + event pump
│  ├─ build.rs          # CXX-Qt QML module (uri de.monocles.chat)
│  └─ qml/              # Material UI
├─ crates/mxc-proto/    # XMPP transport + XEPs; Command/Event over async-channel
├─ crates/mxc-store/    # SQLite (sqlx, SQLCipher)
├─ crates/mxc-omemo/    # PQ OMEMO2 on libsignal
├─ crates/mxc-media/    # GStreamer calls (RGBA frames over a channel)
├─ deps/libsignal/      # libsignal checkout (git-ignored; see "libsignal" below)
└─ packaging/           # flatpak, rpm, macOS, windows (deb lives in scripts/)
```

The UI sends `mxc_proto::Command`s and consumes `Event`s; core events are marshalled back
onto the Qt thread with `CxxQtThread::queue`.

## Build prerequisites

**Rust:** a pinned nightly (libsignal's requirement) — installed automatically by
[rustup](https://rustup.rs) from `rust-toolchain.toml`.

**Qt 6 + QML + WebEngine** (Debian 13 / trixie):

```sh
sudo apt install -y \
  qt6-base-dev qt6-declarative-dev qt6-webengine-dev \
  qml6-module-qtquick qml6-module-qtquick-controls \
  qml6-module-qtquick-layouts qml6-module-qtquick-dialogs \
  qml6-module-qtquick-effects qml6-module-qtquick-window \
  qml6-module-qtquick-templates qml6-module-qtqml-workerscript \
  qml6-module-qtwebengine qml6-module-qtwebengine-controlsdelegates \
  libqt6svg6 qt6-image-formats-plugins
```

**Backend system deps:** `protobuf-compiler` (libsignal compiles protobufs at build time),
`libssl-dev`, and **GStreamer** for calls and voice messages (`-bad1.0-dev` provides
`gstreamer-webrtc-1.0.pc`, required at build time):

```sh
sudo apt install -y \
  protobuf-compiler libssl-dev \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  libgstreamer-plugins-bad1.0-dev \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-nice
```

On Fedora, `packaging/rpm/build-rpm.sh` installs the equivalent packages via dnf.

**libsignal** (required — not committed): clone the monocles fork (`pq-omemo-2`, which carries
the PQ OMEMO2 changes and is the same tree the Android app builds against) into `deps/libsignal`:

```sh
git clone https://codeberg.org/monocles/pq-omemo-2.git deps/libsignal
# Pin the revision this client expects. Not optional in practice: earlier revisions
# predate the v4 bundle transcript (signed by both identity keys) and the <pq-auth>
# handshake transcript, and a mismatched pair fails to establish a session rather
# than degrading — so the symptom looks like a broken build, not a version skew.
git -C deps/libsignal checkout 10861bff671740174f4e99f7e30dc492fcf6ec8b  # "PQ auth check and hardening"
```

**Dev database (sqlx):** `mxc-store`'s compile-time `query!` macros need a SQLite DB with
the schema. With `sqlx-cli` installed, `./scripts/setup-db.sh` creates `.sqlx-dev.db` from
the migrations for you; you then only need the `.cargo/config.toml` step below. Otherwise,
create the DB from the migrations and point `DATABASE_URL` at it manually:

```sh
rm -f .sqlx-dev.db                       # start clean (snippet below is not incremental)
python3 - <<'PY'
import sqlite3, glob
con = sqlite3.connect('.sqlx-dev.db')
for m in sorted(glob.glob('crates/mxc-store/migrations/*.sql')):
    con.executescript(open(m).read())
con.commit()
PY

mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[env]
DATABASE_URL = "sqlite://$PWD/.sqlx-dev.db"
# cxx-qt-build 0.9 otherwise matches a PATH qmake against a version range and, on a miss, tries
# to DOWNLOAD Qt. Point QMAKE at the system qmake6 so the installed Qt 6 is used directly.
QMAKE = "$(command -v qmake6 || command -v qmake)"
EOF
```

(Both files are git-ignored; the packaging scripts set `DATABASE_URL`/`QMAKE` themselves.)

> **After pulling changes that add a migration, refresh the dev DB** — otherwise the build
> fails with errors like `no such column: pq_identity_pub` or `no such table:
> omemo_pq_identities` (these come from `0013_omemo_pq_identity.sql`, the PQ-identity
> migration). The `query!` macros are checked against `.sqlx-dev.db` at **compile** time, so
> a stale dev DB breaks the build even though the runtime DB migrates itself. Re-run
> `./scripts/setup-db.sh` (sqlx-cli applies new migrations incrementally), or just `rm -f
> .sqlx-dev.db` and re-run the snippet above.

## Build & run

```sh
cargo run
```

Log in with your JID + password; the status line should transition to **“Online as …”**.

## Packaging

| Target | Script | Notes |
| --- | --- | --- |
| **Flatpak** (recommended) | `./packaging/flatpak/build-flatpak.sh` | KDE 6.10 runtime + QtWebEngine BaseApp; bundles everything incl. GStreamer |
| Debian/Ubuntu `.deb` | `./scripts/build-deb.sh` | run on Debian; deps resolved via apt |
| Fedora `.rpm` | `./packaging/rpm/build-rpm.sh` | run **on Fedora** (links Fedora's libs) |
| macOS `.app`/`.dmg` | `./packaging/macos/build-macos.sh` | **untested** — see `packaging/macos/README.md` |
| Windows zip | `packaging\windows\build-windows.ps1` | **untested** — see `packaging/windows/README.md` |

Each packaging directory has a README with details and known gaps.

## Cross-platform notes

- **Secret storage:** passwords and the OMEMO identity key are stored in the OS keychain via a
  platform-specific backend (`crates/mxc-store/src/secrets.rs`): the freedesktop Secret Service
  (`oo7`) on Linux, and the `keyring` crate (Keychain Services / Windows Credential Manager) on
  macOS / Windows. Credentials persist on all three.
- **Data dir:** resolved with the `directories` crate, so it is correct on each OS
  (Linux: `~/.local/share/monocles-chat`).

## License

GPL-3.0-or-later. Bundles [libsignal](https://codeberg.org/monocles/pq-omemo-2) (AGPL-3.0;
monocles `pq-omemo-2` fork of [signalapp/libsignal](https://github.com/signalapp/libsignal)).
