// Compile + register the QML module and the CXX-Qt bridge. The module URI (de.monocles.chat)
// is what QML imports to get the `Backend` type; `qrc:/qt/qml/de/monocles/chat/qml/main.qml`
// is the resource path the engine loads (see src/main.rs).
use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    // cxx-qt-build 0.9 replaced the `QmlModule { rust_files, qml_files, qrc_files, .. }` struct
    // with a builder: the module owns the QML files, the Rust bridge sources are added with
    // `.files(..)`, and arbitrary resources go through `.qrc_resources(..)` (auto-prefixed with
    // the module's `/qt/qml/de/monocles/chat/` import path, so the qrc paths are unchanged).
    let mut builder = CxxQtBuilder::new_qml_module(QmlModule::new("de.monocles.chat").qml_files([
        "qml/main.qml",
        "qml/Avatar.qml",
        "qml/ColorIcon.qml",
        "qml/ThinScrollBar.qml",
        "qml/FastScroll.qml",
        "qml/WebxdcWindow.qml",
    ]))
    .files([
        "src/backend.rs",
        "src/model.rs",
        "src/messages.rs",
        "src/roster.rs",
        "src/search.rs",
        "src/occupants.rs",
        "src/conference.rs",
        "src/devices.rs",
        "src/calls.rs",
        "src/stories.rs",
        "src/feeds.rs",
    ])
    .qrc_resources([
        // cxx-qt-build 0.9's qml_files rejects non-.qml files, so the EmojiData JS module is
        // embedded as a plain resource. The `qml/` prefix + module auto-prefix places it at
        // qrc:/qt/qml/de/monocles/chat/qml/EmojiData.js — beside main.qml, so main.qml's
        // relative `import "EmojiData.js"` still resolves.
        "qml/EmojiData.js",
        "icons/nav-chats-symbolic.svg",
        "icons/nav-chats-outline-symbolic.svg",
        "icons/nav-calls-symbolic.svg",
        "icons/nav-calls-outline-symbolic.svg",
        "icons/nav-stories-symbolic.svg",
        "icons/nav-stories-outline-symbolic.svg",
        "icons/nav-feeds-symbolic.svg",
        "icons/nav-feeds-outline-symbolic.svg",
        "icons/reaction-smile-symbolic.svg",
        "icons/lock-omemo2.svg",
        "icons/bookmark.svg",
        "icons/lock-open.svg",
        "icons/members.svg",
        "icons/verified.svg",
        "icons/account-circle.svg",
        "icons/logout.svg",
        "icons/info.svg",
        "icons/monocles-wordmark.svg",
        "icons/fullscreen.svg",
        "icons/fullscreen-exit.svg",
        "icons/call.svg",
        "icons/call-end.svg",
        "icons/videocam.svg",
        "icons/mic-off.svg",
        "icons/call-made.svg",
        "icons/call-received.svg",
        "icons/call-missed.svg",
        "icons/attach.svg",
        "icons/camera.svg",
        "icons/mic.svg",
        "icons/videocam-off.svg",
        "icons/screen-share.svg",
        "icons/screen-share-off.svg",
        "icons/send.svg",
        "icons/search.svg",
        "icons/settings.svg",
        // Default chat-background doodle tiles (from the Android app), light + dark.
        "icons/chat-bg-light.png",
        "icons/chat-bg-dark.png",
    ]);
    // cxx-qt-build 0.9 marks cc_builder unsafe (the callback can change the C++ build in ways
    // that must stay ABI-compatible with the generated cxx-qt code); our use just adds one shim.
    // WebXDC: the scheme handler + QtWebEngineQuick::initialize live in this C++ shim
    // (cpp/webxdc_shim.cpp) — QtWebEngine has no Rust bindings. Needs qt6-webengine-dev.
    builder = unsafe {
        builder.cc_builder(|cc| {
            cc.file("cpp/webxdc_shim.cpp");
            println!("cargo:rerun-if-changed=cpp/webxdc_shim.cpp");
        })
    };
    builder.build();

    // QtWebEngine link libs for the WebXDC shim, emitted directly instead of via
    // `.qt_module("WebEngine*")`: since qt-build-utils 0.9 that call resolves the module's
    // `.prl` under qmake's QT_INSTALL_LIBS and panics if it is missing. In the Flatpak build
    // QtWebEngine comes from the QtWebEngine BaseApp under /app while qmake reports the KDE
    // runtime's /usr, so the .prl is never found there. The shim only needs these two libs —
    // every transitive Qt dep (Quick/Qml/Gui/Core/Network) is already linked by its own module.
    // The library search paths are already present (/usr/lib locally via the Core module; /app/lib
    // via RUSTFLAGS in the Flatpak manifest) and the shim's includes resolve independently
    // (QT_INSTALL_HEADERS locally, -I/app/include in Flatpak), so the compile step is unaffected.
    // Emitted after build() so cxx-qt's static-shim link directive precedes these dynamic libs.
    //
    // QtWebEngine ships as macOS *frameworks* (QtWebEngineQuick.framework /
    // QtWebEngineCore.framework - no "6" in the bundle name), so `-lQt6WebEngine...`
    // (the `lib...` convention used on Linux) can't resolve them.
    let (quick, core) = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        ("framework=QtWebEngineQuick", "framework=QtWebEngineCore")
    } else {
        ("Qt6WebEngineQuick", "Qt6WebEngineCore")
    };
    println!("cargo::rustc-link-lib={quick}");
    println!("cargo::rustc-link-lib={core}");
}
