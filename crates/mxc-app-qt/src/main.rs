//! monocles chat — Qt/QML desktop client (Linux/Windows/macOS).
//!
//! The QML UI runs on the Qt main thread; the XMPP core (`mxc-proto`) runs on a tokio
//! runtime (see [`session`]). They communicate through the [`backend::qobject::Backend`]
//! QObject: QML calls invokables, and core events are queued back onto the Qt thread.

mod backend;
mod calls;
mod conference;
mod devices;
mod feeds;
mod media;
mod messages;
mod model;
mod muc_admin;
mod occupants;
mod qr;
mod roster;
mod search;
mod session;
mod stories;
mod webxdc;

use cxx_qt_lib::{QGuiApplication, QList, QQmlApplicationEngine, QString, QStringList, QUrl};

fn main() {
    // The Material style must be selected before the QML engine instantiates Controls.
    std::env::set_var("QT_QUICK_CONTROLS_STYLE", "Material");

    // WebXDC: GL context sharing + the private webxdc:// scheme must be set up before the
    // QGuiApplication exists (QtWebEngine requirement).
    webxdc::pre_app_init();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mxc_proto=debug,mxc_omemo=debug".into()),
        )
        .init();

    let mut app = QGuiApplication::new();

    // Give the default application font a colour-emoji fallback family, so emoji in plain text
    // (composer, message bubbles) render in colour via the native renderer. QML's `font.families`
    // property isn't assignable at runtime in this Qt build, so we set it app-wide here instead.
    {
        let mut font = app.font();
        let primary = font.family().map(|q| q.to_string()).unwrap_or_default();
        let mut families = QList::<QString>::default();
        if !primary.is_empty() {
            families.append(QString::from(primary.as_str()));
        }
        families.append(QString::from("Noto Color Emoji"));
        font.set_families(&QStringList::from(&families));
        if let Some(app) = app.as_mut() {
            app.set_application_font(&font);
        }
    }

    let mut engine = QQmlApplicationEngine::new();

    if let Some(engine) = engine.as_mut() {
        // Resource path of the QML registered by the `de.monocles.chat` QmlModule
        // (uri → de/monocles/chat) in build.rs.
        engine.load(&QUrl::from(&QString::from(
            "qrc:/qt/qml/de/monocles/chat/qml/main.qml",
        )));
    }

    if let Some(app) = app.as_mut() {
        app.exec();
    }
}
