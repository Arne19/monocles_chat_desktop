// WebXDC C++ shim: the QtWebEngine pieces that have no Rust/QML bindings.
//
//  - mxc_webxdc_pre_app_init(): QtWebEngineQuick::initialize() (GL context sharing — must run
//    BEFORE QGuiApplication) + registration of the private `webxdc://` scheme. The scheme is
//    secure + CORS- and Fetch-enabled so apps get a secure context (crypto.subtle) and can
//    fetch()/module-import their own assets — like a real https origin, but entirely offline.
//    Deliberately NOT a "local" scheme: that gives a file://-like opaque origin, which breaks
//    apps' own same-origin module loads (lesson from the GTK client).
//
//  - mxc_webxdc_install(root, js): points the handler at an extracted app dir + the generated
//    webxdc.js, installing it on the default profile on first use (Qt thread only).
//
//  - The handler serves `webxdc://<host>/<path>` from the app dir, `/webxdc.js` from memory,
//    and forwards `/__bridge__` POST bodies (the JS API's messages) to Rust
//    (mxc_webxdc_bridge_message, defined in src/webxdc.rs — runs on a Chromium IO thread).
//
// SECURITY (webxdc apps are untrusted code from chat peers; mirrors monocles Android):
//  - every app instance gets its own origin `webxdc://x<sha256(instance)>/`, so apps can't read
//    each other's localStorage/IndexedDB; only the live instance's host is served, and only
//    that origin may talk to the bridge;
//  - no network: a CSP on every response plus a request interceptor that blocks http(s)/ws(s)/
//    ftp/file/qrc, so an app can neither leak data nor the user's IP;
//  - paths are canonicalized and must stay inside the extracted app dir (QUrl::path() decodes
//    %2F, so `..%2F..%2F` would otherwise read arbitrary local files);
//  - WebRTC (not covered by CSP or the interceptor: ICE/STUN is direct UDP) is disabled with
//    Delta Chat's FILL500, injected first into every HTML document (see kWebRtcBlocker).

#include <QtWebEngineQuick/qtwebenginequickglobal.h>
#include <QtWebEngineQuick/QQuickWebEngineProfile>
#include <QtWebEngineCore/QWebEngineUrlScheme>
#include <QtWebEngineCore/QWebEngineUrlSchemeHandler>
#include <QtWebEngineCore/QWebEngineUrlRequestJob>

#include <QtWebEngineCore/QWebEngineUrlRequestInterceptor>
#include <QtWebEngineCore/QWebEngineUrlRequestInfo>

#include <QBuffer>
#include <QDir>
#include <QFileInfo>
#include <QMultiMap>
#include <QRegularExpression>
#include <QByteArray>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QString>
#include <QUrl>

extern "C" void mxc_webxdc_bridge_message(const char *data, size_t len);

namespace {

QMutex g_mutex;
QString g_root;   // extracted app dir currently served
QString g_host;   // its private host (webxdc://<g_host>/); nothing else is served
QByteArray g_js;  // generated webxdc.js for the current instance

// Same policy as monocles Android's WebxdcPage: everything from our own origin, no network.
const QByteArray kCsp = QByteArrayLiteral(
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline' blob: ; "
    "font-src 'self' data: blob: ; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: ; "
    "connect-src 'self' data: blob: ; "
    "img-src 'self' data: blob: ; "
    "media-src 'self' data: blob: ; "
    "webrtc 'block' ;");
// Documents that can run scripts but don't get the FILL500 injection may run none at all
// (navigating to one would release the previous document's 500 connections).
const QByteArray kNoScriptCsp = QByteArrayLiteral(
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: blob: ; "
    "font-src 'self' data: ; sandbox");

// FILL500 (https://delta.chat/en/2023-05-22-webxdc-security): Chromium allows at most 500
// RTCPeerConnections per renderer process, counted in the constructor, and unclosed ones live
// as long as their document. Creating 500 before any app script makes every further one fail -
// also in fresh about:blank/srcdoc frames. If a 501st still succeeds (a Chromium without the
// limit), fall back to removing the WebRTC entry points. Keep in sync with Android's
// WebxdcPage.WEBRTC_BLOCKER.
const QByteArray kWebRtcBlocker = QByteArrayLiteral(
    "<script>(function(){'use strict';"
    "try{for(var i=0;i<500;i++){new RTCPeerConnection();}}catch(e){}"
    "var blocked=false;"
    "try{var p=new RTCPeerConnection();try{p.close();}catch(e){}}catch(e){blocked=true;}"
    "if(blocked)return;"
    "console.warn('webxdc: WebRTC connection limit not enforced, removing WebRTC API');"
    "var N=['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel',"
    "'RTCIceCandidate','RTCSessionDescription','RTCRtpSender','RTCRtpReceiver',"
    "'RTCRtpTransceiver','RTCIceTransport','RTCDtlsTransport','RTCSctpTransport',"
    "'RTCCertificate','RTCDTMFSender','RTCPeerConnectionIceEvent','RTCDataChannelEvent',"
    "'RTCTrackEvent','RTCError','RTCErrorEvent'];"
    "function lock(w){if(!w)return w;for(var i=0;i<N.length;i++){try{"
    "Object.defineProperty(w,N[i],{value:undefined,writable:false,configurable:false,enumerable:false});"
    "}catch(e){}}return w;}"
    "lock(window);"
    "[window.HTMLIFrameElement,window.HTMLFrameElement,window.HTMLObjectElement,window.HTMLEmbedElement]"
    ".forEach(function(C){if(!C)return;var P=C.prototype;"
    "['contentWindow','contentDocument'].forEach(function(k){"
    "var d=Object.getOwnPropertyDescriptor(P,k);if(!d||!d.get)return;"
    "Object.defineProperty(P,k,{configurable:false,enumerable:d.enumerable,get:function(){"
    "var v=d.get.call(this);if(v){lock(k==='contentWindow'?v:v.defaultView);}return v;}});});});"
    "})();</script>");

// Insert kWebRtcBlocker as the first script: after <head ...>, else <html ...>, else the
// doctype, else at the very start.
QByteArray injectWebRtcBlocker(const QByteArray &html)
{
    static const QRegularExpression head(QStringLiteral("<head(\\s[^>]*)?>"),
                                         QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression htmlTag(QStringLiteral("<html(\\s[^>]*)?>"),
                                            QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression doctype(QStringLiteral("^\\s*<!doctype[^>]*>"),
                                            QRegularExpression::CaseInsensitiveOption);
    const QString doc = QString::fromUtf8(html);
    qsizetype at = 0;
    QRegularExpressionMatch m = head.match(doc);
    if (!m.hasMatch()) m = htmlTag.match(doc);
    if (!m.hasMatch()) m = doctype.match(doc);
    if (m.hasMatch()) at = m.capturedEnd();
    return doc.left(at).toUtf8() + kWebRtcBlocker + doc.mid(at).toUtf8();
}

// The app-dir file a (decoded) request path refers to, or an empty string if it would leave
// the app dir (`..` segments, encoded slashes, symlinks out of the dir). Caller holds g_mutex.
QString resolveInRoot(const QString &path)
{
    if (path.contains(QLatin1Char('\\')) || path.contains(QChar(0)))
        return QString();
    const QStringList segments = path.split(QLatin1Char('/'));
    if (segments.contains(QStringLiteral("..")))
        return QString();
    const QString root = QFileInfo(g_root).canonicalFilePath();
    if (root.isEmpty())
        return QString();
    const QString file = QFileInfo(g_root + QLatin1Char('/') + path).canonicalFilePath();
    if (file.isEmpty() || !file.startsWith(root + QLatin1Char('/')))
        return QString();
    return file;
}

// Blocks every network request of the WebXDC web views (they share the default profile, which
// nothing else in the app uses). The CSP already forbids these; this is the backstop.
class OfflineInterceptor : public QWebEngineUrlRequestInterceptor
{
public:
    void interceptRequest(QWebEngineUrlRequestInfo &info) override
    {
        const QString scheme = info.requestUrl().scheme().toLower();
        if (scheme == QLatin1String("http") || scheme == QLatin1String("https")
            || scheme == QLatin1String("ws") || scheme == QLatin1String("wss")
            || scheme == QLatin1String("ftp") || scheme == QLatin1String("file")
            || scheme == QLatin1String("qrc"))
            info.block(true);
    }
};

QByteArray mimeFor(const QString &path)
{
    const QString ext = path.section(QLatin1Char('.'), -1).toLower();
    if (ext == QLatin1String("html") || ext == QLatin1String("htm")) return QByteArrayLiteral("text/html");
    if (ext == QLatin1String("js") || ext == QLatin1String("mjs")) return QByteArrayLiteral("text/javascript");
    if (ext == QLatin1String("css")) return QByteArrayLiteral("text/css");
    if (ext == QLatin1String("json")) return QByteArrayLiteral("application/json");
    if (ext == QLatin1String("png")) return QByteArrayLiteral("image/png");
    if (ext == QLatin1String("jpg") || ext == QLatin1String("jpeg")) return QByteArrayLiteral("image/jpeg");
    if (ext == QLatin1String("gif")) return QByteArrayLiteral("image/gif");
    if (ext == QLatin1String("webp")) return QByteArrayLiteral("image/webp");
    if (ext == QLatin1String("svg")) return QByteArrayLiteral("image/svg+xml");
    if (ext == QLatin1String("wasm")) return QByteArrayLiteral("application/wasm");
    if (ext == QLatin1String("woff")) return QByteArrayLiteral("font/woff");
    if (ext == QLatin1String("woff2")) return QByteArrayLiteral("font/woff2");
    if (ext == QLatin1String("ttf")) return QByteArrayLiteral("font/ttf");
    if (ext == QLatin1String("ico")) return QByteArrayLiteral("image/x-icon");
    if (ext == QLatin1String("mp3")) return QByteArrayLiteral("audio/mpeg");
    if (ext == QLatin1String("wav")) return QByteArrayLiteral("audio/wav");
    if (ext == QLatin1String("ogg")) return QByteArrayLiteral("audio/ogg");
    return QByteArrayLiteral("application/octet-stream");
}

class WebxdcSchemeHandler : public QWebEngineUrlSchemeHandler
{
public:
    void requestStarted(QWebEngineUrlRequestJob *job) override
    {
        const QUrl url = job->requestUrl();
        QString host;
        {
            QMutexLocker lock(&g_mutex);
            host = g_host;
        }
        // Only the live instance's own origin is served (an old/other instance gets nothing).
        if (host.isEmpty() || url.host().compare(host, Qt::CaseInsensitive) != 0) {
            job->fail(QWebEngineUrlRequestJob::UrlNotFound);
            return;
        }

        // QUrl::path() is already percent-decoded (including %2F - see resolveInRoot);
        // query/fragment are excluded. Strip leading slashes so root-absolute asset refs
        // (`/assets/x.js`) resolve into the app dir.
        QString path = url.path();
        while (path.startsWith(QLatin1Char('/')))
            path.remove(0, 1);
        if (path.isEmpty())
            path = QStringLiteral("index.html");

        if (path == QLatin1String("__bridge__")) {
            // Only the app's own documents may drive the bridge: a page of another origin
            // could otherwise reach it with a no-cors POST.
            const QUrl initiator = job->initiator();
            if (initiator.scheme() != QLatin1String("webxdc")
                || initiator.host().compare(host, Qt::CaseInsensitive) != 0) {
                job->fail(QWebEngineUrlRequestJob::RequestDenied);
                return;
            }
            // requestBody() hands over the device unopened — open it or readAll() returns
            // nothing ("QIODevice::read: device not open") and app clicks go nowhere.
            QIODevice *body = job->requestBody();
            QByteArray data;
            if (body) {
                if (!body->isOpen())
                    body->open(QIODevice::ReadOnly);
                data = body->readAll();
            }
            mxc_webxdc_bridge_message(data.constData(), static_cast<size_t>(data.size()));
            auto *buf = new QBuffer(job);
            buf->setData(QByteArrayLiteral("{}"));
            job->reply(QByteArrayLiteral("application/json"), buf);
            return;
        }

        QByteArray bytes;
        QByteArray mime;
        {
            QMutexLocker lock(&g_mutex);
            if (path == QLatin1String("webxdc.js")) {
                bytes = g_js;
                mime = QByteArrayLiteral("text/javascript");
            } else {
                const QString file = resolveInRoot(path);
                if (!file.isEmpty()) {
                    QFile f(file);
                    if (f.open(QIODevice::ReadOnly))
                        bytes = f.readAll();
                } else if (path.contains(QLatin1Char('\\'))
                           || path.split(QLatin1Char('/')).contains(QStringLiteral(".."))
                           || QFileInfo::exists(g_root + QLatin1Char('/') + path)) {
                    // Traversal attempt, or an existing file outside the app dir (symlink).
                    job->fail(QWebEngineUrlRequestJob::RequestDenied);
                    return;
                }
                // A missing asset serves empty (not an error page), like the GTK client.
                mime = mimeFor(path);
            }
        }
        QMultiMap<QByteArray, QByteArray> headers;
        if (mime == QByteArrayLiteral("text/html")) {
            bytes = injectWebRtcBlocker(bytes);
            headers.insert(QByteArrayLiteral("Content-Security-Policy"), kCsp);
        } else if (mime == QByteArrayLiteral("image/svg+xml")) {
            headers.insert(QByteArrayLiteral("Content-Security-Policy"), kNoScriptCsp);
        } else {
            headers.insert(QByteArrayLiteral("Content-Security-Policy"), kCsp);
        }
        headers.insert(QByteArrayLiteral("X-DNS-Prefetch-Control"), QByteArrayLiteral("off"));
        job->setAdditionalResponseHeaders(headers);
        auto *buf = new QBuffer(job);
        buf->setData(bytes);
        job->reply(mime, buf);
    }
};

WebxdcSchemeHandler *g_handler = nullptr;
OfflineInterceptor *g_interceptor = nullptr;

} // namespace

extern "C" void mxc_webxdc_pre_app_init()
{
    QtWebEngineQuick::initialize();
    QWebEngineUrlScheme scheme(QByteArrayLiteral("webxdc"));
    scheme.setSyntax(QWebEngineUrlScheme::Syntax::Host);
    scheme.setFlags(QWebEngineUrlScheme::SecureScheme
                    | QWebEngineUrlScheme::CorsEnabled
                    | QWebEngineUrlScheme::FetchApiAllowed);
    QWebEngineUrlScheme::registerScheme(scheme);
}

extern "C" void mxc_webxdc_install(const char *root, const char *js, const char *host)
{
    {
        QMutexLocker lock(&g_mutex);
        g_root = QString::fromUtf8(root);
        g_js = QByteArray(js);
        g_host = QString::fromUtf8(host);
    }
    auto *profile = QQuickWebEngineProfile::defaultProfile();
    if (!g_handler) {
        g_handler = new WebxdcSchemeHandler();
        profile->installUrlSchemeHandler(QByteArrayLiteral("webxdc"), g_handler);
    }
    if (!g_interceptor) {
        g_interceptor = new OfflineInterceptor();
        profile->setUrlRequestInterceptor(g_interceptor);
    }
}
