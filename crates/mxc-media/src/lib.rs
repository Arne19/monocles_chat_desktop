//! GStreamer `webrtcbin` media engine for Jingle RTP calls (the media half of XEP-0166/0167).
//!
//! This crate is deliberately XMPP-agnostic: it speaks **SDP + ICE candidates**. The XMPP
//! side ([`mxc_proto`]) maps the SDP/ICE here to/from Jingle stanzas. Keeping GStreamer behind
//! this seam means the dependency (and its system libs) is isolated to one crate.
//!
//! Audio-only for now (Opus); video (VP8 + a GTK paintable sink) is a follow-up.

use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;
use gstreamer_sdp as gst_sdp;
use gstreamer_webrtc as gst_webrtc;

/// A decoded video frame (RGBA), pushed from an `appsink` to the UI for display.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub width: u32,
    pub height: u32,
    /// Tightly-packed RGBA8 pixels (`width * height * 4` bytes).
    pub data: Vec<u8>,
    /// True for our own camera preview, false for the remote peer's video.
    pub local: bool,
}

type VideoTx = async_channel::Sender<VideoFrame>;

/// Which side of the negotiation we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We place the call → we create the SDP offer.
    Caller,
    /// We answer the call → we create the SDP answer to the peer's offer.
    Callee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpKind {
    Offer,
    Answer,
}

/// Something the engine produced that the signalling layer must send to the peer (or a state
/// change to surface in the UI).
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// Our local SDP description is ready (offer if caller, answer if callee). `renegotiation`
    /// is true for a mid-call re-offer/answer (e.g. an audio→video upgrade) — the signalling
    /// layer maps those to Jingle `content-add`/`content-accept` instead of session-initiate.
    LocalDescription { kind: SdpKind, sdp: String, renegotiation: bool },
    /// A locally-gathered ICE candidate to trickle to the peer.
    IceCandidate { mline_index: u32, candidate: String },
    /// Media is flowing (ICE connected).
    Connected,
    /// The call failed.
    Failed(String),
}

type Tx = async_channel::Sender<EngineEvent>;

/// One audio call's media session.
pub struct CallEngine {
    pipeline: gst::Pipeline,
    webrtc: gst::Element,
    role: Role,
    tx: Tx,
    /// Frame sink for the local camera preview (wired when video is added, incl. mid-call).
    video_tx: VideoTx,
    /// Active screen-share state (PipeWire source bin + the portal session keeping the cast
    /// alive), if the user is currently sharing their screen. `None` otherwise.
    screen: Mutex<Option<ScreenState>>,
    /// For a group (Muji) video leg, the shared [`camera_hub`] channel this engine's camera is
    /// relayed over; released on drop so the hub can stop the camera when the last leg ends.
    /// `None` for audio-only or 1:1 calls (which use `autovideosrc` directly).
    cam_channel: Mutex<Option<String>>,
    /// Whether this is a group-call leg (uses the shared camera hub when video is added).
    shared_camera: bool,
}

/// A live screen-capture stream obtained from the xdg-desktop-portal ScreenCast portal.
/// Holds the portal session/proxy alive: dropping it tells the compositor to stop the cast and
/// invalidates the PipeWire fd.
pub struct ScreenShare {
    // Kept alive for the duration of the stream; their Drop ends the portal session.
    _proxy: ashpd::desktop::screencast::Screencast,
    _session: ashpd::desktop::Session<ashpd::desktop::screencast::Screencast>,
    /// PipeWire remote fd (from `OpenPipeWireRemote`); consumed by `pipewiresrc fd=…`.
    fd: std::os::fd::OwnedFd,
    /// PipeWire node id of the selected screen/window stream (`pipewiresrc path=…`).
    node_id: u32,
}

impl ScreenShare {
    /// The PipeWire remote fd to hand a `pipewiresrc fd=…`. Valid only while `self` is alive.
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
    /// The PipeWire node id of the selected stream (`pipewiresrc path=…`).
    pub fn node_id(&self) -> u32 {
        self.node_id
    }
}

/// Engine-internal bookkeeping for an active screen share: the GStreamer source bin we added to
/// the live pipeline, the `vidsel` request pad it feeds, and the portal handle to keep alive.
struct ScreenState {
    _share: ScreenShare,
    bin: gst::Element,
    pad: gst::Pad,
}

impl CallEngine {
    /// Initialise GStreamer once for the process. Safe to call repeatedly.
    pub fn init() -> Result<()> {
        gst::init().context("gst::init")?;
        Ok(())
    }

    /// Build the pipeline and return the engine, the [`EngineEvent`] channel (signalling), and
    /// the [`VideoFrame`] channel (decoded RGBA frames for the UI; empty for audio-only calls).
    ///
    /// Tries an echo-cancelling pipeline first; if it can't reach `Playing` on this system
    /// (e.g. `webrtcdsp`/`webrtcechoprobe` unavailable), falls back to a plain pipeline so a
    /// call never fails just because AEC isn't available.
    pub fn new(
        role: Role,
        video: bool,
        shared_camera: bool,
    ) -> Result<(Self, async_channel::Receiver<EngineEvent>, async_channel::Receiver<VideoFrame>)> {
        Self::init()?;
        // Bounded so a slow UI drops frames rather than growing memory.
        let (vtx, vrx) = async_channel::bounded::<VideoFrame>(4);

        // Group (Muji) video legs share one camera capture via the hub (a v4l2 camera opens
        // once); 1:1 video keeps `autovideosrc`. Acquire the relay channel up front so it's
        // reused across the AEC/plain build attempts (the hub consumer outlives a discarded
        // call pipeline).
        let cam_channel = if video && shared_camera {
            match camera_hub::acquire() {
                Ok(ch) => Some(ch),
                Err(e) => {
                    tracing::warn!(error = %e, "camera hub acquire failed — falling back to direct camera");
                    None
                }
            }
        } else {
            None
        };

        // Try the echo-cancelling pipeline (webrtcdsp + webrtcechoprobe) first; if it can't
        // reach Playing on this system (e.g. gst-plugins-bad's webrtcdsp is missing), fall back
        // to the plain pipeline so a call never fails just because AEC is unavailable.
        // Always pass the video sink so an incoming video pad (e.g. after a mid-call upgrade) is
        // handled even on a call that started audio-only.
        let mut last_err = None;
        for aec in [true, false] {
            let desc = pipeline_desc(video, aec, cam_channel.as_deref());
            // The AEC attempt waits only briefly so a failure falls back fast (the local audio
            // graph reaches Playing almost instantly); the plain attempt gets the full window.
            let wait_secs = if aec { 2 } else { 3 };
            // Each attempt gets its own signalling channel: a discarded attempt's webrtcbin may
            // already have created an offer (caller) + gathered ICE before it was torn down. On a
            // shared channel that stale SDP — other ICE credentials, a transport that no longer
            // exists — would reach the peer as a second session-initiate.
            let (tx, rx) = async_channel::unbounded::<EngineEvent>();
            match build_and_play(&desc, role, &tx, vtx.clone(), wait_secs, shared_camera) {
                Ok((pipeline, webrtc, _negotiated)) => {
                    tracing::info!(video, aec, shared_camera, "call pipeline started");
                    return Ok((
                        CallEngine {
                            pipeline,
                            webrtc,
                            role,
                            tx,
                            video_tx: vtx,
                            screen: Mutex::new(None),
                            cam_channel: Mutex::new(cam_channel),
                            shared_camera,
                        },
                        rx,
                        vrx,
                    ));
                }
                Err(e) => {
                    tracing::warn!(aec, error = %e, "call pipeline failed to start");
                    last_err = Some(e);
                }
            }
        }
        if let Some(ch) = &cam_channel {
            camera_hub::release(ch);
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no call pipeline")))
    }

    /// Add a video send branch (camera + black-source selector + VP8) to the live session and
    /// link it to a new webrtcbin sink pad. Shared by the outgoing upgrade (we re-offer) and the
    /// incoming upgrade (we answer the peer's content-add). No-op if video is already present.
    /// Returns the new webrtcbin sink pad, or `None` if the branch already existed.
    fn add_video_send_branch(&self) -> Result<Option<gst::Pad>> {
        if self.pipeline.by_name("vidsel").is_some() {
            return Ok(None);
        }
        // Group legs relay the shared camera over an `intervideosrc` channel; 1:1 uses autovideosrc.
        let cam_channel = if self.shared_camera {
            match camera_hub::acquire() {
                Ok(ch) => {
                    *self.cam_channel.lock().unwrap() = Some(ch.clone());
                    Some(ch)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "camera hub acquire failed (upgrade) — direct camera");
                    None
                }
            }
        } else {
            None
        };
        let bin = gst::parse::bin_from_description(&video_send_bin(cam_channel.as_deref()), true)
            .context("parse video send bin")?
            .upcast::<gst::Element>();
        self.pipeline.add(&bin).context("add video bin")?;
        // The camera is a LIVE source added to an already-running pipeline. It MUST share the
        // pipeline's clock and base time, or its buffer timestamps don't line up with the running
        // stream and it stalls after the first (preroll) frame → frozen self-preview + black to
        // the peer. (In the initial video call all elements start together, so this is implicit.)
        if let Some(clock) = self.pipeline.clock() {
            bin.set_base_time(self.pipeline.base_time().unwrap_or(gst::ClockTime::ZERO));
            let _ = bin.set_clock(Some(&clock));
        }
        // Wire the local self-preview appsink (pipeline.by_name recurses into the added bin).
        match self.pipeline.by_name("localvideo") {
            Some(sink) => wire_video_appsink(&sink, self.video_tx.clone(), true),
            None => tracing::warn!("video upgrade: localvideo appsink not found — no self-preview"),
        }
        // Link the bin's (ghosted) RTP src → a new webrtcbin sink pad.
        let sinkpad = link_send_bin(&self.webrtc, &bin)?;
        bin.sync_state_with_parent().context("sync video bin")?;
        // Ensure the live camera (sink_0), not the black source (sink_1), is selected.
        self.set_video_enabled(true);
        // A live source just joined → redistribute latency so its buffers aren't treated as late.
        let _ = self.pipeline.recalculate_latency();
        Ok(Some(sinkpad))
    }

    /// Mid-call OUTGOING upgrade: add our video branch and re-offer, so the engine emits a
    /// renegotiation `LocalDescription{Offer}` → Jingle `content-add`.
    pub fn upgrade_to_video(&self) -> Result<()> {
        if self.pipeline.by_name("vidsel").is_some() {
            return Ok(());
        }
        let pad = self.add_video_send_branch()?;
        // Drive the re-offer explicitly (the on-negotiation-needed handler is gated off after the
        // first offer, so it won't double-offer here) — once the new pad is ready.
        let (webrtc, tx) = (self.webrtc.clone(), self.tx.clone());
        after_send_caps(pad, move || create_offer(&webrtc, tx, true));
        Ok(())
    }

    /// Mid-call INCOMING upgrade: apply the peer's renegotiation offer (full SDP = existing audio
    /// + their new video) and create the renegotiation answer → Jingle `content-accept`.
    ///
    /// We add our own camera transceiver BEFORE `set_remote`, so webrtcbin associates the offer's
    /// video m-line with our sending track (→ a sendrecv answer carrying our SSRC). Requesting the
    /// pad *after* set-remote instead created a separate transceiver, leaving the answered video
    /// m-line recvonly (no SSRC) → we sent nothing (black to peer) and the encoder backed up,
    /// stalling the camera tee (frozen self-preview).
    pub fn apply_video_offer(&self, sdp: &str) -> Result<()> {
        let desc = remote_description(SdpKind::Offer, sdp)?;
        let pad = self.add_video_send_branch()?;
        // Answer once our camera's pad has caps, so the answer carries our sending track (SSRC).
        let (webrtc, tx) = (self.webrtc.clone(), self.tx.clone());
        after_send_caps(pad, move || {
            webrtc.emit_by_name::<()>("set-remote-description", &[&desc, &None::<gst::Promise>]);
            create_answer(&webrtc, tx, true);
        });
        Ok(())
    }

    /// Group-call (Muji) leg: start sending our camera on this session — add the video branch if
    /// the pipeline doesn't have one yet, then re-offer (→ Jingle `content-add` of a new video
    /// m-line). Unlike [`Self::upgrade_to_video`] this also re-offers when the branch already
    /// exists but was never negotiated (e.g. we answered an audio-only offer from a participant
    /// who joined without video).
    pub fn offer_video(&self) -> Result<()> {
        let pad = self.add_video_send_branch()?;
        let (webrtc, tx) = (self.webrtc.clone(), self.tx.clone());
        after_send_caps(pad, move || create_offer(&webrtc, tx, true));
        Ok(())
    }

    /// Mid-call renegotiation offer from the peer that we answer WITHOUT adding our camera: a
    /// group-call participant turned their camera on (we receive only), or changed which side
    /// sends on an existing m-line. Emits a renegotiation `LocalDescription{Answer}`.
    pub fn apply_remote_offer(&self, sdp: &str) -> Result<()> {
        self.set_remote(SdpKind::Offer, sdp)?;
        create_answer(&self.webrtc, self.tx.clone(), true);
        Ok(())
    }

    /// Set a remote description on webrtcbin (no follow-up). Shared by the initial flow and
    /// renegotiation.
    fn set_remote(&self, kind: SdpKind, sdp: &str) -> Result<()> {
        let desc = remote_description(kind, sdp)?;
        self.webrtc
            .emit_by_name::<()>("set-remote-description", &[&desc, &None::<gst::Promise>]);
        Ok(())
    }

    /// Apply the peer's SDP. For the callee, an initial `Offer` triggers creating + emitting the
    /// answer. (Renegotiation offers — the incoming video upgrade — go via `apply_video_offer`.)
    pub fn set_remote_description(&self, kind: SdpKind, sdp: &str) -> Result<()> {
        self.set_remote(kind, sdp)?;
        if self.role == Role::Callee && kind == SdpKind::Offer {
            create_answer(&self.webrtc, self.tx.clone(), false);
        }
        Ok(())
    }

    /// Add a remote ICE candidate (trickled from the peer).
    pub fn add_remote_ice(&self, mline_index: u32, candidate: &str) {
        self.webrtc
            .emit_by_name::<()>("add-ice-candidate", &[&mline_index, &candidate]);
    }

    /// Mute / unmute the microphone (toggles the `volume` gate in the send chain).
    pub fn set_mic_muted(&self, muted: bool) {
        if let Some(vol) = self.pipeline.by_name("micvol") {
            vol.set_property("mute", muted);
        }
    }

    /// Turn the camera on/off during a video call. Switches the `vidsel` input-selector between
    /// the live camera (sink_0) and a black frame source (sink_1), so the peer sees a black
    /// screen while off (not a frozen frame). No-op on an audio-only call (no video branch).
    pub fn set_video_enabled(&self, enabled: bool) {
        let Some(sel) = self.pipeline.by_name("vidsel") else { return };
        let want = if enabled { "sink_0" } else { "sink_1" };
        if let Some(pad) = sel.sink_pads().into_iter().find(|p| p.name() == want) {
            sel.set_property("active-pad", &pad);
        }
    }

    /// Start sharing the screen captured via [`capture_screen`]. The screen replaces the camera as
    /// the single outgoing video track (per the chosen "switch" model): we add the video send
    /// branch if the call was audio-only (re-offering → Jingle `content-add`), feed the portal's
    /// PipeWire stream into a new `vidsel` input, and select it. Restores on [`stop_screen_share`].
    pub fn start_screen_share(&self, screen: ScreenShare) -> Result<()> {
        // If there's no video branch yet (audio-only call) we must also re-offer so the peer
        // learns we now send video. add_video_send_branch is idempotent.
        let need_offer = self.pipeline.by_name("vidsel").is_none();
        let pad = self.add_video_send_branch()?;
        self.attach_screen(screen)?;
        if need_offer {
            // Drive the renegotiation offer (→ content-add); on-negotiation-needed is gated off.
            let (webrtc, tx) = (self.webrtc.clone(), self.tx.clone());
            after_send_caps(pad, move || create_offer(&webrtc, tx, true));
        }
        Ok(())
    }

    /// Build a `pipewiresrc` from the portal stream, splice it into `vidsel` as a new input, and
    /// switch the selector to it. The screen is sent at 720p (vs the camera's 480p) for legibility,
    /// so the encoder renegotiates resolution on switch; VP8 handles that with a keyframe.
    fn attach_screen(&self, screen: ScreenShare) -> Result<()> {
        let sel = self
            .pipeline
            .by_name("vidsel")
            .ok_or_else(|| anyhow!("no vidsel to attach screen to"))?;
        // The portal hands us a PipeWire fd + node id; pipewiresrc streams from it. Scale/convert
        // to the encoder's pixel format at 720p30 (a live source → it shares the pipeline clock).
        // NOTE: the chain MUST end in a real element (here a `queue`), not a caps — a bin
        // description ending in `! caps` is a parse syntax error, and we also need a ghostable src
        // pad to link into `vidsel`. The capsfilter just before forces I420 720p (matching the
        // encoder), and the queue decouples the live PipeWire source.
        let desc = format!(
            "pipewiresrc fd={} path={} do-timestamp=true ! videoconvert ! videoscale ! videorate ! \
             video/x-raw,format=I420,width=1280,height=720,framerate=30/1 ! queue",
            screen.fd.as_raw_fd(),
            screen.node_id
        );
        let bin = gst::parse::bin_from_description(&desc, true)
            .map_err(|e| anyhow!("parse screen-capture bin: {e}"))?
            .upcast::<gst::Element>();
        self.pipeline.add(&bin).context("add screen bin")?;
        // Live source joining a running pipeline: share clock + base time (see add_video_send_branch).
        if let Some(clock) = self.pipeline.clock() {
            bin.set_base_time(self.pipeline.base_time().unwrap_or(gst::ClockTime::ZERO));
            let _ = bin.set_clock(Some(&clock));
        }
        let src = bin
            .src_pads()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("screen bin has no src pad"))?;
        let sinkpad = sel
            .request_pad_simple("sink_%u")
            .ok_or_else(|| anyhow!("vidsel sink pad request failed"))?;
        src.link(&sinkpad).context("link screen bin → vidsel")?;
        bin.sync_state_with_parent().context("sync screen bin")?;
        // Switch the selector to the screen input.
        sel.set_property("active-pad", &sinkpad);
        // Screen content (text/UI) needs more bitrate than a talking-head camera to stay legible.
        if let Some(enc) = self.pipeline.by_name("venc") {
            enc.set_property("target-bitrate", 2_500_000i32);
        }
        let _ = self.pipeline.recalculate_latency();
        *self.screen.lock().unwrap() = Some(ScreenState { _share: screen, bin, pad: sinkpad });
        Ok(())
    }

    /// Stop screen sharing and switch the outgoing video track back to the live camera. Tears down
    /// the PipeWire source and drops the portal session (ending the cast). No-op if not sharing.
    pub fn stop_screen_share(&self) {
        let Some(state) = self.screen.lock().unwrap().take() else {
            return;
        };
        // Back to the camera input before removing the screen source.
        self.set_video_enabled(true);
        if let Some(enc) = self.pipeline.by_name("venc") {
            enc.set_property("target-bitrate", 1_000_000i32);
        }
        let _ = state.bin.set_state(gst::State::Null);
        let _ = self.pipeline.remove(&state.bin);
        if let Some(sel) = self.pipeline.by_name("vidsel") {
            sel.release_request_pad(&state.pad);
        }
        let _ = self.pipeline.recalculate_latency();
        // `state` (and its ScreenShare → portal session) dropped here → the compositor stops casting.
    }

    /// Tear the call down explicitly (also happens on drop).
    pub fn hang_up(self) {
        // `Drop` sets the pipeline to Null.
    }
}

/// Negotiate a screen/window capture via the xdg-desktop-portal ScreenCast portal. This shows the
/// compositor's own screen/window picker (Wayland and X11 both go through the portal), then yields
/// a PipeWire fd + node id we hand to `pipewiresrc`. The returned [`ScreenShare`] must be kept
/// alive for the duration of the share (its Drop ends the cast). Cancelling the picker is an Err.
pub async fn capture_screen() -> Result<ScreenShare> {
    use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};

    let proxy = Screencast::new().await.context("connect ScreenCast portal")?;
    // ashpd 0.13 replaced the positional create_session/select_sources/start args with builder
    // option structs; PersistMode::DoNot and "no restore token" are the defaults we want.
    let session = proxy
        .create_session(Default::default())
        .await
        .context("create portal session")?;
    proxy
        .select_sources(
            &session,
            SelectSourcesOptions::default()
                .set_cursor_mode(CursorMode::Embedded)
                .set_sources(SourceType::Monitor | SourceType::Window)
                .set_multiple(false),
        )
        .await
        .context("select screen sources")?;
    let streams = proxy
        .start(&session, None, Default::default())
        .await
        .context("start screen cast")?
        .response()
        .context("screen cast cancelled or failed")?;
    let node_id = streams
        .streams()
        .first()
        .ok_or_else(|| anyhow!("portal returned no screen-cast stream"))?
        .pipe_wire_node_id();
    let fd = proxy
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .context("open PipeWire remote")?;
    Ok(ScreenShare { _proxy: proxy, _session: session, fd, node_id })
}

impl Drop for CallEngine {
    fn drop(&mut self) {
        // Always return the pipeline to NULL so child elements are cleaned up (avoids
        // "disposed while in PLAYING state" criticals when a call ends/fails).
        let _ = self.pipeline.set_state(gst::State::Null);
        // Release our shared-camera relay channel; the hub stops the camera when the last leg ends.
        if let Some(ch) = self.cam_channel.lock().unwrap().take() {
            camera_hub::release(&ch);
        }
    }
}

/// The pipeline description for an audio (optionally + video) call. Separate gst-launch chains
/// are space-separated; `webrtc.` links back to the named `webrtcbin`.
///
/// With `aec`, acoustic echo cancellation runs in-pipeline: `webrtcdsp` on the mic (near-end)
/// path removes the far-end audio the mic picks up from the speakers, using `webrtcechoprobe`
/// (on a persistent `audiomixer`→speaker playback chain) as the loudspeaker reference. The
/// incoming remote audio is mixed into that `outmix` (see [`link_incoming_audio`]) so the probe
/// sees exactly what's played. `delay-agnostic` copes with the variable mic↔speaker latency of
/// laptops (where fixed-delay AEC otherwise fails and you hear your own voice back).
/// The camera source element. For a group call (`Some(channel)`) the camera is captured once by
/// the shared [`camera_hub`] and relayed to each leg via `intervideosrc` — so N legs don't each
/// try to open the (single-open) v4l2 device. For a 1:1 call with no channel, the best real
/// color camera (see [`raw_camera_element`]).
fn camera_src(cam_channel: Option<&str>) -> String {
    match cam_channel {
        Some(ch) => format!("intervideosrc channel={ch} do-timestamp=true"),
        None => raw_camera_element(),
    }
}

/// The actual capture-source element string for a directly-opened camera. On Linux laptops with
/// several `/dev/video*` nodes (IR/face-unlock sensors, depth cams, metadata nodes, a UVC webcam's
/// extra nodes) a plain `autovideosrc` grabs the first node — often an infrared or non-capture one
/// that can't negotiate normal color video, so the call's video never starts. We therefore pick a
/// usable color camera explicitly via the GStreamer device monitor and pin `v4l2src device=…`.
/// Falls back to `autovideosrc` when enumeration finds nothing (or on non-v4l2 platforms).
fn raw_camera_element() -> String {
    // A valid user choice (still present) wins over the heuristic.
    if let Some(path) = PREFERRED_CAMERA.lock().unwrap().clone() {
        if list_cameras().iter().any(|(_, p)| p == &path) {
            tracing::info!(device = %path, "camera: using user-selected video source");
            return format!("v4l2src device={path}");
        }
        tracing::warn!(device = %path, "camera: selected device not present; auto-selecting");
    }
    match best_camera_device() {
        Some(path) => format!("v4l2src device={path}"),
        None => "autovideosrc".to_string(),
    }
}

/// The user's preferred camera device path (`None` = automatic). Set from the persisted setting at
/// startup and whenever the Settings picker changes; read when a call opens the camera.
static PREFERRED_CAMERA: Mutex<Option<String>> = Mutex::new(None);

/// Set the preferred camera device path; an empty/`None` value means automatic selection.
pub fn set_preferred_camera(path: Option<String>) {
    *PREFERRED_CAMERA.lock().unwrap() = path.filter(|p| !p.is_empty());
}

/// Enumerate usable color cameras as `(display_name, device_path)` for a settings picker —
/// the same set `best_camera_device` chooses from (IR/grayscale/metadata nodes excluded).
pub fn list_cameras() -> Vec<(String, String)> {
    let _ = gst::init();
    let monitor = gst::DeviceMonitor::new();
    let _ = monitor.add_filter(Some("Video/Source"), None);
    if monitor.start().is_err() {
        return Vec::new();
    }
    let devices = monitor.devices();
    monitor.stop();

    let mut out = Vec::new();
    for dev in devices {
        let Some(path) = camera_device_path(&dev) else { continue };
        if !path.starts_with("/dev/video") {
            continue;
        }
        if camera_score(&dev) < 0 {
            continue;
        }
        out.push((dev.display_name().to_string(), path));
    }
    out
}

/// Enumerate `Video/Source` devices and return the `/dev/video*` path of the best real color
/// camera, or `None` to fall back to `autovideosrc`. Grayscale-only (typical of IR sensors),
/// metadata-only and capabilities-less nodes are rejected; among the rest a device offering a
/// color raw format and/or MJPEG wins, with infrared-named devices penalised as a tiebreak.
fn best_camera_device() -> Option<String> {
    let _ = gst::init();
    let monitor = gst::DeviceMonitor::new();
    // Only video sources; we inspect each device's caps ourselves to weed out IR/metadata nodes.
    let _ = monitor.add_filter(Some("Video/Source"), None);
    if monitor.start().is_err() {
        return None;
    }
    let devices = monitor.devices();
    monitor.stop();

    let mut best: Option<(i32, String)> = None;
    for dev in devices {
        let Some(path) = camera_device_path(&dev) else { continue };
        // Restrict explicit selection to Linux v4l2 nodes; other platforms keep autovideosrc.
        if !path.starts_with("/dev/video") {
            continue;
        }
        let score = camera_score(&dev);
        if score < 0 {
            tracing::debug!(device = %path, name = %dev.display_name(), "camera: skipping non-color/metadata node");
            continue;
        }
        if best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
            best = Some((score, path));
        }
    }

    match &best {
        Some((_, path)) => tracing::info!(device = %path, "camera: selected video source"),
        None => tracing::warn!("camera: no suitable color video source found; using autovideosrc"),
    }
    best.map(|(_, p)| p)
}

/// Score a candidate camera: negative = unusable (reject), higher = preferred. A device is usable
/// only if it offers a color raw format or MJPEG; grayscale-only (`GREY`/`Y8`/`Y16`, typical of
/// infrared sensors) and metadata-only nodes score negative.
fn camera_score(dev: &gst::Device) -> i32 {
    let Some(caps) = dev.caps() else { return -1 };
    if caps.is_any() {
        return 1; // unknown caps — usable but not preferred
    }
    let mut has_color = false;
    let mut has_jpeg = false;
    for s in caps.iter() {
        match s.name().as_str() {
            "image/jpeg" => has_jpeg = true,
            n if n.starts_with("video/x-raw") => match s.get::<String>("format") {
                // A single grayscale format is the infrared/depth signature — not color.
                Ok(fmt) if matches!(fmt.as_str(), "GREY" | "Y8" | "Y16" | "GRAY8" | "GRAY16_LE") => {}
                // Any other single format, or a format *list* (get fails) → color-capable.
                _ => has_color = true,
            },
            _ => {} // metadata or other non-video caps — ignored
        }
    }
    if !has_color && !has_jpeg {
        return -1;
    }
    let mut score = 0;
    if has_color {
        score += 10;
    }
    if has_jpeg {
        score += 5;
    }
    // Penalise infrared sensors that still advertise a usable format (e.g. GREY + MJPEG), so a
    // real color camera is preferred. Match "infrared" or a standalone "ir" token (V4L2 names
    // like "Integrated Camera: Integrated IR") without false-matching words such as "mirror".
    let name = dev.display_name().to_string().to_lowercase();
    let is_ir =
        name.contains("infrared") || name.split(|c: char| !c.is_alphanumeric()).any(|t| t == "ir");
    if is_ir {
        score -= 50;
    }
    score
}

/// The `/dev/video*` path (Linux v4l2) for a device, from its monitor properties.
fn camera_device_path(dev: &gst::Device) -> Option<String> {
    let props = dev.properties()?;
    props
        .get::<String>("device.path")
        .ok()
        .or_else(|| props.get::<String>("api.v4l2.path").ok())
        .or_else(|| props.get::<String>("object.path").ok())
}

fn pipeline_desc(video: bool, aec: bool, cam_channel: Option<&str>) -> String {
    // Jitter-buffer depth: bigger absorbs more network jitter so fewer packets are treated as
    // lost (each loss currently causes a brief wait-for-keyframe freeze). 200 ms is a good
    // balance of smoothness vs. call latency.
    let audio: &str = if aec {
        // webrtcdsp wants S16LE at a fixed rate/channel count, matched on near + far ends.
        // A persistent silent source keeps `outmix` producing buffers from the start, so the
        // playback sink can preroll and the pipeline reaches Playing even before any remote
        // audio pad exists (an empty audiomixer never outputs → the sink would stall in Paused).
        "webrtcbin name=webrtc bundle-policy=max-bundle latency=200 \
         autoaudiosrc ! queue ! audioconvert ! audioresample ! \
         audio/x-raw,format=S16LE,rate=48000,channels=1 ! \
         webrtcdsp name=webrtcdsp probe=echoprobe echo-cancel=true noise-suppression=true \
         delay-agnostic=true extended-filter=true ! \
         volume name=micvol ! opusenc ! \
         rtpopuspay pt=111 ! application/x-rtp,media=audio,encoding-name=OPUS,payload=111 ! webrtc. \
         audiotestsrc is-live=true wave=silence ! \
         audio/x-raw,format=S16LE,rate=48000,channels=1 ! outmix. \
         audiomixer name=outmix ! audioconvert ! audioresample ! \
         audio/x-raw,format=S16LE,rate=48000,channels=1 ! \
         webrtcechoprobe name=echoprobe ! autoaudiosink"
    } else {
        "webrtcbin name=webrtc bundle-policy=max-bundle latency=200 \
         autoaudiosrc ! queue ! audioconvert ! audioresample ! volume name=micvol ! opusenc ! \
         rtpopuspay pt=111 ! application/x-rtp,media=audio,encoding-name=OPUS,payload=111 ! webrtc."
    };
    // Video send: camera → VP8 → webrtcbin, tee'd to a local-preview appsink (RGBA).
    // `target-bitrate=2 Mbps` (vs the 256 kbps default) and `error-resilient` markedly improve
    // quality and packet-loss recovery; `cpu-used=4` keeps realtime encoding fast enough.
    // `vidsel` (input-selector) switches the encoded feed between the live camera (sink_0) and
    // a black frame source (sink_1). Turning video off mid-call selects the black input, so the
    // peer sees a black screen rather than our frozen last frame. Both inputs are forced to the
    // same caps so switching is seamless; the black source is cheap to keep running.
    let video_chain = if video {
        format!(
            " input-selector name=vidsel ! tee name=camtee \
             {cam} ! videoconvert ! videoscale ! videorate ! \
             video/x-raw,format=I420,width=640,height=480,framerate=30/1 ! vidsel. \
             videotestsrc is-live=true pattern=black ! videoconvert ! \
             video/x-raw,format=I420,width=640,height=480,framerate=30/1 ! vidsel. \
             camtee. ! queue ! vp8enc name=venc deadline=1 cpu-used=4 target-bitrate=1000000 \
             error-resilient=partitions keyframe-max-dist=15 ! \
             rtpvp8pay pt=96 ! application/x-rtp,media=video,encoding-name=VP8,payload=96 ! webrtc. \
             camtee. ! queue leaky=downstream ! videoconvert ! videoscale ! \
             video/x-raw,format=RGBA,width=140,height=105 ! \
             appsink name=localvideo emit-signals=false sync=false drop=true max-buffers=2",
            cam = camera_src(cam_channel),
        )
    } else {
        String::new()
    };
    format!("{audio}{video_chain}")
}

/// The video send branch as a standalone bin (no `! webrtc.` link, so the RTP payloader's src
/// pad is left unlinked → `bin_from_description` ghosts it). Used to add video to a live call
/// for the mid-call audio→video upgrade; the ghost src is linked to a new webrtcbin sink pad.
// NOTE: the encoder chain ends at `rtpvp8pay` so its (unlinked) src pad is the bin's single
// ghost pad, linked to a new webrtcbin sink. `pt=96` makes its src caps carry the VP8/payload
// info webrtcbin needs, so no trailing capsfilter is required (and a chain can't end in caps).
fn video_send_bin(cam_channel: Option<&str>) -> String {
    format!(
        "input-selector name=vidsel ! tee name=camtee \
         {cam} ! videoconvert ! videoscale ! videorate ! \
         video/x-raw,format=I420,width=640,height=480,framerate=30/1 ! vidsel. \
         videotestsrc is-live=true pattern=black ! videoconvert ! \
         video/x-raw,format=I420,width=640,height=480,framerate=30/1 ! vidsel. \
         camtee. ! queue leaky=downstream ! videoconvert ! videoscale ! \
         video/x-raw,format=RGBA,width=140,height=105 ! \
         appsink name=localvideo emit-signals=false sync=false drop=true max-buffers=2 \
         camtee. ! queue leaky=downstream ! vp8enc name=venc deadline=1 cpu-used=4 target-bitrate=1000000 \
         error-resilient=partitions keyframe-max-dist=15 ! rtpvp8pay pt=96",
        cam = camera_src(cam_channel),
    )
}

/// Shared camera capture for group (Muji) video calls.
///
/// A v4l2 camera can only be opened once, so N concurrent call pipelines can't each run
/// `autovideosrc`. Instead one hub pipeline captures the camera once (`autovideosrc → tee`) and
/// relays it to each call leg over a private `intervideosink`/`intervideosrc` channel. The hub is
/// reference-counted: it starts on the first video leg and stops (releasing the camera) when the
/// last one ends. 1:1 calls don't use it (they keep `autovideosrc`), so this never touches the
/// existing 1:1/2-party video path.
mod camera_hub {
    use super::*;
    use std::collections::HashMap;

    struct Consumer {
        tee_pad: gst::Pad,
        queue: gst::Element,
        sink: gst::Element,
    }

    struct HubState {
        pipeline: gst::Pipeline,
        tee: gst::Element,
        /// `input-selector` whose source is switched between the camera (sink_0) and, while
        /// sharing, a screen `pipewiresrc` input — so every group leg relays the screen at once.
        selector: gst::Element,
        counter: u64,
        consumers: HashMap<String, Consumer>,
        /// The active screen-share source bin + its selector pad, while sharing.
        screen: Option<(gst::Element, gst::Pad)>,
    }

    static HUB: Mutex<Option<HubState>> = Mutex::new(None);

    /// Start the hub if needed and add a relay channel; returns the `intervideosrc` channel name.
    pub fn acquire() -> Result<String> {
        let mut guard = HUB.lock().unwrap();
        if guard.is_none() {
            // The camera feeds an input-selector (sink_0) so its source can later be switched to a
            // shared screen without disturbing the per-leg relays downstream of the tee.
            let pipeline = gst::parse::launch(&format!(
                "input-selector name=camhubsel ! videoconvert ! videoscale ! videorate ! \
                 video/x-raw,format=I420,width=640,height=480,framerate=30/1 ! \
                 tee name=camhubtee allow-not-linked=true \
                 {cam} ! queue ! camhubsel.",
                cam = super::raw_camera_element(),
            ))
            .context("build camera hub pipeline")?
            .downcast::<gst::Pipeline>()
            .map_err(|_| anyhow!("camera hub is not a pipeline"))?;
            let tee = pipeline
                .by_name("camhubtee")
                .ok_or_else(|| anyhow!("camera hub: no tee"))?;
            let selector = pipeline
                .by_name("camhubsel")
                .ok_or_else(|| anyhow!("camera hub: no selector"))?;
            pipeline.set_state(gst::State::Playing).context("camera hub → Playing")?;
            tracing::info!("camera hub started (shared capture for group video)");
            *guard = Some(HubState {
                pipeline,
                tee,
                selector,
                counter: 0,
                consumers: HashMap::new(),
                screen: None,
            });
        }
        let hub = guard.as_mut().unwrap();
        hub.counter += 1;
        let channel = format!("mxc-cam-{}", hub.counter);

        let queue = gst::ElementFactory::make("queue").build().context("camera hub queue")?;
        let sink = gst::ElementFactory::make("intervideosink")
            .property("channel", &channel)
            .property("sync", false)
            .property("async", false)
            .build()
            .context("camera hub intervideosink")?;
        hub.pipeline.add_many([&queue, &sink]).context("add hub consumer")?;
        queue.link(&sink).context("link hub queue → sink")?;
        let tee_pad = hub
            .tee
            .request_pad_simple("src_%u")
            .ok_or_else(|| anyhow!("camera hub: tee pad request failed"))?;
        let qsink = queue.static_pad("sink").ok_or_else(|| anyhow!("hub queue has no sink pad"))?;
        tee_pad.link(&qsink).map_err(|e| anyhow!("link hub tee → queue: {e:?}"))?;
        queue.sync_state_with_parent().ok();
        sink.sync_state_with_parent().ok();
        hub.consumers.insert(channel.clone(), Consumer { tee_pad, queue, sink });
        Ok(channel)
    }

    /// Drop a relay channel; stop the hub (releasing the camera) when the last one is gone.
    pub fn release(channel: &str) {
        let mut guard = HUB.lock().unwrap();
        let Some(hub) = guard.as_mut() else { return };
        if let Some(c) = hub.consumers.remove(channel) {
            let _ = c.queue.set_state(gst::State::Null);
            let _ = c.sink.set_state(gst::State::Null);
            let _ = hub.pipeline.remove_many([&c.queue, &c.sink]);
            hub.tee.release_request_pad(&c.tee_pad);
        }
        if hub.consumers.is_empty() {
            let _ = hub.pipeline.set_state(gst::State::Null);
            tracing::info!("camera hub stopped (no more group-video legs)");
            *guard = None;
        }
    }

    /// Switch the hub's source from the camera to a screen captured via the portal (`fd` + PipeWire
    /// `node_id`). Every group leg reads the hub, so all peers immediately see the screen. The
    /// caller MUST keep the `ScreenShare` alive (it owns the portal session + fd) until `clear_screen`.
    pub fn set_screen(fd: std::os::fd::RawFd, node_id: u32) -> Result<()> {
        let mut guard = HUB.lock().unwrap();
        let hub = guard
            .as_mut()
            .ok_or_else(|| anyhow!("no camera hub (screen share needs an active group video call)"))?;
        // Drop any previous screen source first.
        if let Some((bin, pad)) = hub.screen.take() {
            let _ = bin.set_state(gst::State::Null);
            let _ = hub.pipeline.remove(&bin);
            hub.selector.release_request_pad(&pad);
        }
        let desc = format!(
            "pipewiresrc fd={fd} path={node_id} do-timestamp=true ! videoconvert ! queue"
        );
        let bin = gst::parse::bin_from_description(&desc, true)
            .map_err(|e| anyhow!("parse screen-capture bin: {e}"))?
            .upcast::<gst::Element>();
        hub.pipeline.add(&bin).context("add hub screen bin")?;
        // Live source joining a running pipeline: share clock + base time.
        if let Some(clock) = hub.pipeline.clock() {
            bin.set_base_time(hub.pipeline.base_time().unwrap_or(gst::ClockTime::ZERO));
            let _ = bin.set_clock(Some(&clock));
        }
        let src = bin
            .src_pads()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("hub screen bin has no src pad"))?;
        let selpad = hub
            .selector
            .request_pad_simple("sink_%u")
            .ok_or_else(|| anyhow!("hub selector sink pad request failed"))?;
        src.link(&selpad).map_err(|e| anyhow!("link screen bin → hub selector: {e:?}"))?;
        bin.sync_state_with_parent().context("sync hub screen bin")?;
        hub.selector.set_property("active-pad", &selpad);
        hub.screen = Some((bin, selpad));
        tracing::info!("camera hub: sharing screen to group");
        Ok(())
    }

    /// Switch the hub's source back to the camera and tear down the screen capture. No-op if not
    /// sharing. The caller drops its `ScreenShare` afterwards to end the portal cast.
    pub fn clear_screen() {
        let mut guard = HUB.lock().unwrap();
        let Some(hub) = guard.as_mut() else { return };
        let Some((bin, pad)) = hub.screen.take() else { return };
        // Back to the camera (sink_0) before removing the screen source.
        if let Some(cam) = hub.selector.sink_pads().into_iter().find(|p| p.name() == "sink_0") {
            hub.selector.set_property("active-pad", &cam);
        }
        let _ = bin.set_state(gst::State::Null);
        let _ = hub.pipeline.remove(&bin);
        hub.selector.release_request_pad(&pad);
        tracing::info!("camera hub: stopped screen share, back to camera");
    }
}

/// Share `screen` (its raw fd + node id) to every leg of an active group video call by switching
/// the shared camera hub's source. The caller keeps the [`ScreenShare`] alive until it stops.
pub fn share_screen_to_group(fd: std::os::fd::RawFd, node_id: u32) -> Result<()> {
    camera_hub::set_screen(fd, node_id)
}

/// Stop a group screen share started with [`share_screen_to_group`] — the hub returns to camera.
pub fn stop_group_screen_share() {
    camera_hub::clear_screen();
}

/// An ICE server discovered via XEP-0215 (External Service Discovery), applied to every call's
/// `webrtcbin`. Without a TURN relay, calls fail ICE on restrictive networks (symmetric NAT /
/// UDP-blocking firewalls) where STUN alone can't find a usable candidate pair.
#[derive(Clone, Debug, Default)]
pub struct IceServer {
    pub kind: String,     // "stun" | "stuns" | "turn" | "turns"
    pub host: String,
    pub port: u16,
    pub transport: String, // "udp" | "tcp"
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Process-global ICE servers (set once after XEP-0215 discovery). `webrtcbin` is configured
/// from these at pipeline build time.
static ICE_SERVERS: Mutex<Vec<IceServer>> = Mutex::new(Vec::new());

/// Replace the ICE servers used by subsequent calls (called by the XMPP layer after XEP-0215
/// discovery resolves). Logs counts only — never the credentials.
pub fn set_ice_servers(servers: Vec<IceServer>) {
    let (stun, turn) = servers.iter().fold((0, 0), |(s, t), x| match x.kind.as_str() {
        "turn" | "turns" => (s, t + 1),
        _ => (s + 1, t),
    });
    tracing::info!(stun, turn, "ice servers configured (XEP-0215)");
    *ICE_SERVERS.lock().unwrap() = servers;
}

/// Percent-encode a TURN userinfo component (username/password) so credentials containing `:`,
/// `@`, `/`, `+`, `=` etc. don't corrupt the `turn://user:pass@host` URI webrtcbin parses.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Bracket an IPv6 literal host for use in a URI authority.
fn wrap_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Configure `webrtcbin`'s STUN + TURN servers from [`ICE_SERVERS`]. Falls back to public Google
/// STUN if discovery found none. Must be called before the pipeline reaches `Playing`.
fn configure_ice(webrtc: &gst::Element, muji: bool) {
    let servers = ICE_SERVERS.lock().unwrap().clone();
    // webrtcbin takes a single stun-server; prefer a discovered one, else public Google STUN.
    let stun = servers
        .iter()
        .find(|s| s.kind == "stun" || s.kind == "stuns")
        .map(|s| format!("stun://{}:{}", wrap_host(&s.host), s.port));
    webrtc.set_property_from_str(
        "stun-server",
        stun.as_deref().unwrap_or("stun://stun.l.google.com:19302"),
    );
    // TURN relays make ICE work behind symmetric NAT / restrictive firewalls. Add EVERY relay the
    // XMPP server advertises (XEP-0215) — in particular the TCP/TLS ones on :443/:80, which are
    // what traverse UDP-blocking firewalls.
    //
    // EXCEPTION — Muji group calls on a stock libnice: skip TCP/TLS relays. libnice 0.1.22 crashes
    // in a mesh (`priv_conn_check_tick_stream_nominate` assertion: a pair being nominated is not yet
    // SUCCEEDED) once several NiceAgents run connectivity checks at once — and TCP relay pairs,
    // which complete a TCP handshake before they can succeed, are reliably still in-progress when
    // the controlling agent's nominate tick fires, which is what trips the assertion. Because ICE
    // only pairs candidates of the same transport, simply not gathering local TCP relay candidates
    // removes all TCP pairs (no need to filter remote ones). 1:1 calls have a single agent and do
    // NOT hit this, so they always keep TCP/TLS relays.
    //
    // When running against a PATCHED libnice (see packaging/libnice/) that nominates gracefully
    // instead of asserting, set MONOCLES_MUJI_TCP_RELAY=1 to re-enable TCP/TLS relays for group
    // calls too — needed so a participant whose network blocks UDP can still join a group call.
    let allow_muji_tcp = std::env::var("MONOCLES_MUJI_TCP_RELAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut skipped_tcp = 0u32;
    for s in servers.iter().filter(|s| s.kind == "turn" || s.kind == "turns") {
        // turns (TURN-over-TLS) is TCP-based too; in a Muji mesh skip anything that isn't plain UDP.
        if muji && !allow_muji_tcp && (s.kind == "turns" || s.transport.eq_ignore_ascii_case("tcp")) {
            skipped_tcp += 1;
            continue;
        }
        let (Some(user), Some(pass)) = (s.username.as_deref(), s.password.as_deref()) else {
            tracing::warn!(host = %s.host, "skipping TURN server without credentials");
            continue;
        };
        let transport = if s.transport.is_empty() { "udp" } else { &s.transport };
        let uri = format!(
            "{}://{}:{}@{}:{}?transport={}",
            s.kind,
            pct_encode(user),
            pct_encode(pass),
            wrap_host(&s.host),
            s.port,
            transport,
        );
        let added: bool = webrtc.emit_by_name("add-turn-server", &[&uri]);
        // Log host/port/kind only — the uri carries credentials.
        tracing::info!(kind = %s.kind, host = %s.host, port = s.port, transport, added, "added TURN server");
    }
    if skipped_tcp > 0 {
        tracing::info!(skipped_tcp, "muji: skipped TCP/TLS TURN relays (libnice mesh-nomination crash workaround — UDP relays only for group calls)");
    }
}

/// Our DTLS identity: an ECDSA P-256 self-signed certificate. GStreamer otherwise generates an
/// RSA-2048 cert, and with that, current libwebrtc (monocles Android, webrtc-android 149) as DTLS
/// client fails against us as DTLS *server* (we placed the call: we offer `actpass`, it answers
/// `active`) with OpenSSL "no shared cipher" — its ClientHello evidently has no RSA-authenticated
/// suite. As DTLS client (we answered) the
/// server's cert decides, which is why only outgoing calls broke. Generated once per process,
/// like GStreamer's own default cert (its agent table caches one agent per distinct PEM, forever).
struct DtlsIdentity {
    /// Certificate + private key in one PEM, as `dtlsdec`'s `pem` / the transport's
    /// `certificate` property expects.
    pem: String,
    /// `sha-256` fingerprint of the certificate DER, SDP-formatted (`AB:CD:…`).
    fingerprint: String,
}

fn dtls_identity() -> Option<&'static DtlsIdentity> {
    static ID: std::sync::OnceLock<Option<DtlsIdentity>> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let gen = || -> Result<DtlsIdentity> {
            use sha2::Digest as _;
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            params.distinguished_name.push(rcgen::DnType::CommonName, "WebRTC");
            let cert = params.self_signed(&key)?;
            let fingerprint = sha2::Sha256::digest(cert.der())
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            Ok(DtlsIdentity { pem: format!("{}{}", cert.pem(), key.serialize_pem()), fingerprint })
        };
        gen()
            .inspect_err(|e| tracing::warn!(error = %e, "ECDSA DTLS cert generation failed — using GStreamer's RSA default"))
            .ok()
    })
    .as_ref()
}

/// The DTLS transports of webrtcbin's sending transceivers (one per sink pad — every call
/// pipeline sends on each transceiver it has).
fn dtls_transports(webrtc: &gst::Element) -> Vec<gst_webrtc::WebRTCDTLSTransport> {
    webrtc
        .sink_pads()
        .iter()
        .filter_map(|pad| pad.property::<Option<gst_webrtc::WebRTCRTPTransceiver>>("transceiver"))
        .filter_map(|t| t.property::<Option<gst_webrtc::WebRTCRTPSender>>("sender"))
        .filter_map(|s| s.property::<Option<gst_webrtc::WebRTCDTLSTransport>>("transport"))
        .collect()
}

/// Put our ECDSA [`dtls_identity`] on a `dtlssrtpdec` webrtcbin has just added. This must happen
/// while the element is still in NULL: setting `pem` rebuilds its DTLS connection, and dtlsdec only
/// hooks its key / peer-certificate handlers onto the connection at NULL→READY (and the paired
/// encoder fetches it then too). webrtcbin adds a transport's bins inside create-offer /
/// create-answer and syncs their state right after, so `deep-element-added` is the window.
fn install_dtls_cert(element: &gst::Element) {
    let Some(id) = dtls_identity() else { return };
    if element.factory().map(|f| f.name()).as_deref() != Some("dtlssrtpdec") {
        return;
    }
    if element.current_state() != gst::State::Null {
        tracing::warn!(element = %element.name(), "DTLS transport already running — keeping its default certificate");
        return;
    }
    if element.property::<Option<String>>("pem").as_deref() != Some(id.pem.as_str()) {
        element.set_property("pem", id.pem.as_str());
    }
}

/// Rewrite the `a=fingerprint` lines of a local SDP to our certificate's real fingerprint when
/// webrtcbin's transports carry our [`dtls_identity`]. Needed because webrtcbin (1.26) derives the
/// fingerprint by base64-decoding *every* non-`-----` line of the transport's PEM — fine for its own
/// cert-only PEM, but with a cert+key PEM it hashes the key too and advertises a fingerprint that
/// matches nothing, so the peer would reject our certificate. With BUNDLE all m-lines share the one
/// transport, so every fingerprint line is ours. Returns `None` when there's nothing to rewrite.
fn fix_local_fingerprint(webrtc: &gst::Element, sdp: &str) -> Option<String> {
    let id = dtls_identity()?;
    let transports = dtls_transports(webrtc);
    let ours = |t: &gst_webrtc::WebRTCDTLSTransport| {
        t.property::<Option<String>>("certificate").as_deref() == Some(id.pem.as_str())
    };
    if transports.is_empty() || !transports.iter().all(ours) {
        if transports.iter().any(ours) {
            tracing::warn!("mixed DTLS certificates across transports — leaving fingerprints as-is");
        }
        return None;
    }
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        if line.starts_with("a=fingerprint:") {
            let eol = if line.ends_with("\r\n") { "\r\n" } else if line.ends_with('\n') { "\n" } else { "" };
            out.push_str(&format!("a=fingerprint:sha-256 {}{eol}", id.fingerprint));
        } else {
            out.push_str(line);
        }
    }
    Some(out)
}

/// Parse a pipeline description, wire webrtcbin's signals, and bring it to `Playing`. Returns
/// an error (after tearing the pipeline back down) if it can't reach `Playing`.
fn build_and_play(
    desc: &str,
    role: Role,
    tx: &Tx,
    video_tx: VideoTx,
    wait_secs: u64,
    muji: bool,
) -> Result<(gst::Pipeline, gst::Element, Arc<AtomicBool>)> {
    let pipeline = gst::parse::launch(desc)
        .context("parse pipeline")?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow!("not a gst::Pipeline"))?;
    let webrtc = pipeline.by_name("webrtc").ok_or_else(|| anyhow!("no webrtcbin"))?;
    let negotiated = Arc::new(AtomicBool::new(false));
    // STUN (server-reflexive candidates) + TURN relays (XEP-0215) so ICE works behind NAT.
    configure_ice(&webrtc, muji);
    // Our ECDSA DTLS certificate on every transport webrtcbin creates. They're created lazily
    // (inside create-offer/-answer); deep-element-added also reports the children of an added bin.
    if let Ok(bin) = webrtc.clone().dynamic_cast::<gst::Bin>() {
        bin.connect_deep_element_added(|_, _, element| install_dtls_cert(element));
    }

    // Surface GStreamer's async errors/warnings (otherwise pipeline failures during
    // negotiation are silent — there's no glib main loop on this thread to run a bus watch).
    if let Some(bus) = pipeline.bus() {
        bus.set_sync_handler(|_, msg| {
            use gst::MessageView;
            match msg.view() {
                MessageView::Error(e) => tracing::error!(
                    src = e.src().map(|s| s.path_string().to_string()),
                    error = %e.error(),
                    debug = e.debug().map(|d| d.to_string()),
                    "gst pipeline error"
                ),
                MessageView::Warning(w) => tracing::warn!(
                    src = w.src().map(|s| s.path_string().to_string()),
                    warning = %w.error(),
                    debug = w.debug().map(|d| d.to_string()),
                    "gst pipeline warning"
                ),
                _ => {}
            }
            gst::BusSyncReply::Drop
        });
    }

    wire_signals(&pipeline, &webrtc, role, tx.clone(), video_tx.clone(), negotiated.clone());
    // Local camera preview appsink, if this call started as video.
    if let Some(sink) = pipeline.by_name("localvideo") {
        wire_video_appsink(&sink, video_tx.clone(), true);
    }
    if let Err(e) = pipeline.set_state(gst::State::Playing) {
        let _ = pipeline.set_state(gst::State::Null);
        return Err(anyhow!("pipeline → Playing: {e}"));
    }
    // Wait for the state change to actually settle — catches *async* failures (e.g. an element
    // that errors after set_state returns) so the caller can fall back. The local graph reaches
    // Playing quickly, so the success path returns fast; only a failing pipeline waits the cap.
    let (res, current, _) = pipeline.state(gst::ClockTime::from_seconds(wait_secs));
    if res.is_err() || current != gst::State::Playing {
        let _ = pipeline.set_state(gst::State::Null);
        return Err(anyhow!("pipeline did not reach Playing (state {current:?})"));
    }
    Ok((pipeline, webrtc, negotiated))
}

/// Connect webrtcbin's negotiation / ICE / connection-state signals to the event channel.
fn wire_signals(
    pipeline: &gst::Pipeline,
    webrtc: &gst::Element,
    role: Role,
    tx: Tx,
    video_tx: VideoTx,
    negotiated: Arc<AtomicBool>,
) {
    // The caller drives the INITIAL negotiation by creating the offer once webrtcbin is ready.
    // Mid-call renegotiations (video upgrade) are driven explicitly, so this fires only once.
    if role == Role::Caller {
        let weak = webrtc.downgrade();
        let tx = tx.clone();
        let negotiated = negotiated.clone();
        webrtc.connect("on-negotiation-needed", false, move |_| {
            if negotiated.swap(true, Ordering::SeqCst) {
                return None; // already negotiated once → don't auto-offer the renegotiation
            }
            if let Some(webrtc) = weak.upgrade() {
                create_offer(&webrtc, tx.clone(), false);
            }
            None
        });
    } else {
        // For the callee, the initial answer is created from set_remote_description; still mark
        // negotiated so any later auto-trigger is ignored and renegotiation stays explicit.
        negotiated.store(true, Ordering::SeqCst);
    }

    // Locally gathered ICE candidates → trickle to the peer.
    {
        let tx = tx.clone();
        webrtc.connect("on-ice-candidate", false, move |values| {
            let mline_index = values[1].get::<u32>().unwrap_or(0);
            let candidate = values[2].get::<String>().unwrap_or_default();
            let _ = tx.send_blocking(EngineEvent::IceCandidate { mline_index, candidate });
            None
        });
    }

    // Surface ICE connection state (connected / failed).
    {
        let tx = tx.clone();
        webrtc.connect_notify(Some("ice-connection-state"), move |webrtc, _| {
            let state =
                webrtc.property::<gst_webrtc::WebRTCICEConnectionState>("ice-connection-state");
            match state {
                gst_webrtc::WebRTCICEConnectionState::Connected
                | gst_webrtc::WebRTCICEConnectionState::Completed => {
                    let _ = tx.send_blocking(EngineEvent::Connected);
                }
                gst_webrtc::WebRTCICEConnectionState::Failed => {
                    let _ = tx.send_blocking(EngineEvent::Failed("ICE failed".into()));
                }
                _ => {}
            }
        });
    }

    // Incoming media → decode + play (audio) / decode + emit frames (video).
    {
        let pipeline_weak = pipeline.downgrade();
        webrtc.connect_pad_added(move |_webrtc, pad| {
            if pad.direction() != gst::PadDirection::Src {
                return;
            }
            let Some(pipeline) = pipeline_weak.upgrade() else { return };
            let is_video = pad_is_video(pad);
            let result = if is_video {
                link_incoming_video(&pipeline, pad, video_tx.clone())
            } else {
                link_incoming_audio(&pipeline, pad)
            };
            if let Err(e) = result {
                let _ = tx.send_blocking(EngineEvent::Failed(format!("recv link: {e}")));
            }
        });
    }
}

/// Whether a webrtcbin src pad carries video (vs audio), from its negotiated caps.
fn pad_is_video(pad: &gst::Pad) -> bool {
    pad.current_caps()
        .or_else(|| pad.query_caps(None).into())
        .and_then(|caps| caps.structure(0).map(|s| {
            s.get::<String>("media").map(|m| m == "video").unwrap_or(false)
                || s.get::<String>("encoding-name").map(|e| e.eq_ignore_ascii_case("VP8") || e.eq_ignore_ascii_case("VP9") || e.eq_ignore_ascii_case("H264")).unwrap_or(false)
        }))
        .unwrap_or(false)
}

/// Attach an RGBA `appsink`'s frames to the video channel (drop on backpressure).
fn wire_video_appsink(sink: &gst::Element, vtx: VideoTx, local: bool) {
    let Ok(appsink) = sink.clone().dynamic_cast::<gst_app::AppSink>() else { return };
    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |s| {
                let sample = s.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let caps = sample.caps().ok_or(gst::FlowError::Error)?;
                let st = caps.structure(0).ok_or(gst::FlowError::Error)?;
                let width = st.get::<i32>("width").unwrap_or(0).max(0) as u32;
                let height = st.get::<i32>("height").unwrap_or(0).max(0) as u32;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                let _ = vtx.try_send(VideoFrame { width, height, data: map.as_slice().to_vec(), local });
                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );
}

/// Parse a peer's SDP into a webrtcbin session description.
fn remote_description(kind: SdpKind, sdp: &str) -> Result<gst_webrtc::WebRTCSessionDescription> {
    let ty = match kind {
        SdpKind::Offer => gst_webrtc::WebRTCSDPType::Offer,
        SdpKind::Answer => gst_webrtc::WebRTCSDPType::Answer,
    };
    tracing::debug!(?kind, "set_remote_description SDP:\n{sdp}");
    let msg = gst_sdp::SDPMessage::parse_buffer(sdp.as_bytes()).context("parse remote SDP")?;
    Ok(gst_webrtc::WebRTCSessionDescription::new(ty, msg))
}

/// The RTP caps of our video send branch (`rtpvp8pay pt=96`).
fn video_rtp_caps() -> gst::Caps {
    gst::Caps::builder("application/x-rtp")
        .field("media", "video")
        .field("encoding-name", "VP8")
        .field("payload", 96i32)
        .field("clock-rate", 90000i32)
        .build()
}

/// Link a (mid-call) send bin's ghosted RTP src to a new webrtcbin sink pad. The transceiver gets
/// its codec preference right away: webrtcbin silently LEAVES OUT of `create-offer` a transceiver
/// whose sink pad has no caps yet — which, for a branch just added to a running pipeline, is the
/// case until the first encoded frame — so a re-offer made immediately had no video m-line and no
/// `content-add` was ever sent.
fn link_send_bin(webrtc: &gst::Element, bin: &gst::Element) -> Result<gst::Pad> {
    let src = bin
        .src_pads()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("video bin has no src pad"))?;
    let sinkpad = webrtc
        .request_pad_simple("sink_%u")
        .ok_or_else(|| anyhow!("webrtcbin sink pad request failed"))?;
    if let Some(trans) = sinkpad.property::<Option<gst_webrtc::WebRTCRTPTransceiver>>("transceiver") {
        trans.set_property("codec-preferences", &video_rtp_caps());
    }
    src.link(&sinkpad).context("link video bin → webrtcbin")?;
    Ok(sinkpad)
}

/// Run `f` once the new send pad has negotiated caps (bounded wait), so the SDP we then create
/// carries the m-line WITH our SSRC — the peer needs it to map our RTP to the right m-line. With
/// no new pad (`None`), or caps already there, `f` runs immediately. The codec preference set in
/// [`link_send_bin`] keeps the m-line in the SDP even if the camera is slow to deliver.
fn after_send_caps(pad: Option<gst::Pad>, f: impl FnOnce() + Send + 'static) {
    let Some(pad) = pad else {
        f();
        return;
    };
    if pad.current_caps().is_some() {
        f();
        return;
    }
    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while pad.current_caps().is_none() && start.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if pad.current_caps().is_none() {
            tracing::warn!("video send pad has no caps after 3s — offering without our SSRC");
        }
        f();
    });
}

/// Create an SDP offer, set it as our local description, and emit it. `renegotiation` tags a
/// mid-call re-offer (video upgrade) so the signalling layer sends `content-add`, not initiate.
fn create_offer(webrtc: &gst::Element, tx: Tx, renegotiation: bool) {
    let weak = webrtc.downgrade();
    let promise = gst::Promise::with_change_func(move |reply| {
        send_local_description(weak.upgrade(), reply, "offer", SdpKind::Offer, tx, renegotiation);
    });
    webrtc.emit_by_name::<()>("create-offer", &[&None::<gst::Structure>, &promise]);
}

/// Create an SDP answer, set it as our local description, and emit it.
fn create_answer(webrtc: &gst::Element, tx: Tx, renegotiation: bool) {
    let weak = webrtc.downgrade();
    let promise = gst::Promise::with_change_func(move |reply| {
        send_local_description(weak.upgrade(), reply, "answer", SdpKind::Answer, tx, renegotiation);
    });
    webrtc.emit_by_name::<()>("create-answer", &[&None::<gst::Structure>, &promise]);
}

/// Shared completion for create-offer/create-answer: pull the description out of the promise
/// reply, set it as our local description, and emit a [`EngineEvent::LocalDescription`].
fn send_local_description(
    webrtc: Option<gst::Element>,
    reply: Result<Option<&gst::StructureRef>, gst::PromiseError>,
    field: &str,
    kind: SdpKind,
    tx: Tx,
    renegotiation: bool,
) {
    let Some(webrtc) = webrtc else { return };
    let Ok(Some(reply)) = reply else { return };
    let Ok(desc) = reply.get::<gst_webrtc::WebRTCSessionDescription>(field) else { return };
    // Advertise our ECDSA certificate's real fingerprint (see `fix_local_fingerprint`).
    let fixed = desc
        .sdp()
        .as_text()
        .ok()
        .and_then(|text| fix_local_fingerprint(&webrtc, &text))
        .and_then(|text| gst_sdp::SDPMessage::parse_buffer(text.as_bytes()).ok())
        .map(|msg| gst_webrtc::WebRTCSessionDescription::new(desc.type_(), msg));
    let desc = fixed.unwrap_or(desc);
    webrtc.emit_by_name::<()>("set-local-description", &[&desc, &None::<gst::Promise>]);
    if let Ok(sdp) = desc.sdp().as_text() {
        tracing::debug!(?kind, renegotiation, "local description SDP:\n{sdp}");
        let _ = tx.send_blocking(EngineEvent::LocalDescription { kind, sdp, renegotiation });
    }
}

/// Decode the incoming webrtcbin src pad (`rtpopusdepay ! opusdec ! audioconvert ! audioresample`)
/// and route it to playback. With AEC active, this means mixing into the persistent `outmix`
/// (so the echo probe downstream sees it); otherwise build a dedicated `autoaudiosink`.
fn link_incoming_audio(pipeline: &gst::Pipeline, pad: &gst::Pad) -> Result<()> {
    let depay = gst::ElementFactory::make("rtpopusdepay").build()?;
    let dec = gst::ElementFactory::make("opusdec").build()?;
    let convert = gst::ElementFactory::make("audioconvert").build()?;
    let resample = gst::ElementFactory::make("audioresample").build()?;
    let decode = [&depay, &dec, &convert, &resample];
    pipeline.add_many(decode).context("add recv elements")?;
    gst::Element::link_many(decode).context("link recv chain")?;

    if let Some(outmix) = pipeline.by_name("outmix") {
        // AEC path: feed the mixer that the echo probe monitors. Force the same format the
        // probe/mixer use (S16LE/48k/mono) so audiomixer accepts the input pad.
        let caps = gst::Caps::builder("audio/x-raw")
            .field("format", "S16LE")
            .field("rate", 48000i32)
            .field("channels", 1i32)
            .build();
        let capsfilter = gst::ElementFactory::make("capsfilter")
            .property("caps", &caps)
            .build()?;
        pipeline.add(&capsfilter).context("add recv capsfilter")?;
        resample.link(&capsfilter).context("link resample → capsfilter")?;
        let mixpad = outmix.request_pad_simple("sink_%u").ok_or_else(|| anyhow!("no mixer pad"))?;
        let srcpad = capsfilter.static_pad("src").ok_or_else(|| anyhow!("no capsfilter src pad"))?;
        for e in decode {
            e.sync_state_with_parent()?;
        }
        capsfilter.sync_state_with_parent()?;
        srcpad.link(&mixpad).context("link recv → mixer")?;
    } else {
        // Plain path: dedicated sink.
        let sink = gst::ElementFactory::make("autoaudiosink").build()?;
        pipeline.add(&sink).context("add sink")?;
        resample.link(&sink).context("link recv → sink")?;
        sink.sync_state_with_parent()?;
        for e in decode {
            e.sync_state_with_parent()?;
        }
    }

    let sinkpad = depay.static_pad("sink").ok_or_else(|| anyhow!("no depay sink pad"))?;
    pad.link(&sinkpad).context("link webrtc src → depay")?;
    Ok(())
}

/// Decode an incoming video pad (`rtpvp8depay ! vp8dec ! videoconvert → RGBA → appsink`) and
/// push its frames to the UI via the video channel.
fn link_incoming_video(pipeline: &gst::Pipeline, pad: &gst::Pad, vtx: VideoTx) -> Result<()> {
    // `wait-for-keyframe`: drop corrupt inter-frames after packet loss until a clean keyframe
    // arrives (prevents the "growing sandstorm" from being displayed). `request-keyframe`: ask
    // the sender (via PLI) for a fresh keyframe on loss, so recovery is fast.
    let depay = gst::ElementFactory::make("rtpvp8depay")
        .property("wait-for-keyframe", true)
        .property("request-keyframe", true)
        .build()?;
    let dec = gst::ElementFactory::make("vp8dec").build()?;
    let convert = gst::ElementFactory::make("videoconvert").build()?;
    let sink = gst::ElementFactory::make("appsink")
        .property("emit-signals", false)
        .property("sync", false)
        .property("drop", true)
        .property("max-buffers", 2u32)
        .build()?;
    // Force RGBA out so the UI can upload frames directly as textures.
    let caps = gst::Caps::builder("video/x-raw").field("format", "RGBA").build();
    sink.set_property("caps", &caps);

    let elements = [&depay, &dec, &convert, &sink];
    pipeline.add_many(elements).context("add video recv elements")?;
    gst::Element::link_many(elements).context("link video recv chain")?;
    for e in elements {
        e.sync_state_with_parent()?;
    }
    wire_video_appsink(&sink, vtx, false);

    let sinkpad = depay.static_pad("sink").ok_or_else(|| anyhow!("no vp8depay sink pad"))?;
    pad.link(&sinkpad).context("link webrtc src → vp8depay")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pipeline strings must parse (all element factories present + valid syntax) for both
    /// audio-only and audio+video. This catches a bad description before any call is placed.
    #[test]
    fn pipeline_descriptions_parse() {
        let _ = gst::init();
        for video in [false, true] {
            for aec in [false, true] {
                for cam in [None, Some("mxc-cam-test")] {
                    let desc = pipeline_desc(video, aec, cam);
                    if let Err(e) = gst::parse::launch(&desc) {
                        panic!("desc (video={video}, aec={aec}, cam={cam:?}) failed to parse: {e}\n{desc}");
                    }
                }
            }
        }
    }

    /// The mid-call video-upgrade bin must parse and expose exactly one (ghosted) src pad — the
    /// RTP payloader output that gets linked into a new webrtcbin sink pad.
    #[test]
    fn video_send_bin_parses_with_one_src() {
        let _ = gst::init();
        let desc = video_send_bin(None);
        let bin = gst::parse::bin_from_description(&desc, true)
            .unwrap_or_else(|e| panic!("video send bin failed to parse: {e}\n{desc}"))
            .upcast::<gst::Element>();
        assert_eq!(bin.src_pads().len(), 1, "expected one ghosted src pad on the video bin");
    }

    /// A caller's offer must advertise the fingerprint of our ECDSA certificate (not GStreamer's
    /// RSA default) — otherwise the peer either can't negotiate a cipher with us as DTLS server or
    /// rejects the certificate we present.
    #[test]
    fn caller_offer_uses_ecdsa_dtls_cert() {
        use base64::Engine as _;
        let _ = gst::init();
        let pem = &dtls_identity().expect("ECDSA cert generated").pem;
        let b64: String = pem
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END CERTIFICATE"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let want = <sha2::Sha256 as sha2::Digest>::digest(&der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");

        let desc = "audiotestsrc is-live=true ! opusenc ! rtpopuspay pt=111 ! \
            application/x-rtp,media=audio,encoding-name=OPUS,payload=111 ! \
            webrtcbin name=webrtc bundle-policy=max-bundle";
        let (tx, rx) = async_channel::unbounded::<EngineEvent>();
        let (vtx, _vrx) = async_channel::bounded::<VideoFrame>(4);
        let (pipeline, _webrtc, _) = build_and_play(desc, Role::Caller, &tx, vtx, 3, false).unwrap();
        let sdp = loop {
            match rx.recv_blocking().unwrap() {
                EngineEvent::LocalDescription { sdp, .. } => break sdp,
                _ => continue,
            }
        };
        let got = sdp
            .lines()
            .find_map(|l| l.strip_prefix("a=fingerprint:sha-256 "))
            .expect("offer has a sha-256 fingerprint")
            .trim()
            .to_string();
        let _ = pipeline.set_state(gst::State::Null);
        assert_eq!(got, want, "offer fingerprint must be our ECDSA cert's");
    }

    /// End to end over loopback: we place the call (so we're the DTLS server with the swapped-in
    /// ECDSA cert), the handshake completes, and the callee sees exactly the certificate whose
    /// fingerprint we advertised. Guards the connection rebuild that setting the cert triggers.
    #[test]
    fn loopback_call_handshakes_with_ecdsa_cert() {
        let _ = gst::init();
        let id = dtls_identity().expect("ECDSA cert generated");
        let desc = "audiotestsrc is-live=true ! opusenc ! rtpopuspay pt=111 ! \
            application/x-rtp,media=audio,encoding-name=OPUS,payload=111 ! \
            webrtcbin name=webrtc bundle-policy=max-bundle";
        let (ctx, crx) = async_channel::unbounded::<EngineEvent>();
        let (etx, erx) = async_channel::unbounded::<EngineEvent>();
        let (vtx, _vrx) = async_channel::bounded::<VideoFrame>(4);
        let (cp, caller, _) = build_and_play(desc, Role::Caller, &ctx, vtx.clone(), 3, false).unwrap();
        let (ep, callee, _) = build_and_play(desc, Role::Callee, &etx, vtx, 3, false).unwrap();
        let set_remote = |w: &gst::Element, ty, sdp: &str| {
            let msg = gst_sdp::SDPMessage::parse_buffer(sdp.as_bytes()).unwrap();
            w.emit_by_name::<()>(
                "set-remote-description",
                &[&gst_webrtc::WebRTCSessionDescription::new(ty, msg), &None::<gst::Promise>],
            );
        };

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let (mut offer_fp, mut answer_fp) = (None, None);
        let connected = loop {
            assert!(std::time::Instant::now() < deadline, "DTLS did not connect");
            while let Ok(ev) = crx.try_recv() {
                match ev {
                    EngineEvent::LocalDescription { sdp, .. } => {
                        offer_fp = sdp.lines().find_map(|l| l.strip_prefix("a=fingerprint:sha-256 ")).map(str::to_string);
                        set_remote(&callee, gst_webrtc::WebRTCSDPType::Offer, &sdp);
                        create_answer(&callee, etx.clone(), false);
                    }
                    EngineEvent::IceCandidate { mline_index, candidate } => {
                        callee.emit_by_name::<()>("add-ice-candidate", &[&mline_index, &candidate]);
                    }
                    _ => {}
                }
            }
            while let Ok(ev) = erx.try_recv() {
                match ev {
                    EngineEvent::LocalDescription { sdp, .. } => {
                        answer_fp = sdp.lines().find_map(|l| l.strip_prefix("a=fingerprint:sha-256 ")).map(str::to_string);
                        set_remote(&caller, gst_webrtc::WebRTCSDPType::Answer, &sdp)
                    }
                    EngineEvent::IceCandidate { mline_index, candidate } => {
                        caller.emit_by_name::<()>("add-ice-candidate", &[&mline_index, &candidate]);
                    }
                    _ => {}
                }
            }
            let up = |w: &gst::Element| {
                dtls_transports(w).first().map(|t| {
                    t.property::<gst_webrtc::WebRTCDTLSTransportState>("state")
                        == gst_webrtc::WebRTCDTLSTransportState::Connected
                }) == Some(true)
            };
            if up(&caller) && up(&callee) {
                break dtls_transports(&callee)[0].property::<Option<String>>("remote-certificate");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let _ = cp.set_state(gst::State::Null);
        let _ = ep.set_state(gst::State::Null);

        // GStreamer doesn't check the peer's fingerprint, so the handshake alone can't catch a
        // wrong one — both sides' SDPs must carry our certificate's real fingerprint (incoming
        // calls rely on the answer's being right, outgoing on the offer's).
        assert_eq!(offer_fp.as_deref(), Some(id.fingerprint.as_str()), "offer fingerprint");
        assert_eq!(answer_fp.as_deref(), Some(id.fingerprint.as_str()), "answer fingerprint");
        // The callee received our ECDSA cert (the same one the PEM holds).
        let remote = connected.expect("callee saw a peer certificate");
        let cert_block = |pem: &str| -> String {
            pem.lines()
                .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
                .take_while(|l| !l.starts_with("-----END CERTIFICATE"))
                .collect()
        };
        assert_eq!(cert_block(&remote), cert_block(&id.pem));
    }

    /// Regression: adding the video branch to a RUNNING call (as the former answerer — a Muji
    /// responder leg) and re-offering must produce a video m-line carrying our SSRC. Creating the
    /// offer right after linking the pad dropped the m-line entirely (no caps yet) → no
    /// `content-add` → the peer never saw our camera.
    #[test]
    fn midcall_video_reoffer_has_video_mline() {
        let _ = gst::init();
        let desc = "audiotestsrc is-live=true ! opusenc ! rtpopuspay pt=111 ! \
            application/x-rtp,media=audio,encoding-name=OPUS,payload=111 ! \
            webrtcbin name=webrtc bundle-policy=max-bundle";
        let (ctx, crx) = async_channel::unbounded::<EngineEvent>();
        let (etx, erx) = async_channel::unbounded::<EngineEvent>();
        let (vtx, _vrx) = async_channel::bounded::<VideoFrame>(4);
        let (cp, caller, _) = build_and_play(desc, Role::Caller, &ctx, vtx.clone(), 3, true).unwrap();
        let (ep, callee, _) = build_and_play(desc, Role::Callee, &etx, vtx, 3, true).unwrap();
        let set_remote = |w: &gst::Element, kind, sdp: &str| {
            let d = remote_description(kind, sdp).unwrap();
            w.emit_by_name::<()>("set-remote-description", &[&d, &None::<gst::Promise>]);
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut answered = false;
        while !answered {
            assert!(std::time::Instant::now() < deadline, "initial negotiation did not finish");
            while let Ok(ev) = crx.try_recv() {
                match ev {
                    EngineEvent::LocalDescription { sdp, .. } => {
                        set_remote(&callee, SdpKind::Offer, &sdp);
                        create_answer(&callee, etx.clone(), false);
                    }
                    EngineEvent::IceCandidate { mline_index, candidate } => {
                        callee.emit_by_name::<()>("add-ice-candidate", &[&mline_index, &candidate])
                    }
                    _ => {}
                }
            }
            while let Ok(ev) = erx.try_recv() {
                if let EngineEvent::LocalDescription { sdp, .. } = ev {
                    set_remote(&caller, SdpKind::Answer, &sdp);
                    answered = true;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let bin = gst::parse::bin_from_description(
            "videotestsrc is-live=true ! videoconvert ! video/x-raw,width=320,height=240 ! \
             vp8enc deadline=1 ! rtpvp8pay pt=96",
            true,
        )
        .unwrap()
        .upcast::<gst::Element>();
        ep.add(&bin).unwrap();
        let pad = link_send_bin(&callee, &bin).unwrap();
        bin.sync_state_with_parent().unwrap();
        let (webrtc, tx) = (callee.clone(), etx.clone());
        after_send_caps(Some(pad), move || create_offer(&webrtc, tx, true));
        let start = std::time::Instant::now();
        let reoffer = loop {
            assert!(start.elapsed() < std::time::Duration::from_secs(10), "no re-offer");
            match erx.try_recv() {
                Ok(EngineEvent::LocalDescription { sdp, renegotiation: true, .. }) => break sdp,
                _ => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        };
        let _ = cp.set_state(gst::State::Null);
        let _ = ep.set_state(gst::State::Null);
        assert!(reoffer.contains("m=video"), "re-offer lacks the video m-line:\n{reoffer}");
        let video = &reoffer[reoffer.find("m=video").unwrap()..];
        assert!(video.contains("a=ssrc:"), "video m-line lacks our SSRC:\n{reoffer}");
    }

}
