//! Voice-message recording + audio playback via GStreamer (the same stack the calls use, so no
//! extra Qt Multimedia dependency). Recording produces an Opus/Ogg `.oga` file (sent as a normal
//! XEP-0363 upload); playback drives a `playbin` and a poller pushes position/duration/state onto
//! the `Backend` QObject so the QML player bubble stays in sync.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use cxx_qt::CxxQtThread;
use cxx_qt_lib::QString;
use gstreamer as gst;
use gstreamer::prelude::*;

use crate::backend::qobject::Backend;

/// The active recording pipeline + its output file, while recording.
static RECORDER: Mutex<Option<(gst::Pipeline, PathBuf)>> = Mutex::new(None);

/// The active playback pipeline + the file it's playing.
static PLAYER: Mutex<Option<(gst::Pipeline, String)>> = Mutex::new(None);

fn init() {
    let _ = gst::init();
}

// --- recording -----------------------------------------------------------------------------

fn voice_tmp_path() -> PathBuf {
    // In the volatile view dir (RAM-backed on Linux, wiped at exit), not the shared temp dir.
    let dir = mxc_store::cache::view_subdir("voice").unwrap_or_else(|| {
        let dir = std::env::temp_dir().join("monocles-voice");
        let _ = std::fs::create_dir_all(&dir);
        dir
    });
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    dir.join(format!("voice-{ts}.oga"))
}

/// Start recording from the default microphone (Opus in Ogg). Returns true on success.
pub fn start_recording() -> bool {
    init();
    if RECORDER.lock().unwrap().is_some() {
        return false;
    }
    let path = voice_tmp_path();
    let desc = format!(
        "autoaudiosrc ! audioconvert ! audioresample ! opusenc ! oggmux ! filesink location=\"{}\"",
        path.display()
    );
    let element = match gst::parse::launch(&desc) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "voice: build record pipeline");
            return false;
        }
    };
    let Ok(pipeline) = element.downcast::<gst::Pipeline>() else { return false };
    if pipeline.set_state(gst::State::Playing).is_err() {
        return false;
    }
    *RECORDER.lock().unwrap() = Some((pipeline, path));
    true
}

/// Stop recording cleanly (flush the Ogg headers via EOS) and return the file path.
pub fn stop_recording() -> Option<String> {
    let (pipeline, path) = RECORDER.lock().unwrap().take()?;
    // Send EOS so the muxer finalises the file, then wait for it (bounded).
    pipeline.send_event(gst::event::Eos::new());
    if let Some(bus) = pipeline.bus() {
        let _ = bus.timed_pop_filtered(
            gst::ClockTime::from_seconds(5),
            &[gst::MessageType::Eos, gst::MessageType::Error],
        );
    }
    let _ = pipeline.set_state(gst::State::Null);
    let path = path.to_string_lossy().into_owned();
    if std::path::Path::new(&path).is_file() {
        Some(path)
    } else {
        None
    }
}

/// Abort + delete the current recording.
pub fn cancel_recording() {
    if let Some((pipeline, path)) = RECORDER.lock().unwrap().take() {
        let _ = pipeline.set_state(gst::State::Null);
        let _ = std::fs::remove_file(path);
    }
}

// --- playback ------------------------------------------------------------------------------

fn stop_player() {
    if let Some((pipeline, _)) = PLAYER.lock().unwrap().take() {
        let _ = pipeline.set_state(gst::State::Null);
    }
}

/// Play/pause toggle for `path`. Starts (replacing any current playback) when it's a different
/// file, otherwise flips play/pause. `qt` drives the position poller.
pub fn toggle(path: String, qt: CxxQtThread<Backend>) {
    init();
    // Same file already loaded → toggle play/pause.
    {
        let guard = PLAYER.lock().unwrap();
        if let Some((pipeline, cur)) = guard.as_ref() {
            if *cur == path {
                let playing = pipeline.current_state() == gst::State::Playing;
                let _ = pipeline.set_state(if playing { gst::State::Paused } else { gst::State::Playing });
                let now_playing = !playing;
                drop(guard);
                push_state(&qt, &path, now_playing);
                if now_playing {
                    spawn_poller(qt);
                }
                return;
            }
        }
    }
    // Different (or no) file → (re)start playback.
    stop_player();
    let uri = format!("file://{path}");
    let Ok(playbin) = gst::ElementFactory::make("playbin").property("uri", &uri).build() else {
        return;
    };
    let Ok(pipeline) = playbin.downcast::<gst::Pipeline>() else { return };
    if pipeline.set_state(gst::State::Playing).is_err() {
        return;
    }
    *PLAYER.lock().unwrap() = Some((pipeline, path.clone()));
    push_state(&qt, &path, true);
    spawn_poller(qt);
}

/// Seek the active playback to `ms` milliseconds.
pub fn seek(ms: i64) {
    if let Some((pipeline, _)) = PLAYER.lock().unwrap().as_ref() {
        let _ = pipeline.seek_simple(
            gst::SeekFlags::FLUSH | gst::SeekFlags::KEY_UNIT,
            gst::ClockTime::from_mseconds(ms.max(0) as u64),
        );
    }
}

fn push_state(qt: &CxxQtThread<Backend>, path: &str, playing: bool) {
    let path = path.to_string();
    let _ = qt.queue(move |mut b: Pin<&mut Backend>| {
        b.as_mut().set_audio_path(QString::from(&path));
        b.as_mut().set_audio_playing(playing);
    });
}

/// Poll position/duration (~150ms) while a clip plays and push them to the Backend; stop on EOS.
fn spawn_poller(qt: CxxQtThread<Backend>) {
    crate::session::runtime().spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let snapshot = {
                let guard = PLAYER.lock().unwrap();
                guard.as_ref().map(|(pipeline, _)| {
                    let pos = pipeline
                        .query_position::<gst::ClockTime>()
                        .map(|c| c.mseconds() as i64)
                        .unwrap_or(0);
                    let dur = pipeline
                        .query_duration::<gst::ClockTime>()
                        .map(|c| c.mseconds() as i64)
                        .unwrap_or(0);
                    let eos = pipeline
                        .bus()
                        .and_then(|b| b.pop_filtered(&[gst::MessageType::Eos]))
                        .is_some();
                    let playing = pipeline.current_state() == gst::State::Playing;
                    (pos, dur, eos, playing)
                })
            };
            let Some((pos, dur, eos, playing)) = snapshot else { break };
            if eos {
                let _ = pipeline_to_start();
                let _ = qt.queue(move |mut b: Pin<&mut Backend>| {
                    b.as_mut().set_audio_playing(false);
                    b.as_mut().set_audio_pos(0);
                });
                break;
            }
            let _ = qt.queue(move |mut b: Pin<&mut Backend>| {
                b.as_mut().set_audio_pos(pos);
                b.as_mut().set_audio_duration(dur);
            });
            if !playing {
                break; // paused → stop polling until resumed
            }
        }
    });
}

/// On EOS, rewind the pipeline to the start and pause it (so play can resume from 0).
fn pipeline_to_start() -> Option<()> {
    let guard = PLAYER.lock().unwrap();
    let (pipeline, _) = guard.as_ref()?;
    let _ = pipeline.set_state(gst::State::Paused);
    let _ = pipeline.seek_simple(gst::SeekFlags::FLUSH, gst::ClockTime::ZERO);
    Some(())
}
