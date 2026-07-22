//! Bridges `bh-calls::audio`'s native mic/speaker I/O (`cpal`) into async
//! code. `cpal::Stream` is deliberately **not** `Send` on most platforms
//! (its CoreAudio/WASAPI/ALSA callback internals use raw, thread-affine
//! handles) — it cannot be stored in `AppState`'s `tokio::sync::Mutex`-
//! guarded call registry or moved into a `tokio::spawn`ed task directly.
//! [`spawn_audio_io_thread`] owns both the capture and playback `Stream`
//! for a call on one dedicated OS thread (created and dropped there,
//! never crossing a thread boundary) and exposes only `Send`-safe
//! channels to the rest of the call-wiring code in `calls.rs`.

use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use bh_calls::CallError;
use tokio::sync::mpsc as tokio_mpsc;

/// How often the dedicated audio thread checks for a stop signal while
/// waiting for the next captured frame — bounds shutdown latency without
/// needing a `select!`-capable channel type (would mean adding
/// `crossbeam-channel` just for this).
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The only thing callers need to keep alive: dropping this (or calling
/// [`AudioStopHandle::stop`] explicitly) signals the dedicated audio
/// thread to drop both `cpal::Stream`s, ending capture/playback. Doesn't
/// hold the streams itself (they never leave that thread — see module
/// doc) or the data channels (those are fully consumed once, not held
/// long-term — see [`spawn_audio_io_thread`]'s return value).
pub struct AudioStopHandle {
    stop_tx: std_mpsc::Sender<()>,
}

impl AudioStopHandle {
    /// Best-effort and non-blocking — does not wait for the thread to
    /// actually exit, since the only thing that matters to a caller
    /// tearing down a call is that audio stops being captured/played
    /// *soon*, not synchronously.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(());
    }
}

impl Drop for AudioStopHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Starts mic capture and speaker playback on a fresh, dedicated OS
/// thread, and blocks (briefly) until that thread confirms both opened
/// successfully — so a missing microphone/speaker fails this call
/// synchronously, the same "surface it now, not just in logs" precedent
/// `CallSession::start_camera`/`start_screen_share` already set for
/// capture-open failures. Returns a channel of mic-captured PCM frames to
/// encode+send, a plain `std::sync::mpsc` sender to push decoded remote
/// PCM onto for playback (already `Send` — only the `Stream` itself
/// wasn't), and the [`AudioStopHandle`] that keeps both alive.
pub type AudioIoStartResult = Result<
    (
        tokio_mpsc::UnboundedReceiver<Vec<i16>>,
        std_mpsc::Sender<Vec<i16>>,
        AudioStopHandle,
    ),
    CallError,
>;

pub fn spawn_audio_io_thread() -> AudioIoStartResult {
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (stop_tx, stop_rx) = std_mpsc::channel::<()>();

    std::thread::spawn(move || {
        let opened = (|| -> Result<_, CallError> {
            let (capture_stream, capture_rx) = bh_calls::audio::start_capture()?;
            let (playback_stream, playback_tx) = bh_calls::audio::start_playback()?;
            Ok((capture_stream, capture_rx, playback_stream, playback_tx))
        })();
        let (capture_stream, capture_rx, playback_stream, playback_tx) = match opened {
            Ok(v) => v,
            Err(err) => {
                let _ = ready_tx.send(Err(err));
                return;
            }
        };

        let (bridge_tx, bridge_rx) = tokio_mpsc::unbounded_channel::<Vec<i16>>();
        if ready_tx.send(Ok((bridge_rx, playback_tx))).is_err() {
            // Caller gave up waiting; nothing downstream to forward to.
            return;
        }

        // Keeps `capture_stream`/`playback_stream` alive for exactly this
        // loop's lifetime — forwarding captured frames onto the Tokio
        // channel until told to stop (or the capture stream itself dies).
        loop {
            match capture_rx.recv_timeout(STOP_POLL_INTERVAL) {
                Ok(pcm) => {
                    if bridge_tx.send(pcm).is_err() {
                        break;
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        drop(capture_stream);
        drop(playback_stream);
    });

    let (captured_frames, playback_tx) = ready_rx
        .recv()
        .map_err(|_| CallError::Audio("audio thread died before reporting status".into()))??;
    Ok((captured_frames, playback_tx, AudioStopHandle { stop_tx }))
}
