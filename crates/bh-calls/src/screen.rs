//! Screen capture (`scap`, a cross-platform wrapper over ScreenCaptureKit
//! on macOS, Windows.Graphics.Capture on Windows, and the PipeWire portal
//! on Linux — all audited platform APIs, not a hand-rolled capture path).
//!
//! This module's only job is to produce I420 frames with the exact same
//! output contract as [`crate::video::CameraCapture::capture_i420_frame`]:
//! screen-share frames are just another RGB source that gets converted with
//! the *same* [`crate::video::rgb_to_i420`] function and fed to the *same*
//! [`crate::video::VideoEncoder`] (VP8) and SFrame encryption path camera
//! video uses (see `session.rs`'s `start_screen_share`) — there is no
//! separate codec or encryption scheme for screen sharing.
//!
//! Same hardware caveat as `video.rs`/`audio.rs`: opening a real capturer
//! needs a physical display and (on macOS) screen-recording permission
//! granted to the process, neither of which this sandbox has, so
//! `ScreenCapture::open_default` itself isn't exercised by this module's
//! own tests. What *is* tested here without any of that is the frame
//! shaping helper (`even_crop_rgb`) that keeps arbitrary display
//! resolutions compatible with `rgb_to_i420`'s even-dimensions requirement.

use scap::capturer::{Capturer, Options};
use scap::frame::{Frame, FrameType};

use crate::video::rgb_to_i420;
use crate::CallError;

fn screen_error(err: impl std::fmt::Display) -> CallError {
    CallError::Video(err.to_string())
}

/// `rgb_to_i420` requires even width/height (standard 4:2:0 chroma
/// subsampling constraint). Most displays already are, but this crops off
/// a trailing row/column rather than asserting/panicking if one isn't
/// (e.g. an odd-width cropped capture region).
fn even_crop_rgb(data: &[u8], width: usize, height: usize) -> (Vec<u8>, usize, usize) {
    let even_width = width - (width % 2);
    let even_height = height - (height % 2);
    if even_width == width && even_height == height {
        return (data.to_vec(), width, height);
    }
    let mut out = Vec::with_capacity(even_width * even_height * 3);
    for y in 0..even_height {
        let row_start = y * width * 3;
        out.extend_from_slice(&data[row_start..row_start + even_width * 3]);
    }
    (out, even_width, even_height)
}

/// Wraps the platform's default screen/display capturer, producing frames
/// already converted to I420 — same output contract as
/// [`crate::video::CameraCapture::capture_i420_frame`], so both sources
/// feed [`crate::video::VideoEncoder`] identically.
pub struct ScreenCapture {
    capturer: Capturer,
    width: usize,
    height: usize,
}

impl ScreenCapture {
    /// Opens the primary display's capturer and starts capture. Requires
    /// the platform to support capture at all ([`scap::is_supported`]) and
    /// the process to already hold screen-recording permission
    /// ([`scap::has_permission`]) — neither is requested interactively
    /// here; a client should prompt for permission (via `scap`'s own
    /// `request_permission`, or the OS system-settings flow it triggers)
    /// before calling this.
    pub fn open_default(fps: u32) -> Result<Self, CallError> {
        if !scap::is_supported() {
            return Err(CallError::Video(
                "screen capture is not supported on this platform".into(),
            ));
        }
        if !scap::has_permission() {
            return Err(CallError::Video(
                "screen recording permission was not granted".into(),
            ));
        }

        let options = Options {
            fps,
            show_cursor: true,
            show_highlight: false,
            output_type: FrameType::RGB,
            ..Default::default()
        };
        let mut capturer = Capturer::build(options).map_err(screen_error)?;
        capturer.start_capture();
        let [width, height] = capturer.get_output_frame_size();
        Ok(Self {
            capturer,
            width: width as usize,
            height: height as usize,
        })
    }

    /// The (even-cropped) resolution frames will be produced at — pass
    /// straight to [`crate::video::VideoEncoder::new`].
    pub fn resolution(&self) -> (u32, u32) {
        let (width, height) = even_dimensions(self.width, self.height);
        (width as u32, height as u32)
    }

    /// Blocks until the next screen frame is available (bounded by `fps`
    /// from [`Self::open_default`]), returning it already converted to
    /// I420 and ready for [`crate::video::VideoEncoder::encode_frame`].
    pub fn capture_i420_frame(&mut self) -> Result<Vec<u8>, CallError> {
        let frame = self.capturer.get_next_frame().map_err(screen_error)?;
        match frame {
            Frame::RGB(f) => {
                let (rgb, width, height) =
                    even_crop_rgb(&f.data, f.width as usize, f.height as usize);
                Ok(rgb_to_i420(&rgb, width, height))
            }
            other => Err(CallError::Video(format!(
                "unexpected frame pixel format from screen capturer: {other:?}"
            ))),
        }
    }
}

fn even_dimensions(width: usize, height: usize) -> (usize, usize) {
    (width - (width % 2), height - (height % 2))
}

impl Drop for ScreenCapture {
    fn drop(&mut self) {
        self.capturer.stop_capture();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_rgb(width: usize, height: usize) -> Vec<u8> {
        let mut rgb = vec![0u8; width * height * 3];
        for (i, px) in rgb.chunks_mut(3).enumerate() {
            px[0] = (i % 256) as u8;
            px[1] = ((i / 3) % 256) as u8;
            px[2] = 128;
        }
        rgb
    }

    #[test]
    fn even_dimensions_are_left_untouched() {
        let rgb = synthetic_rgb(64, 48);
        let (cropped, w, h) = even_crop_rgb(&rgb, 64, 48);
        assert_eq!((w, h), (64, 48));
        assert_eq!(cropped, rgb);
    }

    #[test]
    fn odd_dimensions_get_cropped_to_even() {
        let rgb = synthetic_rgb(65, 47);
        let (cropped, w, h) = even_crop_rgb(&rgb, 65, 47);
        assert_eq!((w, h), (64, 46));
        assert_eq!(cropped.len(), w * h * 3);
        // The cropped buffer must still convert cleanly through the same
        // path a real captured frame would take.
        let i420 = rgb_to_i420(&cropped, w, h);
        assert_eq!(i420.len(), w * h * 3 / 2);
    }

    #[test]
    fn even_dimensions_helper_rounds_down() {
        assert_eq!(even_dimensions(1920, 1080), (1920, 1080));
        assert_eq!(even_dimensions(1921, 1081), (1920, 1080));
    }
}
