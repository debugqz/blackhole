//! Video: camera capture (`nokhwa`) and VP8 encoding (`vpx-encode`, a safe
//! wrapper around libvpx — the audited encoder implementation; this
//! module composes it, it doesn't reimplement any codec logic itself,
//! same "audited primitive, not custom crypto/codec" principle as
//! `bh-crypto`).
//!
//! Scope note: this module implements capture -> RGB->I420 conversion ->
//! VP8 encode -> (via `session.rs`) SFrame encryption -> real RTP
//! transport. It does **not** implement VP8 *decoding* for local
//! rendering — no suitable safe Rust VP8 decoder crate exists on
//! crates.io, and hand-rolling one against raw libvpx FFI is exactly the
//! kind of unaudited, security-adjacent code this project avoids writing
//! itself (see `docs/SPEC.md` §2.2's rationale, applied here to codecs
//! rather than crypto). Decoding/rendering the received (already SFrame-
//! decrypted) VP8 bitstream is left to the Tauri client, which can use the
//! webview's native `WebCodecs`/`<video>` decode path instead. The
//! encode-side roundtrip (RGB->I420 conversion, VP8 encoding) is fully
//! covered by this module's own tests with synthetic frames; actual
//! camera capture (`CameraCapture`) needs physical hardware this sandbox
//! doesn't have, same caveat as `audio.rs`.

use nokhwa::pixel_format::RgbFormat;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::Camera;

use crate::CallError;

fn codec_error(err: impl std::fmt::Display) -> CallError {
    CallError::Codec(err.to_string())
}

fn video_error(err: impl std::fmt::Display) -> CallError {
    CallError::Video(err.to_string())
}

/// Converts an RGB8 buffer (`width * height * 3` bytes) into I420 (planar
/// YUV 4:2:0, `width * height * 3 / 2` bytes) — the format `vpx-encode`
/// requires. Standard BT.601 coefficients; chroma is point-sampled rather
/// than averaged across each 2x2 block, a simplification that costs a
/// little chroma sharpness but keeps this a plain, auditable loop instead
/// of a hand-tuned filter.
pub fn rgb_to_i420(rgb: &[u8], width: usize, height: usize) -> Vec<u8> {
    assert_eq!(rgb.len(), width * height * 3, "rgb buffer size mismatch");
    assert!(
        width.is_multiple_of(2) && height.is_multiple_of(2),
        "vpx requires even dimensions"
    );

    let mut out = vec![0u8; width * height * 3 / 2];
    let (y_plane, uv_planes) = out.split_at_mut(width * height);
    let (u_plane, v_plane) = uv_planes.split_at_mut(width * height / 4);

    for y in 0..height {
        for x in 0..width {
            let i = (y * width + x) * 3;
            let (r, g, b) = (rgb[i] as i32, rgb[i + 1] as i32, rgb[i + 2] as i32);
            let luma = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            y_plane[y * width + x] = luma.clamp(0, 255) as u8;
        }
    }

    let chroma_width = width / 2;
    for cy in 0..height / 2 {
        for cx in 0..chroma_width {
            let (x, y) = (cx * 2, cy * 2);
            let i = (y * width + x) * 3;
            let (r, g, b) = (rgb[i] as i32, rgb[i + 1] as i32, rgb[i + 2] as i32);
            let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
            let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
            u_plane[cy * chroma_width + cx] = u.clamp(0, 255) as u8;
            v_plane[cy * chroma_width + cx] = v.clamp(0, 255) as u8;
        }
    }

    out
}

pub struct EncodedVideoFrame {
    pub data: Vec<u8>,
    pub key: bool,
}

pub struct VideoEncoder {
    encoder: vpx_encode::Encoder,
}

impl VideoEncoder {
    pub fn new(width: u32, height: u32, bitrate_kbps: u32) -> Result<Self, CallError> {
        let encoder = vpx_encode::Encoder::new(vpx_encode::Config {
            width,
            height,
            timebase: [1, 1000],
            bitrate: bitrate_kbps,
            codec: vpx_encode::VideoCodecId::VP8,
        })
        .map_err(codec_error)?;
        Ok(Self { encoder })
    }

    /// Encodes one I420 frame at presentation time `pts_ms` (milliseconds,
    /// matching the `[1, 1000]` timebase above). Usually yields exactly
    /// one packet; libvpx's encode/output pump can occasionally buffer,
    /// hence the `Vec`.
    pub fn encode_frame(
        &mut self,
        pts_ms: i64,
        i420_frame: &[u8],
    ) -> Result<Vec<EncodedVideoFrame>, CallError> {
        let packets = self
            .encoder
            .encode(pts_ms, i420_frame)
            .map_err(codec_error)?;
        Ok(packets
            .map(|frame| EncodedVideoFrame {
                data: frame.data.to_vec(),
                key: frame.key,
            })
            .collect())
    }
}

/// Wraps the system's default camera, capturing frames already converted
/// to I420 and ready for [`VideoEncoder::encode_frame`].
pub struct CameraCapture {
    camera: Camera,
}

impl CameraCapture {
    pub fn open_default() -> Result<Self, CallError> {
        let format =
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
        let mut camera = Camera::new(CameraIndex::Index(0), format).map_err(video_error)?;
        camera.open_stream().map_err(video_error)?;
        Ok(Self { camera })
    }

    pub fn resolution(&self) -> (u32, u32) {
        let res = self.camera.resolution();
        (res.width_x, res.height_y)
    }

    pub fn capture_i420_frame(&mut self) -> Result<Vec<u8>, CallError> {
        let buffer = self.camera.frame().map_err(video_error)?;
        let image = buffer.decode_image::<RgbFormat>().map_err(video_error)?;
        let (width, height) = image.dimensions();
        Ok(rgb_to_i420(image.as_raw(), width as usize, height as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_rgb_frame(width: usize, height: usize) -> Vec<u8> {
        // A simple horizontal gradient — not a real camera frame, but
        // enough to exercise every branch of the color conversion (pure
        // red/green/blue components at various intensities).
        let mut rgb = vec![0u8; width * height * 3];
        for y in 0..height {
            for x in 0..width {
                let i = (y * width + x) * 3;
                rgb[i] = (x * 255 / width.max(1)) as u8;
                rgb[i + 1] = (y * 255 / height.max(1)) as u8;
                rgb[i + 2] = 128;
            }
        }
        rgb
    }

    #[test]
    fn rgb_to_i420_produces_the_expected_buffer_size() {
        let (width, height) = (32, 16);
        let rgb = synthetic_rgb_frame(width, height);
        let i420 = rgb_to_i420(&rgb, width, height);
        assert_eq!(i420.len(), width * height * 3 / 2);
    }

    #[test]
    fn black_rgb_frame_converts_to_near_minimum_luma() {
        let (width, height) = (16, 16);
        let rgb = vec![0u8; width * height * 3];
        let i420 = rgb_to_i420(&rgb, width, height);
        // Black (0,0,0) maps to luma 16 in studio-swing BT.601, not 0.
        assert!(i420[..width * height].iter().all(|&y| y == 16));
    }

    #[test]
    fn white_rgb_frame_converts_to_near_maximum_luma() {
        let (width, height) = (16, 16);
        let rgb = vec![255u8; width * height * 3];
        let i420 = rgb_to_i420(&rgb, width, height);
        assert!(i420[..width * height].iter().all(|&y| y >= 235));
    }

    #[test]
    fn encoder_produces_a_keyframe_for_the_first_frame() {
        let (width, height) = (64, 48);
        let mut encoder = VideoEncoder::new(width as u32, height as u32, 256).unwrap();
        let rgb = synthetic_rgb_frame(width, height);
        let i420 = rgb_to_i420(&rgb, width, height);

        let packets = encoder.encode_frame(0, &i420).unwrap();
        assert!(!packets.is_empty());
        assert!(packets[0].key, "first encoded frame should be a keyframe");
        assert!(!packets[0].data.is_empty());
    }

    #[test]
    fn encoding_the_same_frame_twice_yields_a_smaller_delta_frame() {
        let (width, height) = (64, 48);
        let mut encoder = VideoEncoder::new(width as u32, height as u32, 256).unwrap();
        let rgb = synthetic_rgb_frame(width, height);
        let i420 = rgb_to_i420(&rgb, width, height);

        let first = encoder.encode_frame(0, &i420).unwrap();
        let second = encoder.encode_frame(33, &i420).unwrap();
        assert!(!second.is_empty());
        // An unchanged scene's delta frame is typically much smaller than
        // the initial keyframe (not guaranteed for every encoder/setting,
        // but true for a static synthetic frame at default settings).
        assert!(second[0].data.len() <= first[0].data.len());
    }
}
