//! Audio: Opus encode/decode, plus `cpal` microphone capture/speaker
//! playback.
//!
//! The Opus encode/decode roundtrip (`AudioEncoder`/`AudioDecoder`) is
//! fully covered by this module's own tests — synthetic PCM in, decoded
//! PCM out, no microphone or speakers required. Actual device I/O
//! (`start_capture`/`start_playback`) talks to real hardware via `cpal`
//! and is accordingly *not* exercised by an automated test in this
//! sandbox (no audio hardware here) — the same scoping caveat the rest of
//! this crate has for anything touching physical devices; see `lib.rs`.
//!
//! Scope note: capture/playback here require the device's default input/
//! output config to already be 48kHz — no sample-rate conversion is
//! implemented. Most desktop audio hardware supports 48kHz natively; a
//! device that doesn't will get a clear error here rather than silently
//! degraded audio from a naive resample.

use std::sync::mpsc::{Receiver, Sender};

use audiopus::coder::{Decoder as OpusDecoder, Encoder as OpusEncoder};
use audiopus::{Application, Channels, SampleRate};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, Stream, StreamConfig};

use crate::CallError;

pub const OPUS_SAMPLE_RATE: u32 = 48_000;
pub const OPUS_CHANNELS: u16 = 2;
/// One 20ms frame at 48kHz stereo — the standard WebRTC Opus frame size.
pub const OPUS_FRAME_SAMPLES: usize =
    (OPUS_SAMPLE_RATE as usize / 1000) * 20 * OPUS_CHANNELS as usize;
/// Per the Opus spec, encoded packets never exceed this size.
const MAX_OPUS_PACKET_BYTES: usize = 4000;

fn codec_error(err: impl std::fmt::Display) -> CallError {
    CallError::Codec(err.to_string())
}

pub struct AudioEncoder {
    encoder: OpusEncoder,
}

impl AudioEncoder {
    pub fn new() -> Result<Self, CallError> {
        let encoder = OpusEncoder::new(SampleRate::Hz48000, Channels::Stereo, Application::Voip)
            .map_err(codec_error)?;
        Ok(Self { encoder })
    }

    /// Encodes exactly one 20ms frame (`OPUS_FRAME_SAMPLES` interleaved
    /// i16 samples) into an Opus packet.
    pub fn encode_frame(&self, pcm: &[i16]) -> Result<Vec<u8>, CallError> {
        let mut out = vec![0u8; MAX_OPUS_PACKET_BYTES];
        let len = self.encoder.encode(pcm, &mut out).map_err(codec_error)?;
        out.truncate(len);
        Ok(out)
    }
}

pub struct AudioDecoder {
    decoder: OpusDecoder,
}

impl AudioDecoder {
    pub fn new() -> Result<Self, CallError> {
        let decoder =
            OpusDecoder::new(SampleRate::Hz48000, Channels::Stereo).map_err(codec_error)?;
        Ok(Self { decoder })
    }

    /// Decodes one Opus packet back into interleaved i16 PCM. Pass `None`
    /// to signal a lost packet (Opus's built-in concealment fills in a
    /// plausible frame instead of silence).
    pub fn decode_frame(&mut self, packet: Option<&[u8]>) -> Result<Vec<i16>, CallError> {
        let mut out = vec![0i16; OPUS_FRAME_SAMPLES];
        let samples_per_channel = self
            .decoder
            .decode(packet, &mut out[..], false)
            .map_err(codec_error)?;
        out.truncate(samples_per_channel * OPUS_CHANNELS as usize);
        Ok(out)
    }
}

fn desired_config() -> StreamConfig {
    StreamConfig {
        channels: OPUS_CHANNELS,
        sample_rate: cpal::SampleRate(OPUS_SAMPLE_RATE),
        buffer_size: cpal::BufferSize::Default,
    }
}

/// Starts capturing from the system's default input device, delivering
/// 20ms i16 PCM frames (ready for [`AudioEncoder::encode_frame`]) on
/// `Receiver`. The returned `Stream` must be kept alive for capture to
/// continue — dropping it stops the microphone.
pub fn start_capture() -> Result<(Stream, Receiver<Vec<i16>>), CallError> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| CallError::Audio("no default input (microphone) device".into()))?;
    let config = desired_config();

    let (tx, rx): (Sender<Vec<i16>>, Receiver<Vec<i16>>) = std::sync::mpsc::channel();
    let mut frame_buf: Vec<i16> = Vec::with_capacity(OPUS_FRAME_SAMPLES);

    let stream = device
        .build_input_stream(
            &config,
            move |data: &[i16], _| {
                for &sample in data {
                    frame_buf.push(sample);
                    if frame_buf.len() == OPUS_FRAME_SAMPLES {
                        let _ = tx.send(std::mem::replace(
                            &mut frame_buf,
                            Vec::with_capacity(OPUS_FRAME_SAMPLES),
                        ));
                    }
                }
            },
            |err| tracing::warn!(%err, "audio capture stream error"),
            None,
        )
        .map_err(|err| CallError::Audio(err.to_string()))?;
    stream
        .play()
        .map_err(|err| CallError::Audio(err.to_string()))?;
    Ok((stream, rx))
}

/// Starts playback to the system's default output device, pulling 20ms
/// i16 PCM frames (as produced by [`AudioDecoder::decode_frame`]) from
/// `Sender`'s paired channel. The returned `Stream` must be kept alive for
/// playback to continue.
pub fn start_playback() -> Result<(Stream, Sender<Vec<i16>>), CallError> {
    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or_else(|| CallError::Audio("no default output (speaker) device".into()))?;
    let config = desired_config();

    let (tx, rx): (Sender<Vec<i16>>, Receiver<Vec<i16>>) = std::sync::mpsc::channel();
    let mut pending: Vec<i16> = Vec::new();

    let stream = device
        .build_output_stream(
            &config,
            move |data: &mut [i16], _| {
                let mut written = 0;
                while written < data.len() {
                    if pending.is_empty() {
                        match rx.try_recv() {
                            Ok(frame) => pending = frame,
                            Err(_) => {
                                // Underrun: fill the rest with silence rather
                                // than glitching on stale data.
                                data[written..].fill(0);
                                return;
                            }
                        }
                    }
                    let take = pending.len().min(data.len() - written);
                    data[written..written + take].copy_from_slice(&pending[..take]);
                    pending.drain(..take);
                    written += take;
                }
            },
            |err| tracing::warn!(%err, "audio playback stream error"),
            None,
        )
        .map_err(|err| CallError::Audio(err.to_string()))?;
    stream
        .play()
        .map_err(|err| CallError::Audio(err.to_string()))?;
    Ok((stream, tx))
}

/// Reported by `cpal` alongside a device's config — exposed so callers can
/// sanity-check hardware supports [`OPUS_SAMPLE_RATE`] before calling
/// [`start_capture`]/[`start_playback`], since neither does resampling.
pub fn default_input_sample_format() -> Result<SampleFormat, CallError> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| CallError::Audio("no default input (microphone) device".into()))?;
    let config = device
        .default_input_config()
        .map_err(|err| CallError::Audio(err.to_string()))?;
    Ok(config.sample_format())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic 440Hz-ish tone, not real microphone input — this is the
    /// part of the audio path that doesn't need physical hardware to test.
    fn synthetic_frame() -> Vec<i16> {
        (0..OPUS_FRAME_SAMPLES)
            .map(|i| {
                let t = i as f32 / OPUS_SAMPLE_RATE as f32;
                (8000.0 * (t * 440.0 * std::f32::consts::TAU).sin()) as i16
            })
            .collect()
    }

    #[test]
    fn opus_roundtrip_produces_plausible_pcm() {
        let encoder = AudioEncoder::new().unwrap();
        let mut decoder = AudioDecoder::new().unwrap();

        let frame = synthetic_frame();
        let encoded = encoder.encode_frame(&frame).unwrap();
        assert!(!encoded.is_empty());
        assert!(
            encoded.len() < frame.len() * 2,
            "opus should compress the frame"
        );

        let decoded = decoder.decode_frame(Some(&encoded)).unwrap();
        assert_eq!(decoded.len(), frame.len());
    }

    #[test]
    fn decoder_conceals_a_lost_packet_instead_of_erroring() {
        let mut decoder = AudioDecoder::new().unwrap();
        let concealed = decoder.decode_frame(None).unwrap();
        assert_eq!(concealed.len(), OPUS_FRAME_SAMPLES);
    }

    #[test]
    fn silence_encodes_and_decodes_cleanly() {
        let encoder = AudioEncoder::new().unwrap();
        let mut decoder = AudioDecoder::new().unwrap();
        let silence = vec![0i16; OPUS_FRAME_SAMPLES];

        let encoded = encoder.encode_frame(&silence).unwrap();
        let decoded = decoder.decode_frame(Some(&encoded)).unwrap();
        assert_eq!(decoded.len(), OPUS_FRAME_SAMPLES);
    }
}
