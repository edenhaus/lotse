//! Coordination of Video Orientation (CVO): the stream's orientation as the
//! `urn:3gpp:video-orientation` RTP header extension, so the browser turns
//! the picture and no transcode is needed.
//!
//! Standards: 3GPP TS 26.114 §7.4.5 (the byte; the video writer puts it
//! on the last packet of every frame, a `SPEC-DEVIATION` explained there)
//! and §6.2.3.3 (negotiation: answered only when offered, which str0m does
//! by echoing the offered `a=extmap` under its id, RFC 8285 §6), in the
//! one-byte header form (RFC 8285 §4.2).
//!
//! `SPEC-DEVIATION`: str0m 0.24 carries only the two rotation bits
//! (`str0m::rtp::VideoOrientation`), so the flip
//! bit of the four mirrored orientations is not sent and those play
//! turned but not mirrored. The browsers that offer CVO read only the
//! rotation bits too (libwebrtc `modules/rtp_rtcp/include/rtp_cvo.h`,
//! `ConvertCVOByteToVideoRotation`, observed 2026-10-03), so the bit would
//! change nothing there.

use lotse_core::Orientation;
use str0m::Rtc;
use str0m::media::Mid;
use str0m::rtp::{Extension, VideoOrientation};

/// The flip bit F of the CVO byte (TS 26.114 §7.4.5): the picture on the
/// link is mirrored left to right.
const FLIP: u8 = 0b0100;

/// The rotation bits R1 R0 of the CVO byte (TS 26.114 §7.4.5, Table 7.2):
/// the picture on the link is turned counterclockwise by R × 90°, so the
/// receiver turns it clockwise by as much before display.
const ROTATION: u8 = 0b0011;

/// The CVO byte `0 0 0 0 C F R1 R0` of an orientation (TS 26.114 §7.4.5).
/// C is 0, the value for a camera direction the sender does not know. The
/// receiver compensates the rotation first and flips after, so each
/// orientation is the turn R and the flip F whose composition is the
/// orientation's transform (`lotse_core::orientation`): to turn the picture left the
/// receiver turns it 270° clockwise (R = 3); a transpose is a quarter turn
/// clockwise and a mirror (R = 1, F), an anti-transpose a quarter turn
/// counterclockwise and a mirror (R = 3, F); a top-to-bottom flip is a
/// half turn and a mirror (R = 2, F).
pub(crate) const fn byte(orientation: Orientation) -> u8 {
    match orientation {
        Orientation::NoTransform => 0,
        Orientation::Mirror => FLIP,
        Orientation::Rotate180 => 2,
        Orientation::Flip => FLIP | 2,
        Orientation::RotateLeftAndFlip => FLIP | 1,
        Orientation::RotateLeft => 3,
        Orientation::RotateRightAndFlip => FLIP | 3,
        Orientation::RotateRight => 1,
    }
}

/// str0m's value for a CVO byte: its rotation bits, which str0m writes as
/// they are (`Deg270` is R = 1, `Deg90` R = 3: the turn on the link,
/// counterclockwise by R × 90°). The flip bit is lost (module docs).
fn engine_value(byte: u8) -> VideoOrientation {
    // SPEC-DEVIATION(3GPP TS 26.114 §7.4.5): F is not sent, as str0m 0.24
    // has no field for it and libwebrtc ignores it; gate:
    // ts_26_114_7_4_5_a_mirrored_orientation_sends_its_rotation_without_the_flip_bit
    VideoOrientation::from(byte & ROTATION)
}

/// A session's CVO: whether its answer negotiated the extension, which
/// decides whether the stream's orientation reaches the browser, at the
/// answer and after every change (`stream/put`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cvo {
    /// The extension's id in the answer, the offer's (RFC 8285 §6), when
    /// the offer listed it on the video m-line.
    id: Option<u8>,
}

impl Cvo {
    /// What the answer negotiated on the video m-line `mid`, with the
    /// value the session's video carries on the last packet of each frame
    /// for `orientation`: none for a stream that is not turned, or without
    /// the extension. Logs the decision.
    pub(crate) fn negotiate(
        rtc: &Rtc,
        mid: Mid,
        orientation: Orientation,
    ) -> (Self, Option<VideoOrientation>) {
        let id = rtc
            .media(mid)
            .and_then(|media| media.remote_extmap().id_of(Extension::VideoOrientation));
        let cvo = Self { id };
        if orientation == Orientation::NoTransform {
            return (cvo, None);
        }
        let Some(id) = id else {
            tracing::info!(
                orientation = orientation.name(),
                "the offer has no video orientation extension; the picture goes as the camera sends it"
            );
            return (cvo, None);
        };
        let byte = byte(orientation);
        let sent = engine_value(byte);
        tracing::info!(
            orientation = orientation.name(),
            extension_id = id,
            cvo = byte,
            sent = ?sent,
            "video orientation negotiated; the browser turns the picture (rotation bits only)"
        );
        (cvo, Some(sent))
    }

    /// The value after the stream's orientation changed to `orientation`.
    /// With the extension, every frame from now on states it, the identity
    /// included: TS 26.114 §7.4.5 has a sender mark only keyframes and
    /// changes, so a receiver keeps the last value it got and a turn back
    /// must be said. Without it, none: the picture goes on as the camera
    /// sends it. Logs the decision.
    pub(crate) fn change(self, orientation: Orientation) -> Option<VideoOrientation> {
        let Some(id) = self.id else {
            tracing::info!(
                orientation = orientation.name(),
                "orientation changed, but the offer had no video orientation extension; the picture goes on as the camera sends it"
            );
            return None;
        };
        let byte = byte(orientation);
        let sent = engine_value(byte);
        tracing::info!(
            orientation = orientation.name(),
            extension_id = id,
            cvo = byte,
            sent = ?sent,
            "video orientation changed; the browser turns the picture from the next frame"
        );
        Some(sent)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    /// Applies a CVO byte the way TS 26.114 §7.4.5 tells the receiver to:
    /// rotation compensation (clockwise by R × 90°), then the flip, to the
    /// corners of a 2 × 2 picture given as rows `[[top left, top right],
    /// [bottom left, bottom right]]`.
    fn receive(byte: u8, mut picture: [[char; 2]; 2]) -> [[char; 2]; 2] {
        for _ in 0..(byte & ROTATION) {
            let [[a, b], [c, d]] = picture;
            picture = [[c, a], [d, b]]; // a quarter turn clockwise
        }
        if byte & FLIP != 0 {
            let [[a, b], [c, d]] = picture;
            picture = [[b, a], [d, c]];
        }
        picture
    }

    #[test]
    fn ts_26_114_7_4_5_the_receiver_shows_each_orientation_s_transform() {
        // Each orientation's transform, as ffmpeg filters, on a picture
        // with corners a b / c d.
        let picture = [['a', 'b'], ['c', 'd']];
        let cases = [
            (Orientation::NoTransform, [['a', 'b'], ['c', 'd']], 0b000),
            (Orientation::Mirror, [['b', 'a'], ['d', 'c']], 0b100), // hflip
            (Orientation::Rotate180, [['d', 'c'], ['b', 'a']], 0b010),
            (Orientation::Flip, [['c', 'd'], ['a', 'b']], 0b110), // vflip
            // transpose=2 (a quarter counterclockwise), then vflip.
            (
                Orientation::RotateLeftAndFlip,
                [['a', 'c'], ['b', 'd']],
                0b101,
            ),
            (Orientation::RotateLeft, [['b', 'd'], ['a', 'c']], 0b011),
            // transpose=1 (a quarter clockwise), then vflip.
            (
                Orientation::RotateRightAndFlip,
                [['d', 'b'], ['c', 'a']],
                0b111,
            ),
            (Orientation::RotateRight, [['c', 'a'], ['d', 'b']], 0b001),
        ];
        for (orientation, shown, expected) in cases {
            assert_eq!(byte(orientation), expected, "{orientation:?}");
            assert_eq!(
                receive(byte(orientation), picture),
                shown,
                "{orientation:?}"
            );
        }
    }

    #[test]
    fn ts_26_114_7_4_5_camera_bit_stays_zero_and_bits_above_it_unused() {
        for orientation in Orientation::ALL {
            assert_eq!(byte(orientation) & !(FLIP | ROTATION), 0, "{orientation:?}");
        }
    }

    #[test]
    fn str0m_carries_the_rotation_bits_and_drops_the_flip() {
        let cases = [
            (Orientation::NoTransform, VideoOrientation::Deg0),
            (Orientation::Mirror, VideoOrientation::Deg0),
            (Orientation::Rotate180, VideoOrientation::Deg180),
            (Orientation::Flip, VideoOrientation::Deg180),
            (Orientation::RotateLeftAndFlip, VideoOrientation::Deg270),
            (Orientation::RotateLeft, VideoOrientation::Deg90),
            (Orientation::RotateRightAndFlip, VideoOrientation::Deg90),
            (Orientation::RotateRight, VideoOrientation::Deg270),
        ];
        for (orientation, expected) in cases {
            let value = engine_value(byte(orientation));
            assert_eq!(value, expected, "{orientation:?}");
            // str0m writes the enum's discriminant as the byte.
            assert_eq!(value as u8, byte(orientation) & ROTATION, "{orientation:?}");
        }
    }
}
