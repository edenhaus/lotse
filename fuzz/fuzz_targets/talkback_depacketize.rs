//! `talkback_depacketize`: the talk-back depacketizer never panics on any
//! payload a viewer sends, in any payload type, and what it hands on is
//! the packet as sent, in the codec its payload type names, an Opus one
//! framed by RFC 6716 §3.4 and a G.711 one with at least one sample.
//! Run with `cargo +nightly fuzz run talkback_depacketize` from the repository root.

#![no_main]

use std::sync::Arc;
use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use lotse_codec::opus;
use lotse_core::codec::CodecFamily;
use lotse_core::media::RtpHeaderFields;
use lotse_core::uplink::UplinkCodec;
use lotse_webrtc::talkback::Depacketizer;

fuzz_target!(|data: &[u8]| {
    // [pt][marker][payload...]: a browser's payload types, with G.722 and
    // video in the same BUNDLE group, refused.
    let Some((&pt, rest)) = data.split_first() else {
        return;
    };
    let Some((&marker, payload)) = rest.split_first() else {
        return;
    };
    let depacketizer = Depacketizer::new([
        (111, CodecFamily::Opus),
        (0, CodecFamily::Pcmu),
        (8, CodecFamily::Pcma),
        (9, CodecFamily::G722),
        (96, CodecFamily::H264),
    ]);
    let rtp = RtpHeaderFields {
        pt: pt & 0x7f,
        seq: u16::from(marker),
        ts: u32::from(pt),
        marker: marker & 1 != 0,
        ssrc: 1,
    };
    let now = Instant::now();
    let Ok(uplink) = depacketizer.depacketize(rtp, Arc::from(payload), now) else {
        return;
    };
    assert_eq!(uplink.packet.rtp, rtp);
    assert_eq!(&uplink.packet.payload[..], payload);
    assert_eq!(depacketizer.codec(rtp.pt), Some(uplink.codec));
    match uplink.codec {
        UplinkCodec::Opus => assert!(opus::packet_samples(payload).is_ok_and(|n| n <= 5_760)),
        UplinkCodec::Pcmu | UplinkCodec::Pcma => assert!(!payload.is_empty()),
    }
});
