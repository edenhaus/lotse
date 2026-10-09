//! `sdp_offer`: an offer from outside never panics the session's answer
//! path, for an H.264 or an H.265 stream (Main or High tier). The payload
//! type check refuses what would panic str0m, the engine answers the rest
//! or returns an error, and a refused offer never reaches it.
//! Run with `cargo +nightly fuzz run sdp_offer` from the repository root.

#![no_main]

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use libfuzzer_sys::fuzz_target;
use lotse_core::Orientation;
use lotse_core::codec::Codec;
use lotse_core::session::{IceCredentials, SessionLimits, SessionOpenError, SessionRequest};
use lotse_webrtc::Session;
use lotse_webrtc::sdp::check_payload_types;

/// An offer of a web player's shape, audio and video in one BUNDLE group, that the
/// session answers: the base the fuzzer inserts lines into, so it reaches
/// the engine's codec matching instead of failing the parse.
const BASE: &str = "v=0\r\n\
o=- 1 2 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE a v\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:te7QCTlMEJQRQ74A\r\n\
a=ice-pwd:7JXEPPENxh4T91N1tbohRt\r\n\
a=fingerprint:sha-256 36:F3:39:20:61:D2:E3:66:F6:5A:CB:96:5D:6D:7B:85:CA:71:37:86:8E:CF:B4:3E:44:53:8F:F3:4B:74:53:23\r\n\
a=setup:actpass\r\n\
a=mid:a\r\n\
a=recvonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 108 109 114 115 116 117 118 119\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:te7QCTlMEJQRQ74A\r\n\
a=ice-pwd:7JXEPPENxh4T91N1tbohRt\r\n\
a=fingerprint:sha-256 36:F3:39:20:61:D2:E3:66:F6:5A:CB:96:5D:6D:7B:85:CA:71:37:86:8E:CF:B4:3E:44:53:8F:F3:4B:74:53:23\r\n\
a=setup:actpass\r\n\
a=mid:v\r\n\
a=recvonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:108 H264/90000\r\n\
a=rtcp-fb:108 nack\r\n\
a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n\
a=rtpmap:109 rtx/90000\r\n\
a=fmtp:109 apt=108\r\n\
a=rtpmap:114 H264/90000\r\n\
a=fmtp:114 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\n\
a=rtpmap:115 rtx/90000\r\n\
a=fmtp:115 apt=114\r\n\
a=rtpmap:116 H265/90000\r\n\
a=fmtp:116 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST\r\n\
a=rtpmap:117 rtx/90000\r\n\
a=fmtp:117 apt=116\r\n\
a=rtpmap:118 H265/90000\r\n\
a=fmtp:118 level-id=153;profile-id=2;tier-flag=1;tx-mode=SRST\r\n\
a=rtpmap:119 rtx/90000\r\n\
a=fmtp:119 apt=118\r\n";

fuzz_target!(|data: &[u8]| {
    // Byte 0 picks the stream's audio (none: every audio codec enabled;
    // Opus; PCMU), its video (H.264, or H.265 under Main and Main 10, RFC
    // 7798 §7.2.2, with no SPS or a High tier one, ITU-T H.265 A.4.1) and
    // whether the rest is the whole offer or lines to insert into BASE
    // before the line byte 1 picks; its top three bits pick the stream's
    // orientation, which the answer marks when the offer negotiates CVO.
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let offer = if pick & 4 == 0 {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        let Some((&at, lines)) = rest.split_first() else {
            return;
        };
        let base: Vec<&str> = BASE.lines().collect();
        let at = usize::from(at) % base.len();
        let mut offer = String::new();
        for (index, line) in base.iter().enumerate() {
            if index == at {
                offer.push_str(&String::from_utf8_lossy(lines));
                offer.push_str("\r\n");
            }
            offer.push_str(line);
            offer.push_str("\r\n");
        }
        offer
    };
    let audio = match pick & 3 {
        0 => None,
        1 => Some(Arc::new(Codec::Opus { channels: 2 })),
        _ => Some(Arc::new(Codec::Pcmu)),
    };
    let checked = check_payload_types(&offer);
    let request = SessionRequest {
        offer,
        ice: IceCredentials {
            ufrag: "lotseufrag".into(),
            pass: "lotsepassword0123456789ab".into(),
        },
        candidates: vec!["192.0.2.10:18556".parse().expect("an address")],
        tcp_candidates: vec![],
        video: Arc::new(if pick & 8 == 0 {
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            }
        } else {
            Codec::H265 {
                vps: None,
                sps: (pick & 16 != 0)
                    .then(|| lotse_codec::h265::test_data::sps_of_tier(1, true, 640, 480).into()),
                pps: None,
            }
        }),
        audio,
        orientation: Orientation::ALL[usize::from(pick >> 5)],
        limits: SessionLimits::default(),
        wall: SystemTime::UNIX_EPOCH,
    };
    let answered = Session::answer(&request, Instant::now());
    if checked.is_err() {
        assert!(
            matches!(answered, Err(SessionOpenError::InvalidSdp(_))),
            "a refused offer is invalid_sdp"
        );
    }
});
