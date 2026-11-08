//! Test support: the fake RTSP camera (with a fake ONVIF keyframe endpoint),
//! the fake WebRTC camera that answers a `webrtc` source's offer,
//! the scripted HTTP server of the HTTP source,
//! the third-party camera of the browser and interop tests (MediaMTX and
//! ffmpeg), the fake TURN server, the source and output conformance suites, a
//! headless `str0m` viewer, a client of the control API's mutual-TLS
//! listener, fixtures, the load generator, the browser test and, on Linux,
//! the DSCP a datagram arrived with.
//!
//! A dev-dependency of every crate except `lotse-core`, which it depends on
//! itself: a dev-dependency cycle would compile two copies of core whose types
//! do not unify. Core's own fakes live behind its `test-util` feature. Excluded
//! from the coverage gate and exercised by every suite that uses it.

mod base64;
pub mod browser;
pub mod control_tls;
pub mod dev_viewer;
#[cfg(target_os = "linux")]
pub mod dscp;
pub mod fake_camera;
pub mod fake_http;
pub mod fake_turn;
pub mod fake_webrtc_camera;
pub mod latency;
pub mod libwebrtc;
pub mod load;
pub mod mediamtx;
pub mod output_suite;
pub mod source_harness;
pub mod viewer;

pub use fake_camera::{CameraConfig, FakeCamera};

/// A `stream/put` source of `url`, named by the URL's scheme, which is its
/// protocol (`rtsp`, `https`, the fake `fake`), with the protocol's
/// `fields` beside it (an object; anything else adds none).
pub fn source(url: &str, fields: serde_json::Value) -> serde_json::Value {
    let protocol = url
        .split_once("://")
        .map_or(url, |(scheme, _)| scheme)
        .to_ascii_lowercase();
    let mut source = serde_json::json!({ "protocol": protocol, "url": url });
    if let (Some(source), serde_json::Value::Object(fields)) = (source.as_object_mut(), fields) {
        source.extend(fields);
    }
    source
}
pub use source_harness::Harness;
pub use viewer::Viewer;
