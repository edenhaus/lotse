//! Test support: the fake RTSP camera (with a fake ONVIF keyframe endpoint),
//! the third-party camera of the browser and interop tests (MediaMTX and
//! ffmpeg), the fake TURN server, the source and output conformance suites, a
//! headless `str0m` viewer, fixtures, the load generator, the browser test
//! and, on Linux, the DSCP a datagram arrived with.
//!
//! A dev-dependency of every crate except `lotse-core`, which it depends on
//! itself: a dev-dependency cycle would compile two copies of core whose types
//! do not unify. Core's own fakes live behind its `test-util` feature. Excluded
//! from the coverage gate and exercised by every suite that uses it.

mod base64;
pub mod browser;
pub mod dev_viewer;
#[cfg(target_os = "linux")]
pub mod dscp;
pub mod fake_camera;
pub mod fake_turn;
pub mod latency;
pub mod libwebrtc;
pub mod load;
pub mod mediamtx;
pub mod output_suite;
pub mod source_harness;
pub mod viewer;

pub use fake_camera::{CameraConfig, FakeCamera};
pub use source_harness::Harness;
pub use viewer::Viewer;
