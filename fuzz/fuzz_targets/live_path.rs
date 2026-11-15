//! `live_path`: the live route's path parser (`lotse_api::live_id_of`), which
//! reads an untrusted request path, never panics; a path it takes is
//! exactly `/v0/live/{live_id}` with an id of the identifier pattern
//! (`^[A-Za-z0-9._-]{1,128}$`, never `.` or `..`, RFC 3986 §3.3), so the id
//! names the path it came from and nothing the route did not check.
//! Run with `cargo +nightly fuzz run live_path` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_api_types::live::live_path;

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    let Some(live_id) = lotse_api::live_id_of(path) else {
        return;
    };
    let id = live_id.as_str();
    assert_eq!(live_path(id), path, "the id is the path's one segment");
    assert!((1..=128).contains(&id.len()));
    assert!(
        id.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    );
    assert!(id != "." && id != "..");
});
