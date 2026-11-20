//! `hls_route`: the LL-HLS route's request parser (`lotse_api::hls::hls_request_of`),
//! which reads an untrusted request path and query, never panics; what it
//! takes is exactly `/v0/hls/{hls_id}/{name}` with an id of the identifier
//! pattern (`^[A-Za-z0-9._-]{1,128}$`, never `.` or `..`, RFC 3986 §3.3) and
//! a name that is the playlist or a resource as the playlist writes it, so
//! the request names the path it came from and nothing the route did not
//! check. The input, split at its first NUL byte, is the path and the query.
//! Run with `cargo +nightly fuzz run hls_route` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_api::hls::{HlsRequest, hls_request_of};
use lotse_api_types::HLS_PATH;
use lotse_api_types::hls::PLAYLIST_NAME;

fuzz_target!(|data: &[u8]| {
    let (path, query) = match data.iter().position(|byte| *byte == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &data[..0]),
    };
    let (Ok(path), Ok(query)) = (std::str::from_utf8(path), std::str::from_utf8(query)) else {
        return;
    };
    let Ok((hls_id, request)) = hls_request_of(path, query) else {
        return;
    };
    let id = hls_id.as_str();
    assert!((1..=128).contains(&id.len()));
    assert!(
        id.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    );
    assert!(id != "." && id != "..");
    let name = match request {
        HlsRequest::Playlist(_) => PLAYLIST_NAME.to_owned(),
        HlsRequest::Media(resource) => resource.to_string(),
    };
    assert_eq!(
        format!("{HLS_PATH}/{id}/{name}"),
        path,
        "the request is the path's"
    );
});
