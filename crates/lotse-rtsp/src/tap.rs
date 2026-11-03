//! The interleaved channel a `SETUP` answer's `Transport` header gives a
//! stream (RFC 2326 §12.39 `interleaved=N-M`), which the UDP relay reads
//! from retina's side ([`crate::udp`]). Every TCP interleaved connection
//! drives retina's core on its own connection ([`crate::driver`]), and
//! retina sends the receiver reports there, so nothing reads along the
//! camera's side any more.

/// The first channel of an `interleaved` parameter in a `Transport`
/// header (RFC 2326 §12.39), when it names one.
pub(crate) fn interleaved(transport: &str) -> Option<u8> {
    transport
        .split(';')
        .find_map(|param| param.trim().strip_prefix("interleaved="))
        .and_then(|range| range.split('-').next())
        .and_then(|first| first.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2326_12_39_interleaved_names_the_first_channel() {
        assert_eq!(interleaved("RTP/AVP/TCP;unicast;interleaved=2-3"), Some(2));
        assert_eq!(interleaved("RTP/AVP/TCP; interleaved= 4"), Some(4));
        assert_eq!(interleaved("RTP/AVP;unicast;client_port=5000-5001"), None);
        assert_eq!(interleaved("RTP/AVP/TCP;interleaved=x"), None);
    }
}
