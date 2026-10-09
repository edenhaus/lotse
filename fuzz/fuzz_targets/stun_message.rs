//! `stun_message`: the supervisor's STUN parser and checks never panic on
//! network bytes; a USERNAME's local ufrag is only ever the part before
//! its colon; MESSAGE-INTEGRITY verifies only under the password it was
//! made with and only over the bytes it covers; and what the builder makes
//! parses back (RFC 8489 §14.3, §14.5, §14.7; RFC 8445 §7.2.2).
//! Run with `cargo +nightly fuzz run stun_message` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_supervisor::net::stun::{Builder, Class, METHOD_BINDING, is_stun, parse};

fuzz_target!(|data: &[u8]| {
    let _ = is_stun(data);
    if let Ok(message) = parse(data) {
        if let Some(local) = message.local_ufrag() {
            let username = message.username().expect("a ufrag comes from a username");
            assert!(
                username
                    .strip_prefix(local)
                    .is_some_and(|rest| rest.starts_with(':'))
            );
        }
        let _ = message.xor_mapped_address();
        let _ = message.error_code();
        let _ = message.verify_integrity(data, b"password");
        let _ = message.fingerprint_ok(data);
        // Whatever parsed rebuilds into something that parses again.
        let mut builder = Builder::new(message.class, message.method, message.transaction_id);
        for (attr_type, value) in &message.attributes {
            builder = builder.attribute(*attr_type, value);
        }
        let rebuilt = builder.build();
        assert!(parse(&rebuilt).is_ok());
    }
    if data.len() >= 12 {
        let mut id = [0_u8; 12];
        id.copy_from_slice(&data[..12]);
        let built = Builder::new(Class::Request, METHOD_BINDING, id)
            .username(&String::from_utf8_lossy(data))
            .integrity(b"pw")
            .fingerprint()
            .build();
        let message = parse(&built).expect("a built message parses");
        assert!(message.verify_integrity(&built, b"pw"));
        assert!(message.fingerprint_ok(&built));
        assert!(
            !message.verify_integrity(&built, b"other"),
            "only its password"
        );
        // One flipped bit of the transaction id, which the HMAC covers.
        let mut forged = built.clone();
        forged[8] ^= 1;
        let message = parse(&forged).expect("the forgery still parses");
        assert!(
            !message.verify_integrity(&forged, b"pw"),
            "only the bytes it covers"
        );
        assert!(!message.fingerprint_ok(&forged));
    }
});
