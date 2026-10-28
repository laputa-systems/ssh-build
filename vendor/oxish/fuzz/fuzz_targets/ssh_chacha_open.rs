#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::{
    crypto::{KeySourceSide, OpeningKey as _, SealingKey as _},
    named::EncryptionAlgorithm,
};

const HEADER: usize = 64 + 4 + 16;

fuzz_target!(|data: &[u8]| {
    let Some((header, packet)) = data.split_at_checked(HEADER) else {
        return;
    };

    let source = KeySourceSide {
        algorithm: EncryptionAlgorithm::Chacha20Poly1305,
        encryption_key: header[..64].to_vec(),
        initial_iv: Vec::new(),
    };
    let seq = u32::from_be_bytes(header[64..68].try_into().unwrap());
    let tag = &header[68..];

    let mut opener = provider::DEFAULT_PROVIDER.opening_key(0, &source).unwrap();
    let mut opened = packet.to_vec();
    if opener.open_in_place(seq, &mut opened, tag).is_err() {
        // Authentication failed: the packet must be untouched, never partly decrypted.
        let mut again = packet.to_vec();
        let _ = provider::DEFAULT_PROVIDER
            .opening_key(0, &source)
            .unwrap()
            .open_in_place(seq, &mut again, tag);
        assert_eq!(again, packet);
        return;
    }

    // An authentic packet must seal back to exactly what was received.
    let mut sealer = provider::DEFAULT_PROVIDER.sealing_key(0, &source).unwrap();
    let mut resealed = opened.clone();
    let mut new_tag = [0u8; 16];
    sealer.seal_in_place(seq, &mut resealed, &mut new_tag).unwrap();
    assert_eq!(resealed, packet);
    assert_eq!(new_tag, tag);
});
