#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::{
    crypto::{KeySourceSide, OpeningKey as _, SealingKey as _},
    named::EncryptionAlgorithm,
};

fuzz_target!(|data: &[u8]| {
    let Some((header, plain)) = data.split_at_checked(64 + 4 + 1) else {
        return;
    };
    if plain.len() < 4 {
        return;
    }

    let source = KeySourceSide {
        algorithm: EncryptionAlgorithm::Chacha20Poly1305,
        encryption_key: header[..64].to_vec(),
        initial_iv: Vec::new(),
    };
    let seq = u32::from_be_bytes(header[64..68].try_into().unwrap());
    let flip = usize::from(header[68]);

    let mut sealer = provider::DEFAULT_PROVIDER.sealing_key(0, &source).unwrap();
    let mut packet = plain.to_vec();
    let mut tag = [0u8; 16];
    sealer.seal_in_place(seq, &mut packet, &mut tag).unwrap();

    let mut opener = provider::DEFAULT_PROVIDER.opening_key(0, &source).unwrap();
    let length = opener.decrypt_packet_length(seq, packet[..4].try_into().unwrap());
    assert_eq!(length, plain[..4]);

    let mut forged = packet.clone();
    let mut forged_tag = tag;
    let index = flip % (forged.len() + 16);
    match forged.get_mut(index) {
        Some(byte) => *byte ^= 1,
        None => forged_tag[index - packet.len()] ^= 1,
    }
    let before = forged.clone();
    assert!(opener.open_in_place(seq, &mut forged, &forged_tag).is_err());
    assert_eq!(forged, before);

    let mut opener = provider::DEFAULT_PROVIDER.opening_key(0, &source).unwrap();
    let mut genuine = packet;
    opener.open_in_place(seq, &mut genuine, &tag).unwrap();
    assert_eq!(genuine, plain);
});
