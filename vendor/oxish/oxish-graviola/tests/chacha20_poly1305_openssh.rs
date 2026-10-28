//! `chacha20-poly1305@openssh.com` against vectors produced by OpenSSH's own
//! `chachapoly_crypt` (see `scripts/gen-chachapoly-vectors.sh`), plus the failure behavior the
//! packet layer depends on.

use oxish_graviola::DEFAULT_PROVIDER;
use proto::{
    crypto::{CryptoError, KeySourceSide, OpeningKey, SealingKey},
    named::EncryptionAlgorithm,
};

const VECTORS: &str = include_str!("openssh-chachapoly.vectors");

struct Vector {
    key: Vec<u8>,
    seq: u32,
    plain: Vec<u8>,
    sealed: Vec<u8>,
}

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> Vec<Vector> {
    VECTORS
        .lines()
        .map(|line| {
            let field = |name: &str| {
                line.split(' ')
                    .find_map(|part| part.strip_prefix(name))
                    .unwrap_or_else(|| panic!("no {name} in {line}"))
            };
            Vector {
                key: hex(field("key=")),
                seq: field("seq=").parse().unwrap(),
                plain: hex(field("pt=")),
                sealed: hex(field("ct=")),
            }
        })
        .collect()
}

fn source(key: &[u8]) -> KeySourceSide {
    KeySourceSide {
        algorithm: EncryptionAlgorithm::Chacha20Poly1305,
        encryption_key: key.to_vec(),
        initial_iv: Vec::new(),
    }
}

fn sealer(key: &[u8], counter: u64) -> Box<dyn SealingKey> {
    DEFAULT_PROVIDER.sealing_key(counter, &source(key)).unwrap()
}

fn opener(key: &[u8], counter: u64) -> Box<dyn OpeningKey> {
    DEFAULT_PROVIDER.opening_key(counter, &source(key)).unwrap()
}

#[test]
fn matches_openssh_for_every_vector() {
    let vectors = vectors();
    assert!(vectors.len() >= 400);
    for vector in &vectors {
        let split = vector.sealed.len() - 16;
        let (expected_packet, expected_tag) = vector.sealed.split_at(split);

        let mut packet = vector.plain.clone();
        let mut tag = [0u8; 16];
        sealer(&vector.key, 0)
            .seal_in_place(vector.seq, &mut packet, &mut tag)
            .unwrap();
        assert_eq!(packet, expected_packet, "ciphertext, seq {}", vector.seq);
        assert_eq!(tag, expected_tag, "tag, seq {}", vector.seq);

        let mut opener = opener(&vector.key, 0);
        let length = opener.decrypt_packet_length(vector.seq, packet[..4].try_into().unwrap());
        assert_eq!(length, vector.plain[..4]);
        opener.open_in_place(vector.seq, &mut packet, &tag).unwrap();
        assert_eq!(packet, vector.plain, "round trip, seq {}", vector.seq);
    }
}

#[test]
fn any_modified_bit_fails_authentication_and_never_yields_plaintext() {
    let vector = vectors()
        .into_iter()
        .find(|vector| vector.plain.len() == 64)
        .unwrap();
    let split = vector.sealed.len() - 16;
    let (packet, tag) = vector.sealed.split_at(split);

    for bit in 0..packet.len() * 8 {
        let mut tampered = packet.to_vec();
        tampered[bit / 8] ^= 1 << (bit % 8);
        let before = tampered.clone();
        let result = opener(&vector.key, 0).open_in_place(vector.seq, &mut tampered, tag);
        assert_eq!(result, Err(CryptoError::DecryptionFailed), "bit {bit}");
        assert_eq!(tampered, before, "a failed open must not touch the packet (bit {bit})");
    }

    for bit in 0..tag.len() * 8 {
        let mut bad_tag = tag.to_vec();
        bad_tag[bit / 8] ^= 1 << (bit % 8);
        let mut copy = packet.to_vec();
        let result = opener(&vector.key, 0).open_in_place(vector.seq, &mut copy, &bad_tag);
        assert_eq!(result, Err(CryptoError::DecryptionFailed), "tag bit {bit}");
        assert_eq!(copy, packet);
    }
}

#[test]
fn the_sequence_number_is_bound_into_the_tag() {
    let vector = &vectors()[0];
    let split = vector.sealed.len() - 16;
    let (packet, tag) = vector.sealed.split_at(split);
    for seq in [vector.seq.wrapping_add(1), vector.seq.wrapping_sub(1), !vector.seq] {
        let mut copy = packet.to_vec();
        assert_eq!(
            opener(&vector.key, 0).open_in_place(seq, &mut copy, tag),
            Err(CryptoError::DecryptionFailed)
        );
    }
}

#[test]
fn malformed_inputs_are_rejected() {
    let key = [7u8; 64];
    let mut tag = [0u8; 16];
    assert!(DEFAULT_PROVIDER.sealing_key(0, &source(&key[..32])).is_err());
    assert!(DEFAULT_PROVIDER.opening_key(0, &source(&[7u8; 65])).is_err());
    let mut with_iv = source(&key);
    with_iv.initial_iv = vec![0; 12];
    assert!(DEFAULT_PROVIDER.sealing_key(0, &with_iv).is_err());

    assert_eq!(
        sealer(&key, 0).seal_in_place(0, &mut [0u8; 3], &mut tag),
        Err(CryptoError::InvalidLength)
    );
    assert_eq!(
        sealer(&key, 0).seal_in_place(0, &mut [0u8; 8], &mut [0u8; 15]),
        Err(CryptoError::InvalidLength)
    );
    assert!(opener(&key, 0).open_in_place(0, &mut [0u8; 3], &tag).is_err());
    assert!(opener(&key, 0).open_in_place(0, &mut [0u8; 8], &tag[..15]).is_err());
}

#[test]
fn the_nonce_space_of_a_key_is_never_reused() {
    let key = [9u8; 64];
    let last = u64::from(u32::MAX);
    let mut sealer = sealer(&key, last - 1);
    let mut tag = [0u8; 16];
    sealer.seal_in_place(u32::MAX - 1, &mut [0u8; 8], &mut tag).unwrap();
    assert_eq!(sealer.counter(), last);
    for _ in 0..3 {
        assert_eq!(
            sealer.seal_in_place(u32::MAX, &mut [0u8; 8], &mut tag),
            Err(CryptoError::NonceOverflow)
        );
    }

    let mut opener = opener(&key, last);
    assert_eq!(
        opener.open_in_place(u32::MAX, &mut [0u8; 8], &tag),
        Err(CryptoError::NonceOverflow)
    );
}
