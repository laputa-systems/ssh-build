//! `chacha20-poly1305@openssh.com` packet protection.
//!
//! This is OpenSSH's packet construction (`cipher-chachapoly.c`), not the
//! RFC 8439 AEAD: the ChaCha variant here uses a 64-bit nonce with a 64-bit
//! counter (`chacha.c`, DJB's original), two 256-bit keys (body + header),
//! the packet sequence number as nonce, and Poly1305 over the ciphertext.
//! The primitives below are transcribed from OpenSSH's `chacha.c` and
//! `poly1305.c` (public-domain poly1305-donna); the graviola crate exposes
//! only the RFC AEAD, which cannot express this construction.

use zeroize::{Zeroize, Zeroizing};

/// Key length: two 256-bit keys (body key, then header key).
pub(crate) const KEY_LEN: usize = 64;
/// Authentication tag length.
pub(crate) const TAG_LEN: usize = 16;
/// Cipher block size reported to the packet layer (matches OpenSSH).
pub(crate) const BLOCK_LEN: usize = 8;

/// Packet keys for one direction.
pub(crate) struct PacketKey {
    main: Zeroizing<[u8; 32]>,
    header: Zeroizing<[u8; 32]>,
}

impl PacketKey {
    /// Split 64 bytes of derived key material into body and header keys.
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        let key: &[u8; KEY_LEN] = key.first_chunk()?;
        let mut main = Zeroizing::new([0u8; 32]);
        let mut header = Zeroizing::new([0u8; 32]);
        main.copy_from_slice(&key[..32]);
        header.copy_from_slice(&key[32..]);
        Some(Self { main, header })
    }

    /// The Poly1305 one-time key: the first 32 bytes of the body-key
    /// keystream for this sequence number (counter 0).
    fn poly_key(&self, seq: u32) -> [u8; 32] {
        let mut ctx = Chacha::new(&self.main);
        ctx.ivsetup(&seq_nonce(seq), 0);
        let mut out = [0u8; 32];
        ctx.xor(&[0u8; 32], &mut out);
        out
    }

    /// Encrypt `data` (`packet_length` + plaintext) in place, writing `tag`.
    pub(crate) fn seal(&self, seq: u32, data: &mut [u8], tag: &mut [u8; TAG_LEN]) {
        let nonce = seq_nonce(seq);
        let mut poly_key = self.poly_key(seq);
        let (length, payload) = data.split_at_mut(4);

        let mut header = Chacha::new(&self.header);
        header.ivsetup(&nonce, 0);
        header.xor_in_place(length);

        let mut body = Chacha::new(&self.main);
        body.ivsetup(&nonce, 1);
        body.xor_in_place(payload);

        *tag = poly1305_auth(data, &poly_key);
        poly_key.zeroize();
    }

    /// Verify `tag` over `data`, then decrypt it in place.
    pub(crate) fn open(&self, seq: u32, data: &mut [u8], tag: &[u8]) -> Result<(), OpenError> {
        let Some(tag): Option<&[u8; TAG_LEN]> = tag.first_chunk() else {
            return Err(OpenError::InvalidLength);
        };
        let nonce = seq_nonce(seq);
        let mut poly_key = self.poly_key(seq);
        let mut expected = poly1305_auth(data, &poly_key);
        poly_key.zeroize();
        // Verify before decrypting so a failed open never exposes plaintext.
        if !ct_equal(&expected, tag) {
            expected.zeroize();
            return Err(OpenError::DecryptionFailed);
        }
        let (length, payload) = data.split_at_mut(4);

        let mut header = Chacha::new(&self.header);
        header.ivsetup(&nonce, 0);
        header.xor_in_place(length);

        let mut body = Chacha::new(&self.main);
        body.ivsetup(&nonce, 1);
        body.xor_in_place(payload);
        Ok(())
    }

    /// Recover the cleartext `packet_length` from its encrypted form.
    pub(crate) fn packet_length(&self, seq: u32, encrypted: [u8; 4]) -> [u8; 4] {
        let mut ctx = Chacha::new(&self.header);
        ctx.ivsetup(&seq_nonce(seq), 0);
        let mut out = encrypted;
        ctx.xor_in_place(&mut out);
        out
    }
}

/// Failure to open a packet.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum OpenError {
    /// The tag had an invalid length.
    InvalidLength,
    /// Tag verification failed.
    DecryptionFailed,
}

/// Sequence number encoding: `POKE_U64`, big-endian.
fn seq_nonce(seq: u32) -> [u8; 8] {
    (seq as u64).to_be_bytes()
}

fn ct_equal(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// DJB's original ChaCha: 256-bit key, 64-bit counter, 64-bit nonce.
struct Chacha {
    input: [u32; 16],
}

impl Chacha {
    fn new(key: &[u8; 32]) -> Self {
        // "expand 32-byte k", little-endian words.
        let mut input = [0u32; 16];
        for (i, word) in input.iter_mut().take(4).enumerate() {
            *word = u32::from_le_bytes([
                b"expand 32-byte k"[4 * i],
                b"expand 32-byte k"[4 * i + 1],
                b"expand 32-byte k"[4 * i + 2],
                b"expand 32-byte k"[4 * i + 3],
            ]);
        }
        for (i, word) in input.iter_mut().skip(4).take(8).enumerate() {
            *word = u32::from_le_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }
        Self { input }
    }

    fn ivsetup(&mut self, iv: &[u8; 8], counter: u64) {
        self.input[12] = counter as u32;
        self.input[13] = (counter >> 32) as u32;
        self.input[14] = u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]);
        self.input[15] = u32::from_le_bytes([iv[4], iv[5], iv[6], iv[7]]);
    }

    fn xor(&mut self, m: &[u8], c: &mut [u8]) {
        debug_assert_eq!(m.len(), c.len());
        self.xor_in_place_split(m, c);
    }

    fn xor_in_place(&mut self, data: &mut [u8]) {
        // XOR with freshly zeroed scratch is only valid because the keystream
        // block is fully overwritten below for every byte we read back.
        let len = data.len();
        let mut i = 0;
        let mut j12 = self.input[12];
        let mut j13 = self.input[13];
        while i < len {
            let mut block = [0u8; 64];
            self.block(j12, j13, &mut block);
            let n = Ord::min(64, len - i);
            for k in 0..n {
                data[i + k] ^= block[k];
            }
            i += n;
            (j12, j13) = next_counter(j12, j13);
            // Match `chacha_encrypt_bytes`: a message ending on a block
            // boundary still consumes (and discards) one more block.
            if i == len && n == 64 {
                let mut discard = [0u8; 64];
                self.block(j12, j13, &mut discard);
                (j12, j13) = next_counter(j12, j13);
            }
        }
        self.input[12] = j12;
        self.input[13] = j13;
    }

    fn xor_in_place_split(&mut self, m: &[u8], c: &mut [u8]) {
        let len = m.len();
        let mut i = 0;
        let mut j12 = self.input[12];
        let mut j13 = self.input[13];
        while i < len {
            let mut block = [0u8; 64];
            self.block(j12, j13, &mut block);
            let n = Ord::min(64, len - i);
            for k in 0..n {
                c[i + k] = m[i + k] ^ block[k];
            }
            i += n;
            (j12, j13) = next_counter(j12, j13);
            if i == len && n == 64 {
                let mut discard = [0u8; 64];
                self.block(j12, j13, &mut discard);
                (j12, j13) = next_counter(j12, j13);
            }
        }
        self.input[12] = j12;
        self.input[13] = j13;
    }

    fn block(&self, j12: u32, j13: u32, out: &mut [u8; 64]) {
        let mut x = self.input;
        x[12] = j12;
        x[13] = j13;
        let j = x;
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        for (i, word) in x.iter().enumerate() {
            let mixed = word.wrapping_add(j[i]);
            out[4 * i..4 * i + 4].copy_from_slice(&mixed.to_le_bytes());
        }
    }
}

fn next_counter(j12: u32, j13: u32) -> (u32, u32) {
    let j12 = j12.wrapping_add(1);
    match j12 {
        0 => (0, j13.wrapping_add(1)),
        _ => (j12, j13),
    }
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Poly1305 one-time authenticator (poly1305-donna-32).
fn poly1305_auth(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let load = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);

    // Clamp key.
    let mut t0 = load(&key[0..4]);
    let mut t1 = load(&key[4..8]);
    let mut t2 = load(&key[8..12]);
    let mut t3 = load(&key[12..16]);

    // Precompute multipliers.
    let r0 = t0 & 0x3ffffff;
    t0 >>= 26;
    t0 |= t1 << 6;
    let r1 = t0 & 0x3ffff03;
    t1 >>= 20;
    t1 |= t2 << 12;
    let r2 = t1 & 0x3ffc0ff;
    t2 >>= 14;
    t2 |= t3 << 18;
    let r3 = t2 & 0x3f03fff;
    t3 >>= 8;
    let r4 = t3 & 0x00fffff;

    let s1 = r1.wrapping_mul(5);
    let s2 = r2.wrapping_mul(5);
    let s3 = r3.wrapping_mul(5);
    let s4 = r4.wrapping_mul(5);

    // Init state.
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    let mut t = [0u64; 5];
    let mut msg = msg;
    if msg.len() >= 16 {
        loop {
            let (block, rest) = msg.split_at(16);
            msg = rest;
            t0 = load(&block[0..4]);
            t1 = load(&block[4..8]);
            t2 = load(&block[8..12]);
            t3 = load(&block[12..16]);

            h0 += t0 & 0x3ffffff;
            h1 += ((((t1 as u64) << 32) | t0 as u64) >> 26) as u32 & 0x3ffffff;
            h2 += ((((t2 as u64) << 32) | t1 as u64) >> 20) as u32 & 0x3ffffff;
            h3 += ((((t3 as u64) << 32) | t2 as u64) >> 14) as u32 & 0x3ffffff;
            h4 += (t3 >> 8) | (1 << 24);

            multiply(
                &mut t,
                [h0, h1, h2, h3, h4],
                [r0, r1, r2, r3, r4],
                [s1, s2, s3, s4],
            );
            (h0, h1, h2, h3, h4) = carry(&mut t);

            if msg.len() < 16 {
                break;
            }
        }
    }

    // Final bytes.
    if !msg.is_empty() {
        let mut mp = [0u8; 16];
        mp[..msg.len()].copy_from_slice(msg);
        mp[msg.len()] = 1;

        t0 = load(&mp[0..4]);
        t1 = load(&mp[4..8]);
        t2 = load(&mp[8..12]);
        t3 = load(&mp[12..16]);

        h0 += t0 & 0x3ffffff;
        h1 += ((((t1 as u64) << 32) | t0 as u64) >> 26) as u32 & 0x3ffffff;
        h2 += ((((t2 as u64) << 32) | t1 as u64) >> 20) as u32 & 0x3ffffff;
        h3 += ((((t3 as u64) << 32) | t2 as u64) >> 14) as u32 & 0x3ffffff;
        h4 += t3 >> 8;

        multiply(
            &mut t,
            [h0, h1, h2, h3, h4],
            [r0, r1, r2, r3, r4],
            [s1, s2, s3, s4],
        );
        (h0, h1, h2, h3, h4) = carry(&mut t);
    }

    // Fully carry h.
    let mut b = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += b;
    b = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += b;
    b = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += b;
    b = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += b;
    b = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += b * 5;
    b = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += b;

    // Compute h + -p.
    let mut g0 = h0.wrapping_add(5);
    b = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h1.wrapping_add(b);
    b = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h2.wrapping_add(b);
    b = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h3.wrapping_add(b);
    b = g3 >> 26;
    g3 &= 0x3ffffff;
    let g4 = h4.wrapping_add(b).wrapping_sub(1 << 26);

    // Select h if h < p, or h + -p if h >= p.
    let b = (g4 >> 31).wrapping_sub(1);
    let nb = !b;
    h0 = (h0 & nb) | (g0 & b);
    h1 = (h1 & nb) | (g1 & b);
    h2 = (h2 & nb) | (g2 & b);
    h3 = (h3 & nb) | (g3 & b);
    h4 = (h4 & nb) | (g4 & b);

    // h = h % 2^128. The ORs below are 32-bit (wrapping), widened after.
    let f0 = (h0 | h1.wrapping_shl(26)) as u64 + load(&key[16..20]) as u64;
    let mut f1 = ((h1 >> 6) | h2.wrapping_shl(20)) as u64 + load(&key[20..24]) as u64;
    let mut f2 = ((h2 >> 12) | h3.wrapping_shl(14)) as u64 + load(&key[24..28]) as u64;
    let mut f3 = ((h3 >> 18) | h4.wrapping_shl(8)) as u64 + load(&key[28..32]) as u64;

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    f1 += f0 >> 32;
    out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    f2 += f1 >> 32;
    out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    f3 += f2 >> 32;
    out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    out
}

fn multiply(t: &mut [u64; 5], h: [u32; 5], r: [u32; 5], s: [u32; 4]) {
    let h = h.map(u64::from);
    let r = r.map(u64::from);
    let s = s.map(u64::from);
    t[0] = h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0];
    t[1] = h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1];
    t[2] = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2];
    t[3] = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3];
    t[4] = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];
}

fn carry(t: &mut [u64; 5]) -> (u32, u32, u32, u32, u32) {
    let h0 = (t[0] as u32) & 0x3ffffff;
    let c = t[0] >> 26;
    t[1] += c;
    let h1 = (t[1] as u32) & 0x3ffffff;
    let b = (t[1] >> 26) as u32;
    t[2] += b as u64;
    let h2 = (t[2] as u32) & 0x3ffffff;
    let b = (t[2] >> 26) as u32;
    t[3] += b as u64;
    let h3 = (t[3] as u32) & 0x3ffffff;
    let b = (t[3] >> 26) as u32;
    t[4] += b as u64;
    let h4 = (t[4] as u32) & 0x3ffffff;
    let b = (t[4] >> 26) as u32;
    let h0 = h0.wrapping_add(b.wrapping_mul(5));
    (h0, h1, h2, h3, h4)
}

#[cfg(test)]
mod tests {
    use super::*;

    type PacketCase = (u32, &'static [u8], &'static [u8], &'static [u8]);

    fn key() -> Vec<u8> {
        (0u8..64).collect()
    }

    #[test]
    fn poly1305_reference() {
        // Produced by OpenSSH's own poly1305_auth (harness over poly1305.c).
        let key: [u8; 32] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];
        let tag = poly1305_auth(b"Cryptographic Forum Research Group", &key);
        assert_eq!(
            tag,
            [
                0x12, 0x06, 0x38, 0xa8, 0xc1, 0xb3, 0x22, 0x5f, 0x79, 0x1c, 0xcd, 0x6d, 0x01, 0xa6,
                0xe8, 0x56
            ]
        );
    }

    #[test]
    fn packet_vectors() {
        // Produced by OpenSSH's own chachapoly_crypt/get_length (key 00..3f).
        let cases: &[PacketCase] = &[
            (
                0,
                &[
                    0x00, 0x00, 0x00, 0x10, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x00,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                ],
                &[
                    0x94, 0x45, 0x0e, 0x49, 0x1d, 0xd0, 0x27, 0x5d, 0xc1, 0x89, 0x87, 0xf0, 0x13,
                    0x60, 0x5e, 0x62, 0xab, 0x46, 0x48, 0x20,
                ],
                &[
                    0x5b, 0x4b, 0x60, 0x3d, 0xe9, 0x41, 0x9e, 0x79, 0x0d, 0x79, 0x70, 0x09, 0xb6,
                    0x13, 0xd0, 0xb6,
                ],
            ),
            (
                1,
                &[
                    0x00, 0x00, 0x00, 0x10, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x00,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                ],
                &[
                    0xc9, 0x22, 0xa7, 0xb5, 0x6c, 0x34, 0x19, 0xb5, 0x5d, 0x65, 0x99, 0x5b, 0x2d,
                    0x70, 0x7c, 0x2c, 0xb7, 0x11, 0x11, 0x15,
                ],
                &[
                    0x86, 0xa4, 0xc4, 0x2f, 0x46, 0xfa, 0x58, 0x15, 0xd1, 0x4e, 0xf9, 0xeb, 0x28,
                    0x0a, 0xfc, 0x34,
                ],
            ),
            (
                300,
                &[
                    0x00, 0x00, 0x00, 0x10, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x00,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                ],
                &[
                    0x0f, 0x6a, 0x0d, 0x76, 0xf0, 0xd0, 0xc6, 0xc7, 0x7d, 0xad, 0xfc, 0x50, 0xc2,
                    0x7d, 0x46, 0x4e, 0xb7, 0x23, 0x78, 0x0a,
                ],
                &[
                    0x5b, 0xbc, 0xb8, 0x4d, 0x1f, 0x46, 0x7c, 0xd8, 0xc9, 0xef, 0x78, 0x1e, 0x31,
                    0xe3, 0x12, 0x30,
                ],
            ),
        ];

        let k = PacketKey::new(&key()).unwrap();
        for (seq, plain, ct, tag) in cases {
            let mut buf = plain.to_vec();
            let mut out_tag = [0u8; TAG_LEN];
            k.seal(*seq, &mut buf, &mut out_tag);
            assert_eq!(&buf, ct, "ciphertext mismatch at seq {seq}");
            assert_eq!(&out_tag, tag, "tag mismatch at seq {seq}");

            let mut len = [0u8; 4];
            len.copy_from_slice(&buf[..4]);
            assert_eq!(k.packet_length(*seq, len), plain[..4]);

            let mut open = buf.clone();
            k.open(*seq, &mut open, tag).expect("open failed");
            assert_eq!(&open, plain, "round-trip mismatch at seq {seq}");
        }
    }

    #[test]
    fn packet_vectors_multiblock() {
        // 44-byte packet: exercises payload past one Poly1305 block.
        let plain: &[u8] = &[
            0x00, 0x00, 0x00, 0x2c, 0x14, b'T', b'h', b'e', b' ', b'q', b'u', b'i', b'c', b'k',
            b' ', b'b', b'r', b'o', b'w', b'n', b' ', b'f', b'o', b'x', b' ', b'j', b'u', b'm',
            b'p', b's', b'!', b'!', b'!', b'!', b'!', 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba,
            0xbe, 0x01,
        ];
        assert_eq!(plain.len(), 44);
        let cases: &[(u32, &[u8], &[u8])] = &[
            (
                0,
                &[
                    0x94, 0x45, 0x0e, 0x75, 0x0c, 0xec, 0x2a, 0x54, 0x8d, 0x97, 0xd3, 0xb8, 0x70,
                    0x0a, 0x7c, 0x03, 0xdd, 0x2c, 0x39, 0x49, 0xd8, 0xd7, 0x9c, 0x8d, 0xc1, 0xc7,
                    0x2e, 0x31, 0x9c, 0x8b, 0xdd, 0x33, 0x0b, 0x14, 0x54, 0x82, 0xdf, 0xb6, 0xe7,
                    0xa7, 0x2f, 0x54, 0x82, 0x5c,
                ],
                &[
                    0x5c, 0xaf, 0x25, 0xea, 0x79, 0x88, 0xf8, 0xcc, 0xed, 0x24, 0xf1, 0x1f, 0x3d,
                    0xd2, 0x9a, 0x22,
                ],
            ),
            (
                1,
                &[
                    0xc9, 0x22, 0xa7, 0x89, 0x7d, 0x08, 0x14, 0xbc, 0x11, 0x7b, 0xcd, 0x13, 0x4e,
                    0x1a, 0x5e, 0x4d, 0xc1, 0x7b, 0x60, 0x7c, 0x30, 0x97, 0x50, 0x38, 0xee, 0xdb,
                    0x89, 0x18, 0x35, 0x49, 0x94, 0x09, 0x08, 0xcf, 0xbe, 0xd4, 0x7e, 0x93, 0x03,
                    0xc0, 0x4d, 0x41, 0x10, 0x82,
                ],
                &[
                    0x81, 0x62, 0x10, 0x62, 0x9e, 0xcb, 0x93, 0x91, 0xc0, 0xe0, 0x65, 0x37, 0x1f,
                    0xa9, 0x1e, 0xeb,
                ],
            ),
            (
                300,
                &[
                    0x0f, 0x6a, 0x0d, 0x4a, 0xe1, 0xec, 0xcb, 0xce, 0x31, 0xb3, 0xa8, 0x18, 0xa1,
                    0x17, 0x64, 0x2f, 0xc1, 0x49, 0x09, 0x63, 0xd9, 0x32, 0x21, 0x42, 0x04, 0xec,
                    0x6b, 0x33, 0xa2, 0x9d, 0xea, 0x21, 0x81, 0x52, 0x45, 0x50, 0x50, 0xb3, 0x74,
                    0x93, 0x6d, 0xa0, 0x6b, 0xe9,
                ],
                &[
                    0x95, 0xcd, 0x09, 0x76, 0x8d, 0xc3, 0x8b, 0xb0, 0x59, 0x11, 0x72, 0x3b, 0xa5,
                    0x03, 0x03, 0xe3,
                ],
            ),
        ];

        let k = PacketKey::new(&key()).unwrap();
        for (seq, ct, tag) in cases {
            let mut buf = plain.to_vec();
            let mut out_tag = [0u8; TAG_LEN];
            k.seal(*seq, &mut buf, &mut out_tag);
            assert_eq!(&buf, ct, "ciphertext mismatch at seq {seq}");
            assert_eq!(&out_tag, tag, "tag mismatch at seq {seq}");

            let mut open = buf.clone();
            k.open(*seq, &mut open, tag).expect("open failed");
            assert_eq!(&open, plain, "round-trip mismatch at seq {seq}");
        }
    }

    #[test]
    fn tampered_packets_fail() {
        let k = PacketKey::new(&key()).unwrap();
        let plain = vec![
            0x00, 0x00, 0x00, 0x10, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x00, 0x01,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let seq = 7u32;
        let mut buf = plain.clone();
        let mut tag = [0u8; TAG_LEN];
        k.seal(seq, &mut buf, &mut tag);

        // Flipped ciphertext bit.
        let mut bad = buf.clone();
        bad[9] ^= 0x01;
        assert!(k.open(seq, &mut bad, &tag).is_err());

        // Flipped length bit.
        let mut bad = buf.clone();
        bad[0] ^= 0x80;
        assert!(k.open(seq, &mut bad, &tag).is_err());

        // Flipped tag bit.
        let mut bad_tag = tag;
        bad_tag[3] ^= 0x04;
        let mut bad = buf.clone();
        assert!(k.open(seq, &mut bad, &bad_tag).is_err());

        // Wrong sequence number.
        let mut bad = buf.clone();
        assert!(k.open(seq + 1, &mut bad, &tag).is_err());

        // Short tag.
        let mut bad = buf.clone();
        assert!(k.open(seq, &mut bad, &tag[..8]).is_err());

        // Failed opens leave no plaintext behind.
        let mut bad = buf.clone();
        bad[9] ^= 0x01;
        let before = bad.clone();
        assert!(k.open(seq, &mut bad, &tag).is_err());
        assert_eq!(bad, before);
    }

    #[test]
    fn roundtrip_lengths_and_seqs() {
        let mut raw = [0u8; KEY_LEN];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x25).wrapping_add(0x11);
        }
        let k = PacketKey::new(&raw).unwrap();
        for len in [0usize, 1, 4, 15, 16, 17, 31, 32, 60, 64, 65, 100, 128, 200] {
            for seq in [0u32, 1, 42, u32::MAX - 1, u32::MAX] {
                let mut buf = vec![0u8; 4 + len];
                buf[..4].copy_from_slice(&(len as u32).to_be_bytes());
                for (i, b) in buf[4..].iter_mut().enumerate() {
                    *b = (i as u8).wrapping_add(seq as u8);
                }
                let want = buf.clone();
                let mut tag = [0u8; TAG_LEN];
                k.seal(seq, &mut buf, &mut tag);
                if len > 0 {
                    assert_ne!(&buf[4..], &want[4..]);
                }
                let mut len_enc = [0u8; 4];
                len_enc.copy_from_slice(&buf[..4]);
                assert_eq!(k.packet_length(seq, len_enc), want[..4]);
                k.open(seq, &mut buf, &tag).expect("open failed");
                assert_eq!(buf, want);
            }
        }
    }

    #[test]
    fn short_key_rejected() {
        assert!(PacketKey::new(&[0u8; 32]).is_none());
        assert!(PacketKey::new(&[0u8; 63]).is_none());
        assert!(PacketKey::new(&[]).is_none());
    }
}
