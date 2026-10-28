// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! The `chacha20-poly1305@openssh.com` SSH packet protection.
//!
//! This is **not** the RFC 8439 AEAD offered by [`ChaCha20Poly1305`](super::chacha20poly1305).
//! It is the construction OpenSSH defined in `PROTOCOL.chacha20poly1305`:
//!
//! - 512 bits of key material form two independent 256-bit keys: the first 32 bytes are the
//!   payload key `K_2`, the last 32 bytes are the packet-length key `K_1`.
//! - The nonce is the 64-bit packet sequence number, big-endian, in ChaCha20's 64-bit-nonce
//!   layout (which equals the RFC layout with four zero bytes in front).
//! - The Poly1305 key is the first 32 bytes of the `K_2` keystream at block counter 0.
//! - The 4-byte packet length is encrypted with `K_1` at counter 0; the payload is encrypted
//!   with `K_2` starting at counter 1.
//! - The tag is Poly1305 over the encrypted length and encrypted payload, with no padding and
//!   no length block.
//! - A packet is authenticated **before** any of it is decrypted.

use crate::Error;
use crate::low::chacha20::ChaCha20;
use crate::low::poly1305::Poly1305;
use crate::low::{Entry, ct_equal, zeroise};

/// Length in bytes of the packet length field that is encrypted separately.
const LENGTH_LEN: usize = 4;

/// Packet protection state for one direction of an SSH connection.
pub struct SshChaCha20Poly1305 {
    payload_key: [u8; 32],
    length_key: [u8; 32],
}

impl SshChaCha20Poly1305 {
    /// Create the packet protection from the 64 bytes derived by the SSH key exchange.
    pub fn new(key: &[u8; 64]) -> Self {
        let mut payload_key = [0u8; 32];
        let mut length_key = [0u8; 32];
        payload_key.copy_from_slice(&key[..32]);
        length_key.copy_from_slice(&key[32..]);
        Self {
            payload_key,
            length_key,
        }
    }

    /// Decrypt the 4-byte packet length so the receiver knows how much to read.
    ///
    /// The result is unauthenticated until [`Self::open`] succeeds on the whole packet; callers
    /// must bound it before allocating.
    pub fn decrypt_length(&self, sequence_number: u32, encrypted: [u8; 4]) -> [u8; 4] {
        let _entry = Entry::new_secret();
        let mut length = encrypted;
        self.length_cipher(sequence_number).cipher(&mut length);
        length
    }

    /// Encrypt a packet in place and produce its tag.
    ///
    /// `packet` is the 4-byte length followed by the payload. The sequence number must not be
    /// reused with the same key; SSH guarantees this by re-keying before it can wrap.
    ///
    /// Returns [`Error::WrongLength`] if `packet` is shorter than the length field.
    pub fn seal(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        let (length, payload) = packet
            .split_first_chunk_mut::<LENGTH_LEN>()
            .ok_or(Error::WrongLength)?;

        let mut poly_key = self.poly_key(sequence_number);
        self.length_cipher(sequence_number).cipher(length);
        self.payload_cipher(sequence_number).cipher(payload);

        let mut poly = Poly1305::new(&poly_key);
        poly_key.iter_mut().for_each(|b| *b = 0);
        poly.add_bytes(length);
        poly.add_bytes(payload);
        tag_out.copy_from_slice(&poly.finish());
        Ok(())
    }

    /// Verify a packet's tag and, only if it is valid, decrypt the packet in place.
    ///
    /// `packet` is the encrypted length followed by the encrypted payload. On any failure the
    /// packet is left exactly as received and [`Error::DecryptFailed`] is returned.
    pub fn open(
        &self,
        sequence_number: u32,
        packet: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        if packet.len() < LENGTH_LEN {
            return Err(Error::WrongLength);
        }

        let mut poly_key = self.poly_key(sequence_number);
        let mut poly = Poly1305::new(&poly_key);
        poly_key.iter_mut().for_each(|b| *b = 0);
        poly.add_bytes(packet);
        let expected = poly.finish();

        if !ct_equal(&expected, tag) {
            return Err(Error::DecryptFailed);
        }

        let (length, payload) = packet.split_at_mut(LENGTH_LEN);
        self.length_cipher(sequence_number).cipher(length);
        self.payload_cipher(sequence_number).cipher(payload);
        Ok(())
    }

    /// The Poly1305 key: the first 32 bytes of the payload-key keystream at counter 0.
    fn poly_key(&self, sequence_number: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        self.payload_cipher_at(sequence_number, 0).cipher(&mut key);
        key
    }

    fn length_cipher(&self, sequence_number: u32) -> ChaCha20 {
        ChaCha20::new(&self.length_key, &layout(sequence_number, 0))
    }

    fn payload_cipher(&self, sequence_number: u32) -> ChaCha20 {
        self.payload_cipher_at(sequence_number, 1)
    }

    fn payload_cipher_at(&self, sequence_number: u32, counter: u32) -> ChaCha20 {
        ChaCha20::new(&self.payload_key, &layout(sequence_number, counter))
    }
}

/// ChaCha20 input words 12..16: 32-bit block counter, four zero bytes, then the big-endian
/// sequence number. With the high counter word and the nonce prefix both zero this is
/// identical to DJB's original 64-bit counter and 64-bit nonce layout that OpenSSH uses.
fn layout(sequence_number: u32, counter: u32) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&counter.to_le_bytes());
    block[8..].copy_from_slice(&u64::from(sequence_number).to_be_bytes());
    block
}

impl Drop for SshChaCha20Poly1305 {
    fn drop(&mut self) {
        zeroise(&mut self.payload_key);
        zeroise(&mut self.length_key);
    }
}
