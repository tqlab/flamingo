// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

// This module implements a crypto core for encrypting and decrypting message streams
//
// The crypto core only encrypts and decrypts messages, using given keys. Negotiating and rotating the keys is out of
// scope of the crypto core. The crypto core assumes that the remote node will always have the necessary key to decrypt
// the message.
//
// The crypto core encrypts messages in place, writes some extra data (key id and nonce) into a given space and
// includes the given header data in the authentication tag. When decrypting messages, the crypto core reads the extra
// data, uses the key id to find the right key to decrypting the message and then decrypts the message, using the given
// nonce and including the given header data in the verification of the authentication tag.
//
// While the core only uses a single key at a time for encrypting messages, it is ready to decrypt messages based on
// one of 4 stored keys (the encryption key being one of them). An external key rotation is responsible for adding the
// key to the remote peer before switching to the key on the local peer for encryption.
//
// As mentioned, the encryption and decryption works in place. Therefore the parameter payload_and_tag contains (when
// decrypting) or provides space for (when encrypting) the payload and the authentication tag. When encrypting, that
// means, that the last TAG_LEN bytes of payload_and_tag must be reserved for the tag and must not contain payload
// bytes.
//
// The nonce is a value of 12 bytes (192 bits). Since both nodes can use the same key for encryption, the most
// significant byte (msb) of the nonce is initialized differently on both peers: one peer uses the value 0x00 and the
// other one 0x80. That means that the nonce space is essentially divided in two halves, one for each node.
//
// To save space and keep the encrypted data aligned to 64 bits, not all bytes of the nonce are transferred. Instead,
// only 7 bytes are included in messages (another byte is used for the key id, hence 64 bit alignment). The rest of the
// nonce is deduced by the nodes: All other bytes are assumed to be 0x00, except for the most significant byte, which
// is assumed to be the opposite ones own msb. This has two nice effects:
// 1) Long before the nonce could theoretically repeat, the messages can no longer be decrypted by the peer as the
// higher bytes are no longer zero as assumed.
// 2) By deducing the msb to be the opposite of ones own msb, it is no longer possible for an attacker to redirect a
// message back to the sender because then the assumed nonce will be wrong and the message fails to decrypt. Otherwise,
// this could lead to problems as nodes would be able to accidentally decrypt their own messages.
//
// In order to be resistent against replay attacks but allow for reordering of messages, the crypto core uses nonce
// pinning. For every active key, the biggest nonce seen so far is being tracked. Every second, the biggest nonce seen
// one second ago plus 1 becomes the minimum nonce that is accepted for that key. That means, that reordering can
// happen within one second but after a second, old messages will not be accepted anymore.

use byteorder::{ReadBytesExt, WriteBytesExt};
use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

use std::{
    io::{Cursor, Read, Write},
    mem,
};

use crate::{
    crypto::{EXTRA_LEN, TAG_LEN},
    error::Error,
    util::MsgBuffer,
};

use super::random_data;

const NONCE_LEN: usize = 12;

#[derive(PartialOrd, Ord, PartialEq, Debug, Eq, Clone)]
struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    fn zero() -> Self {
        Nonce([0; NONCE_LEN])
    }

    fn random(rand: &SystemRandom) -> Self {
        let mut nonce = Nonce::zero();
        rand.fill(&mut nonce.0[6..]).expect("Failed to obtain random bytes");
        nonce
    }

    fn set_msb(&mut self, val: u8) {
        self.0[0] = val
    }

    fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    fn increment(&mut self) {
        for i in (0..NONCE_LEN).rev() {
            let mut num = self.0[i];
            num = num.wrapping_add(1);
            self.0[i] = num;
            if num > 0 {
                return;
            }
        }
    }
}

struct CryptoKey {
    key: LessSafeKey,
    send_nonce: Nonce,
    min_nonce: Nonce,
    next_min_nonce: Nonce,
    seen_nonce: Nonce,
}

impl CryptoKey {
    fn new(rand: &SystemRandom, key: LessSafeKey, nonce_half: bool) -> Self {
        let mut send_nonce = Nonce::random(rand);
        send_nonce.set_msb(if nonce_half { 0x80 } else { 0x00 });
        CryptoKey {
            key,
            send_nonce,
            min_nonce: Nonce::zero(),
            next_min_nonce: Nonce::zero(),
            seen_nonce: Nonce::zero(),
        }
    }

    fn update_min_nonce(&mut self) {
        mem::swap(&mut self.min_nonce, &mut self.next_min_nonce);
        self.next_min_nonce = self.seen_nonce.clone();
        self.next_min_nonce.increment();
    }
}

pub struct CryptoCore {
    rand: SystemRandom,
    keys: [CryptoKey; 4],
    current_key: usize,
    nonce_half: bool,
}

impl CryptoCore {
    ///
    ///
    ///
    pub fn new(key: LessSafeKey, nonce_half: bool) -> Self {
        let rand = SystemRandom::new();
        let dummy_key_data = random_data(key.algorithm().key_len());
        let dummy_key1 = LessSafeKey::new(UnboundKey::new(key.algorithm(), &dummy_key_data).unwrap());
        let dummy_key2 = LessSafeKey::new(UnboundKey::new(key.algorithm(), &dummy_key_data).unwrap());
        let dummy_key3 = LessSafeKey::new(UnboundKey::new(key.algorithm(), &dummy_key_data).unwrap());
        Self {
            keys: [
                CryptoKey::new(&rand, key, nonce_half),
                CryptoKey::new(&rand, dummy_key1, nonce_half),
                CryptoKey::new(&rand, dummy_key2, nonce_half),
                CryptoKey::new(&rand, dummy_key3, nonce_half),
            ],
            current_key: 0,
            nonce_half,
            rand,
        }
    }

    ///
    ///
    ///
    pub fn encrypt(&mut self, buffer: &mut MsgBuffer) {
        let data_start = buffer.get_start();
        let data_length = buffer.len();
        assert!(buffer.get_start() >= EXTRA_LEN);
        buffer.set_start(data_start - EXTRA_LEN);
        buffer.set_length(data_length + EXTRA_LEN + TAG_LEN);
        let (extra, data_and_tag) = buffer.message_mut().split_at_mut(EXTRA_LEN);
        let (data, tag_space) = data_and_tag.split_at_mut(data_length);
        let key = &mut self.keys[self.current_key];
        key.send_nonce.increment();
        {
            let mut extra = Cursor::new(extra);
            extra.write_u8(self.current_key as u8).unwrap();
            extra.write_all(&key.send_nonce.as_bytes()[5..]).unwrap();
        }
        let nonce = aead::Nonce::assume_unique_for_key(*key.send_nonce.as_bytes());
        let tag = key.key.seal_in_place_separate_tag(nonce, aead::Aad::empty(), data).expect("Failed to encrypt");
        tag_space.clone_from_slice(tag.as_ref());
    }

    ///
    ///
    ///
    pub fn decrypt(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        assert!(buffer.len() >= EXTRA_LEN + TAG_LEN);
        let (extra, data_and_tag) = buffer.message_mut().split_at_mut(EXTRA_LEN);
        let key_id;
        let mut nonce;
        {
            let mut extra = Cursor::new(extra);
            key_id = extra.read_u8().map_err(|_| Error::Crypto("Input data too short"))? % 4;
            nonce = Nonce::zero();
            extra.read_exact(&mut nonce.0[5..]).map_err(|_| Error::Crypto("Input data too short"))?;
            nonce.set_msb(if self.nonce_half { 0x00 } else { 0x80 });
        }
        let key = &mut self.keys[key_id as usize];
        let result = Self::decrypt_with_key(key, nonce, data_and_tag);
        buffer.set_start(buffer.get_start() + EXTRA_LEN);
        buffer.set_length(buffer.len() - TAG_LEN);
        result
    }

    ///
    ///
    ///
    pub fn rotate_key(&mut self, key: LessSafeKey, id: u64, use_for_sending: bool) {
        debug!("Rotated key {} (use for sending: {})", id, use_for_sending);
        let id = (id % 4) as usize;
        self.keys[id] = CryptoKey::new(&self.rand, key, self.nonce_half);
        if use_for_sending {
            self.current_key = id
        }
    }

    ///
    ///
    ///
    pub fn algorithm(&self) -> &'static aead::Algorithm {
        self.keys[self.current_key].key.algorithm()
    }

    ///
    ///
    ///
    pub fn every_second(&mut self) {
        // Set min nonce on all keys
        for k in &mut self.keys {
            k.update_min_nonce();
        }
    }

    fn decrypt_with_key(key: &mut CryptoKey, nonce: Nonce, data_and_tag: &mut [u8]) -> Result<(), Error> {
        if nonce < key.min_nonce {
            return Err(Error::Crypto("Old nonce rejected"));
        }
        // decrypt
        let crypto_nonce = aead::Nonce::assume_unique_for_key(*nonce.as_bytes());
        key.key
            .open_in_place(crypto_nonce, aead::Aad::empty(), data_and_tag)
            .map_err(|_| Error::Crypto("Failed to decrypt data"))?;
        // last seen nonce
        if key.seen_nonce < nonce {
            key.seen_nonce = nonce;
        }
        Ok(())
    }
}
