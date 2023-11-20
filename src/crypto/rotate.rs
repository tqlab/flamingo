// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

// This module implements a turn based key rotation.
//
// The main idea is that both peers periodically create ecdh key pairs and exchange their public keys to create
// common key material. There are always two separate ecdh handshakes going on: one initiated by each peer.
// However, one handshake is always one step ahead of the other. That means that every message being sent contains a
// public key from step 1 of the handshake "proposed key" and a public key from step 2 of the handshake "confirmed
// key" (all messages except first message).
//
// When receiving a message from the peer, the node will create a new ecdh key pair and perform the key
// calculation for the proposed key. The peer will store the public key for the confirmation as pending to be
// confirmed in the next cycle. Also, if the message contains a confirmation (all but the very first message do),
// the node will use the stored private key to perform the ecdh key calculation and emit that key to be used in
// the crypto stream.
//
// Upon each cycle, a node first checks if it still has a proposed key that has not been confirmed by the remote
// peer. If so, a message must have been lost and the whole last message including the proposed key as well as the
// last confirmed key is being resent. If no proposed key is stored, the node will create a new ecdh key pair, and
// store the private key as proposed key. It then sends out a message containing the public key as proposal, as
// well as confirming the pending key. This key is also emitted to be added to the crypto stream but not to be
// used for encrypting.
//
// Monotonically increasing message ids guard the communication from message duplication and also serve as
// identifiers for the keys to be used in the crypto stream. Since the keys are rotating, the last 2 bits of the
// id are enough to identify the key.
//
// The whole communication is sent via the crypto stream and is therefore encrypted and protected against tampering.

use super::Key;
use crate::{error::Error, util::MsgBuffer};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    rand::SystemRandom,
};
use smallvec::{smallvec, SmallVec};
use std::io::{self, Cursor, Read, Write};

type EcdhPublicKey = UnparsedPublicKey<SmallVec<[u8; 96]>>;
type EcdhPrivateKey = EphemeralPrivateKey;

pub struct RotationMessage {
    message_id: u64,
    propose: EcdhPublicKey,
    confirm: Option<EcdhPublicKey>,
}

impl RotationMessage {
    #[allow(dead_code)]
    pub fn read_from<R: Read>(mut r: R) -> Result<Self, io::Error> {
        let message_id = r.read_u64::<NetworkEndian>()?;
        let key_len = r.read_u8()? as usize;
        let mut key_data = smallvec![0; key_len];
        r.read_exact(&mut key_data)?;
        let propose = EcdhPublicKey::new(&X25519, key_data);
        let key_len = r.read_u8()? as usize;
        let confirm = if key_len > 0 {
            let mut key_data = smallvec![0; key_len];
            r.read_exact(&mut key_data)?;
            Some(EcdhPublicKey::new(&X25519, key_data))
        } else {
            None
        };
        Ok(RotationMessage { message_id, propose, confirm })
    }

    #[allow(dead_code)]
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        w.write_u64::<NetworkEndian>(self.message_id)?;
        let key_bytes = self.propose.bytes();
        w.write_u8(key_bytes.len() as u8)?;
        w.write_all(key_bytes)?;
        if let Some(ref key) = self.confirm {
            let key_bytes = key.bytes();
            w.write_u8(key_bytes.len() as u8)?;
            w.write_all(key_bytes)?;
        } else {
            w.write_u8(0)?;
        }
        Ok(())
    }
}

pub struct RotationState {
    confirmed: Option<(EcdhPublicKey, u64)>, // sent by remote, already confirmed
    pending: Option<(Key, EcdhPublicKey)>,   // sent by remote, to be confirmed
    proposed: Option<EcdhPrivateKey>,        // my own, proposed but not confirmed
    message_id: u64,
    timeout: bool,
}

pub struct RotatedKey {
    pub key: Key,
    pub id: u64,
    pub use_for_sending: bool,
}

impl RotationState {
    #[allow(dead_code)]
    pub fn new(initiator: bool, out: &mut MsgBuffer) -> Self {
        if initiator {
            let (private_key, public_key) = Self::create_key();
            Self::send(&RotationMessage { message_id: 1, confirm: None, propose: public_key }, out);
            Self { confirmed: None, pending: None, proposed: Some(private_key), message_id: 1, timeout: false }
        } else {
            Self { confirmed: None, pending: None, proposed: None, message_id: 0, timeout: false }
        }
    }

    fn send(msg: &RotationMessage, out: &mut MsgBuffer) {
        assert!(out.is_empty());
        debug!("Rotation sending message with id {}", msg.message_id);
        let len;
        {
            let mut cursor = Cursor::new(out.buffer());
            msg.write_to(&mut cursor).expect("Buffer too small");
            len = cursor.position() as usize;
        }
        out.set_length(len);
    }

    fn create_key() -> (EcdhPrivateKey, EcdhPublicKey) {
        let rand = SystemRandom::new();
        let private_key = EcdhPrivateKey::generate(&X25519, &rand).unwrap();
        let public_key = Self::compute_public_key(&private_key);
        (private_key, public_key)
    }

    fn compute_public_key(private_key: &EcdhPrivateKey) -> EcdhPublicKey {
        let public_key = private_key.compute_public_key().unwrap();
        let mut vec = SmallVec::<[u8; 96]>::new();
        vec.extend_from_slice(public_key.as_ref());
        EcdhPublicKey::new(&X25519, vec)
    }

    fn derive_key(private_key: EcdhPrivateKey, public_key: EcdhPublicKey) -> Key {
        agree_ephemeral(private_key, &public_key, |k| {
            let mut vec = Key::new();
            vec.extend_from_slice(k);
            vec
        })
        .unwrap()
    }

    pub fn handle_message(&mut self, msg: &[u8]) -> Result<Option<RotatedKey>, Error> {
        let msg =
            RotationMessage::read_from(Cursor::new(msg)).map_err(|_| Error::Crypto("Rotation message too short"))?;
        Ok(self.process_message(msg))
    }

    pub fn process_message(&mut self, msg: RotationMessage) -> Option<RotatedKey> {
        if msg.message_id <= self.message_id {
            return None;
        }
        debug!("Received rotation message with id {}", msg.message_id);
        self.timeout = false;
        // Create key from proposal and store reply as pending
        let (private_key, public_key) = Self::create_key();
        let key = Self::derive_key(private_key, msg.propose);
        self.pending = Some((key, public_key));
        // If proposed key has been confirmed, derive and use key
        if let Some(peer_key) = msg.confirm {
            if let Some(private_key) = self.proposed.take() {
                let key = Self::derive_key(private_key, peer_key);
                return Some(RotatedKey { key, id: msg.message_id, use_for_sending: true });
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn cycle(&mut self, out: &mut MsgBuffer) -> Option<RotatedKey> {
        if let Some(ref private_key) = self.proposed {
            // Still a proposed key that has not been confirmed, proposal must have been lost
            if self.timeout {
                let proposed_key = Self::compute_public_key(private_key);
                if let Some((ref confirmed_key, message_id)) = self.confirmed {
                    // Reconfirm last confirmed key
                    Self::send(
                        &RotationMessage { confirm: Some(confirmed_key.clone()), propose: proposed_key, message_id },
                        out,
                    );
                } else {
                    // First message has been lost
                    Self::send(&RotationMessage { confirm: None, propose: proposed_key, message_id: 1 }, out);
                }
            } else {
                self.timeout = true;
            }
        } else {
            // No proposed key, our turn to propose a new one
            if let Some((key, confirm_key)) = self.pending.take() {
                // Send out pending confirmation and register key for receiving
                self.message_id += 2;
                let message_id = self.message_id;
                let (private_key, propose_key) = Self::create_key();
                self.proposed = Some(private_key);
                self.confirmed = Some((confirm_key.clone(), message_id));
                Self::send(&RotationMessage { confirm: Some(confirm_key), propose: propose_key, message_id }, out);
                return Some(RotatedKey { key, id: message_id, use_for_sending: false });
            } else {
                // Nothing pending nor proposed, still waiting to receive message 1
                // Do nothing, peer will retry
            }
        }
        None
    }
}
