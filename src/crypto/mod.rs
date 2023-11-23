// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

mod core;
mod crypto;

use std::{fmt::Debug, io::Read};

use crate::{error::Error, util::MsgBuffer};

pub use core::*;
pub use crypto::Crypto;

use ring::{
    aead::Algorithm,
    agreement::{EphemeralPrivateKey, UnparsedPublicKey},
    rand::{SecureRandom, SystemRandom},
    signature::ED25519_PUBLIC_KEY_LEN,
};
use smallvec::SmallVec;

pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_LEN];
pub type EcdhPublicKey = UnparsedPublicKey<SmallVec<[u8; 96]>>;
pub type EcdhPrivateKey = EphemeralPrivateKey;

pub const TAG_LEN: usize = 16;
pub const EXTRA_LEN: usize = 8;

pub trait Payload: Debug + PartialEq + Sized {
    fn write_to(&self, buffer: &mut MsgBuffer);
    fn read_from<R: Read>(r: R) -> Result<Self, Error>;
}

#[derive(Debug, PartialEq)]
pub enum MessageResult<P: Payload> {
    Message(u8),
    Initialized(P),
    InitializedWithReply(P),
    Reply,
    None,
}

#[derive(Clone)]
pub struct Algorithms {
    pub algorithm_speeds: SmallVec<[(&'static Algorithm, f32); 3]>,
    pub allow_unencrypted: bool,
}

pub fn random_data(size: usize) -> Vec<u8> {
    let rand = SystemRandom::new();
    let mut data = vec![0; size];
    rand.fill(&mut data).expect("Failed to obtain random bytes");
    data
}
