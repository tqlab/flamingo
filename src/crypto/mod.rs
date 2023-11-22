// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

mod common;
mod core;
mod init;
mod rotate;
mod crypto;

pub use self::core::{EXTRA_LEN, TAG_LEN};
pub use common::*;
pub use crypto::Crypto;
use ring::rand::{SystemRandom, SecureRandom};

pub fn random_data(size: usize) -> Vec<u8> {
    let rand = SystemRandom::new();
    let mut data = vec![0; size];
    rand.fill(&mut data).expect("Failed to obtain random bytes");
    data
}
