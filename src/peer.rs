// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{marker::PhantomData, net::SocketAddr, sync::Arc};

use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    signature::Ed25519KeyPair,
};

use crate::{
    crypto::{Algorithms, Crypto, CryptoCore, Ed25519PublicKey, MessageResult, Payload},
    error::Error,
    init::{InitResult, InitState, CLOSING, STAGE_PING},
    messages::AddrList,
    rotate::RotationState,
    types::NodeId,
    util::{Duration, MsgBuffer, Time, TimeSource},
};

pub struct PeerData<P: Payload, TS: TimeSource> {
    addrs: AddrList,
    #[allow(dead_code)] //TODO: export in status
    last_seen: Time,
    timeout: Time,
    peer_timeout: u16,
    node_id: NodeId,
    peer: PeerCrypto<P>,
    _dummy_p: PhantomData<P>,
    _dummy_ts: PhantomData<TS>,
}

impl<P: Payload, TS: TimeSource> PeerData<P, TS> {
    ///
    ///
    ///
    pub fn new(addrs: AddrList, timeout: Duration, peer_timeout: u16, node_id: NodeId, peer: PeerCrypto<P>) -> Self {
        Self {
            addrs,
            last_seen: TS::now(),
            timeout: TS::now() + timeout as Time,
            peer_timeout,
            node_id,
            peer,
            _dummy_p: PhantomData,
            _dummy_ts: PhantomData,
        }
    }

    pub fn get_node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn get_last_seen(&self) -> Time {
        self.last_seen
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = TS::now();
    }

    pub fn get_timeout(&self) -> Time {
        self.timeout
    }

    pub fn update_timeout(&mut self, timeout: Duration) {
        self.last_seen = TS::now() + timeout as Time;
    }

    pub fn get_peer_timeout(&self) -> u16 {
        self.peer_timeout
    }

    pub fn send_message(&mut self, type_: u8, buffer: &mut MsgBuffer) -> Result<(), Error> {
        self.peer.send_message(type_, buffer)
    }

    pub fn get_addrs(&self) -> &AddrList {
        &self.addrs
    }

    pub fn get_addrs_mut(&mut self) -> &AddrList {
        &mut self.addrs
    }

    pub fn clear_addrs(&mut self) {
        self.addrs.clear();
    }

    pub fn add_addr(&mut self, addr: &SocketAddr) {
        if !self.addrs.contains(addr) {
            self.addrs.push(*addr);
        }
    }

    pub fn every_second(&mut self, out: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        self.peer.every_second(out)
    }

    pub fn algorithm_name(&self) -> &'static str {
        self.peer.algorithm_name()
    }

    pub fn has_init(&self) -> bool {
        self.peer.has_init()
    }

    pub fn handle_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        self.peer.handle_message(buffer)
    }
}

const INIT_MESSAGE_FIRST_BYTE: u8 = 0xff;
const MESSAGE_TYPE_ROTATION: u8 = 0x10;
const ROTATE_INTERVAL: usize = 120;

pub struct PeerCrypto<P: Payload> {
    #[allow(dead_code)]
    node_id: NodeId,
    init: Option<InitState<P>>,
    rotation: Option<RotationState>,
    unencrypted: bool,
    core: Option<CryptoCore>,
    rotate_counter: usize,
}

impl<P: Payload> PeerCrypto<P> {
    pub fn new(
        node_id: NodeId, init_payload: P, key_pair: Arc<Ed25519KeyPair>, trusted_keys: Arc<[Ed25519PublicKey]>,
        algorithms: Algorithms,
    ) -> Self {
        Self {
            node_id,
            init: Some(InitState::new(node_id, init_payload, key_pair, trusted_keys, algorithms)),
            rotation: None,
            unencrypted: false,
            core: None,
            rotate_counter: 0,
        }
    }

    fn get_init(&mut self) -> Result<&mut InitState<P>, Error> {
        if let Some(init) = &mut self.init {
            Ok(init)
        } else {
            Err(Error::InvalidCryptoState("Initialization already finished"))
        }
    }

    fn get_core(&mut self) -> Result<&mut CryptoCore, Error> {
        if let Some(core) = &mut self.core {
            Ok(core)
        } else {
            Err(Error::InvalidCryptoState("Crypto core not ready yet"))
        }
    }

    fn get_rotation(&mut self) -> Result<&mut RotationState, Error> {
        if let Some(rotation) = &mut self.rotation {
            Ok(rotation)
        } else {
            Err(Error::InvalidCryptoState("Key rotation not initialized"))
        }
    }

    pub fn initialize(&mut self, out: &mut MsgBuffer) -> Result<(), Error> {
        let init = self.get_init()?;
        if init.stage() != STAGE_PING {
            Err(Error::InvalidCryptoState("Initialization already ongoing"))
        } else {
            init.send_ping(out);
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            Ok(())
        }
    }

    pub fn has_init(&self) -> bool {
        self.init.is_some()
    }

    pub fn is_ready(&self) -> bool {
        self.core.is_some()
    }

    pub fn algorithm_name(&self) -> &'static str {
        if let Some(ref core) = self.core {
            let algo = core.algorithm();
            if algo == &aead::CHACHA20_POLY1305 {
                "CHACHA20"
            } else if algo == &aead::AES_128_GCM {
                "AES128"
            } else if algo == &aead::AES_256_GCM {
                "AES256"
            } else {
                unreachable!()
            }
        } else {
            "PLAIN"
        }
    }

    fn handle_init_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        let result = self.get_init()?.handle_init(buffer)?;
        if !buffer.is_empty() {
            buffer.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
        }
        match result {
            InitResult::Continue => Ok(MessageResult::Reply),
            InitResult::Success { peer_payload, is_initiator } => {
                self.core = self.get_init()?.take_core();
                if self.core.is_none() {
                    self.unencrypted = true;
                }
                if self.get_init()?.stage() == CLOSING {
                    self.init = None
                }
                if self.core.is_some() {
                    self.rotation = Some(RotationState::new(!is_initiator, buffer));
                }
                if !is_initiator {
                    if self.unencrypted {
                        return Ok(MessageResult::Initialized(peer_payload));
                    }
                    assert!(!buffer.is_empty());
                    buffer.prepend_byte(MESSAGE_TYPE_ROTATION);
                    self.encrypt_message(buffer)?;
                }
                Ok(MessageResult::InitializedWithReply(peer_payload))
            }
        }
    }

    fn handle_rotate_message(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.unencrypted {
            return Ok(());
        }
        if let Some(rot) = self.get_rotation()?.handle_message(data)? {
            let core = self.get_core()?;
            let algo = core.algorithm();
            let key = LessSafeKey::new(UnboundKey::new(algo, &rot.key[..algo.key_len()]).unwrap());
            core.rotate_key(key, rot.id, rot.use_for_sending);
        }
        Ok(())
    }

    fn encrypt_message(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        if self.unencrypted {
            return Ok(());
        }
        self.get_core()?.encrypt(buffer);
        Ok(())
    }

    fn decrypt_message(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        if self.unencrypted {
            return Ok(());
        }
        self.get_core()?.decrypt(buffer)
    }

    pub fn handle_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        // HOT PATH
        if buffer.is_empty() {
            return Err(Error::InvalidCryptoState("No message in buffer"));
        }
        if is_init_message(buffer.buffer()) {
            // COLD PATH
            debug!("Received init message");
            buffer.take_prefix();
            self.handle_init_message(buffer)
        } else {
            // HOT PATH
            debug!("Received encrypted message");
            self.decrypt_message(buffer)?;
            let msg_type = buffer.take_prefix();
            if msg_type == MESSAGE_TYPE_ROTATION {
                // COLD PATH
                debug!("Received rotation message");
                self.handle_rotate_message(buffer.buffer())?;
                buffer.clear();
                Ok(MessageResult::None)
            } else {
                Ok(MessageResult::Message(msg_type))
            }
        }
    }

    pub fn send_message(&mut self, type_: u8, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        assert_ne!(type_, MESSAGE_TYPE_ROTATION);
        buffer.prepend_byte(type_);
        self.encrypt_message(buffer)
    }

    pub fn every_second(&mut self, out: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        out.clear();
        if let Some(ref mut core) = self.core {
            core.every_second()
        }
        if let Some(ref mut init) = self.init {
            init.every_second(out)?;
        }

        // reset init to None.
        if self.init.as_ref().map(|i| i.stage()).unwrap_or(CLOSING) == CLOSING {
            self.init = None
        }
        if !out.is_empty() {
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            return Ok(MessageResult::Reply);
        }
        if let Some(ref mut rotate) = self.rotation {
            self.rotate_counter += 1;
            if self.rotate_counter >= ROTATE_INTERVAL {
                self.rotate_counter = 0;
                if let Some(rot) = rotate.cycle(out) {
                    let core = self.get_core()?;
                    let algo = core.algorithm();
                    let key = LessSafeKey::new(UnboundKey::new(algo, &rot.key[..algo.key_len()]).unwrap());
                    core.rotate_key(key, rot.id, rot.use_for_sending);
                }
                if !out.is_empty() {
                    out.prepend_byte(MESSAGE_TYPE_ROTATION);
                    self.encrypt_message(out)?;
                    return Ok(MessageResult::Reply);
                }
            }
        }
        Ok(MessageResult::None)
    }
}

pub fn is_init_message(msg: &[u8]) -> bool {
    // HOT PATH
    !msg.is_empty() && msg[0] == INIT_MESSAGE_FIRST_BYTE
}

///
///
///
pub fn peer_instance<P: Payload>(crypto: &Crypto, node_id: NodeId, payload: P) -> PeerCrypto<P> {
    PeerCrypto::new(node_id, payload, crypto.get_key_pair(), crypto.get_trusted_keys(), crypto.get_algorithms())
}
