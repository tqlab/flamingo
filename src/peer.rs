use std::{marker::PhantomData, net::SocketAddr};

use crate::{
    crypto::{MessageResult, Payload, PeerCrypto},
    error::Error,
    messages::AddrList,
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
