// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp::{max, min},
    collections::HashMap,
    fmt,
    fs::{self, File},
    hash::BuildHasherDefault,
    io::{self, Cursor, Seek, SeekFrom, Write},
    marker::PhantomData,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    str::FromStr,
};

use fnv::FnvHasher;
use rand::{random, seq::SliceRandom, thread_rng};
use smallvec::{smallvec, SmallVec};

use crate::{
    beacon::BeaconSerializer,
    config::{Config, DEFAULT_PEER_TIMEOUT, DEFAULT_PORT},
    crypto::{Crypto, MessageResult},
    device::{Device, Type},
    error::Error,
    messages::{
        AddrList, NodeInfo, PeerInfo, MESSAGE_TYPE_CLOSE, MESSAGE_TYPE_DATA, MESSAGE_TYPE_KEEPALIVE,
        MESSAGE_TYPE_NODE_INFO,
    },
    net::{mapped_addr, Socket},
    payload::Protocol,
    peer::{PeerData, PeerCrypto, is_init_message},
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    table::ClaimTable,
    traffic::TrafficStats,
    types::{Address, Mode, NodeId, Range, RangeList},
    util::{addr_nice, bytes_to_hex, resolve, CtrlC, Duration, MsgBuffer, Time, TimeSource},
};

pub type Hash = BuildHasherDefault<FnvHasher>;

const MAX_RECONNECT_INTERVAL: u16 = 3600;
const RESOLVE_INTERVAL: Time = 300;
pub const STATS_INTERVAL: Time = 60;
const OWN_ADDRESS_RESET_INTERVAL: Time = 300;
const SPACE_BEFORE: usize = 100;

#[derive(Clone)]
pub struct ReconnectEntry {
    address: Option<(String, Time)>,
    resolved: AddrList,
    tries: u16,
    timeout: u16,
    next: Time,
    final_timeout: Option<Time>,
}

pub struct GenericCloud<D: Device, P: Protocol, S: Socket, TS: TimeSource> {
    node_id: NodeId,
    config: Config,
    learning: bool,
    broadcast: bool,
    peers: HashMap<SocketAddr, PeerData<NodeInfo, TS>, Hash>,
    reconnect_peers: SmallVec<[ReconnectEntry; 3]>,
    own_addresses: AddrList,
    pending_inits: HashMap<SocketAddr, PeerCrypto<NodeInfo>, Hash>,
    table: ClaimTable<TS>,
    socket: S,
    device: D,
    claims: RangeList,
    crypto: Crypto,
    next_peers: Time,
    peer_timeout_publish: u16,
    update_freq: u16,
    stats_file: Option<File>,
    next_housekeep: Time,
    next_stats_out: Time,
    next_beacon: Time,
    next_own_address_reset: Time,
    port_forwarding: Option<PortForwarding>,
    traffic: TrafficStats,
    beacon_serializer: BeaconSerializer<TS>,
    _dummy_p: PhantomData<P>,
    _dummy_ts: PhantomData<TS>,
}

impl<D: Device, P: Protocol, S: Socket, TS: TimeSource> GenericCloud<D, P, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config, socket: S, device: D, port_forwarding: Option<PortForwarding>, stats_file: Option<File>,
    ) -> Self {
        let (learning, broadcast) = match config.mode {
            Mode::Normal => match config.device_type {
                Type::Tap => (true, true),
                Type::Tun => (false, false),
            },
            Mode::Router => (false, false),
            Mode::Switch => (true, true),
            Mode::Hub => (false, true),
        };
        let mut claims = SmallVec::with_capacity(config.claims.len());
        for s in &config.claims {
            claims.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
        }
        if device.get_type() == Type::Tun && config.auto_claim {
            match device.get_ip() {
                Ok(ip) => {
                    let range = Range { base: Address::from_ipv4(ip), prefix_len: 32 };
                    info!("Auto-claiming {} due to interface address", range);
                    claims.push(range);
                }
                Err(Error::DeviceIo(_, e)) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                    info!("No address set on interface.")
                }
                Err(e) => error!("{}", e),
            }
        }
        let now = TS::now();
        let update_freq = config.get_keepalive() as u16;
        let node_id = random();
        let crypto = Crypto::new(&config.crypto).unwrap();
        let beacon_key = config.beacon_password.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let mut res = GenericCloud {
            node_id,
            peers: HashMap::default(),
            claims,
            learning,
            broadcast,
            pending_inits: HashMap::default(),
            reconnect_peers: SmallVec::new(),
            own_addresses: SmallVec::new(),
            peer_timeout_publish: config.peer_timeout as u16,
            table: ClaimTable::new(config.switch_timeout as Duration, config.peer_timeout as Duration),
            socket,
            device,
            next_peers: now,
            update_freq,
            stats_file,
            next_housekeep: now,
            next_stats_out: now + STATS_INTERVAL,
            next_beacon: now,
            next_own_address_reset: now + OWN_ADDRESS_RESET_INTERVAL,
            port_forwarding,
            traffic: TrafficStats::default(),
            beacon_serializer: BeaconSerializer::new(beacon_key),
            crypto,
            config: config.clone(),
            _dummy_p: PhantomData,
            _dummy_ts: PhantomData,
        };
        res.initialize();
        res
    }

    #[inline]
    pub fn ifname(&self) -> &str {
        self.device.ifname()
    }

    /// Sends the message to all peers
    ///
    /// # Errors
    /// Returns an `Error::SocketError` when the underlying system call fails or only part of the
    /// message could be sent (can this even happen?).
    /// Some messages could have been sent.
    #[inline]
    fn broadcast_msg(&mut self, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, msg.len(), self.peers.len());
        let mut msg_data = MsgBuffer::new(100);
        for (addr, peer_data) in &mut self.peers {
            msg_data.set_start(msg.get_start());
            msg_data.set_length(msg.len());
            msg_data.message_mut().clone_from_slice(msg.message());
            peer_data.send_message(type_, &mut msg_data)?;
            self.traffic.count_out_traffic(*addr, msg_data.len());
            match self.socket.send(msg_data.message(), *addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(e) => Err(Error::SocketIo("IOError when sending", e)),
            }?
        }
        Ok(())
    }

    #[inline]
    fn send_to(&mut self, addr: SocketAddr, msg: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        self.traffic.count_out_traffic(addr, msg.len());
        match self.socket.send(msg.message(), addr) {
            Ok(written) if written == msg.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e)),
        }
    }

    #[inline]
    fn send_msg(&mut self, addr: SocketAddr, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        if let Some(peer_data) = self.peers.get_mut(&addr) {
            peer_data.send_message(type_, msg)?;
            self.send_to(addr, msg)
        } else {
            Err(Error::Message("Sending to node that is not a peer"))
        }
    }

    pub fn reset_own_addresses(&mut self) -> io::Result<()> {
        self.own_addresses.clear();
        let socket_addr = self.socket.address().map(mapped_addr)?;
        // 1) Specified advertise addresses
        for addr in &self.config.advertise_addresses {
            if let Ok(addr) = addr.parse::<IpAddr>() {
                self.own_addresses.push(SocketAddr::new(addr, socket_addr.port()));
            }
        }
        // 2) Address of UDP socket
        self.own_addresses.push(socket_addr);
        // 3) Addresses from port forwarding
        if let Some(ref pfw) = self.port_forwarding {
            self.own_addresses.push(pfw.get_internal_ip().into());
            self.own_addresses.push(pfw.get_external_ip().into());
        }
        debug!("Own addresses: {:?}", self.own_addresses);
        // TODO: detect address changes and call event
        Ok(())
    }

    /// Returns the number of peers
    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Adds a peer to the reconnect list
    ///
    /// This method adds a peer to the list of nodes to reconnect to. A periodic task will try to
    /// connect to the peer if it is not already connected.
    pub fn add_reconnect_peer(&mut self, add: String) {
        let now = TS::now();
        let resolved = match resolve(&add as &str) {
            Ok(addrs) => addrs,
            Err(err) => {
                warn!("Failed to resolve {}: {:?}", add, err);
                smallvec![]
            }
        };
        self.reconnect_peers.push(ReconnectEntry {
            address: Some((add, now)),
            tries: 0,
            timeout: 1,
            resolved,
            next: now,
            final_timeout: None,
        })
    }

    /// Connects to a node given by its address
    ///
    /// This method connects to node by sending a `Message::Init` to it. If `addr` is a name that
    /// resolves to multiple addresses, one message is sent to each of them.
    /// If the node is already a connected peer or the address is blacklisted, no message is sent.
    ///
    /// # Errors
    /// This method returns `Error::NameError` if the address is a name that fails to resolve.
    pub fn connect<Addr: ToSocketAddrs + fmt::Debug + Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        let addrs = resolve(&addr)?.into_iter().map(mapped_addr).collect::<SmallVec<[SocketAddr; 3]>>();
        for addr in &addrs {
            if self.own_addresses.contains(addr)
                || self.peers.contains_key(addr)
                || self.pending_inits.contains_key(addr)
            {
                return Ok(());
            }
        }
        if !addrs.is_empty() {
            self.config.call_hook(
                "peer_connecting",
                vec![("PEER", format!("{:?}", addr_nice(addrs[0]))), ("IFNAME", self.device.ifname().to_owned())],
                true,
            );
        }
        // Send a message to each resolved address
        for a in addrs {
            // Ignore error this time
            self.connect_sock(a).ok();
        }
        Ok(())
    }

    fn create_node_info(&self) -> NodeInfo {
        let mut peers = smallvec![];
        for peer_data in self.peers.values() {
            peers.push(PeerInfo { node_id: Some(peer_data.get_node_id()), addrs: peer_data.get_addrs().clone() })
        }
        if peers.len() > 20 {
            let mut rng = rand::thread_rng();
            peers.partial_shuffle(&mut rng, 20);
            peers.truncate(20);
        }
        NodeInfo {
            node_id: self.node_id,
            peers,
            claims: self.claims.clone(),
            peer_timeout: Some(self.peer_timeout_publish),
            addrs: self.own_addresses.clone(),
        }
    }

    fn connect_sock(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let addr = mapped_addr(addr);
        if self.peers.contains_key(&addr)
            || self.own_addresses.contains(&addr)
            || self.pending_inits.contains_key(&addr)
        {
            return Ok(());
        }
        debug!("Connecting to {:?}", addr);
        let payload = self.create_node_info();
        let mut peer_crypto = crate::peer::peer_instance(&self.crypto, self.node_id, payload);
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        peer_crypto.initialize(&mut msg)?;
        self.pending_inits.insert(addr, peer_crypto);
        self.send_to(addr, &mut msg)
    }

    fn crypto_housekeep(&mut self) -> Result<(), Error> {
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        let mut del: SmallVec<[SocketAddr; 4]> = smallvec![];

        // pending init peers
        for addr in self.pending_inits.keys().copied().collect::<SmallVec<[SocketAddr; 4]>>() {
            if let Some(peer) = self.pending_inits.get_mut(&addr) {
                match peer.every_second(&mut msg) {
                    Err(_) => del.push(addr),
                    Ok(MessageResult::None) => (),
                    Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                    Ok(_) => unreachable!(),
                }
            }
        }
        // initialized peers
        for addr in self.peers.keys().copied().collect::<SmallVec<[SocketAddr; 16]>>() {
            if let Some(peer_data) = self.peers.get_mut(&addr) {
                match peer_data.every_second(&mut msg) {
                    Err(_) => del.push(addr),
                    Ok(MessageResult::None) => (),
                    Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                    Ok(_) => unreachable!(),
                }
            }
        }
        for addr in del {
            self.pending_inits.remove(&addr);
            if self.peers.remove(&addr).is_some() {
                self.connect_sock(addr)?;
            }
        }
        Ok(())
    }

    fn reconnect_to_peers(&mut self) -> Result<(), Error> {
        let now = TS::now();
        // Connect to those reconnect_peers that are due
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue;
            }
            self.connect(&entry.resolved as &[SocketAddr])?;
        }
        for entry in &mut self.reconnect_peers {
            // Schedule for next second if node is connected
            for addr in &entry.resolved {
                if self.peers.contains_key(addr) {
                    entry.tries = 0;
                    entry.timeout = 1;
                    entry.next = now + 1;
                    continue;
                }
            }
            // Resolve entries anew
            if let Some((ref address, ref mut next_resolve)) = entry.address {
                if *next_resolve <= now {
                    match resolve(address as &str) {
                        Ok(addrs) => entry.resolved = addrs,
                        Err(_) => match resolve(&format!("{}:{}", address, DEFAULT_PORT)) {
                            Ok(addrs) => entry.resolved = addrs,
                            Err(err) => warn!("Failed to resolve {}: {}", address, err),
                        },
                    }
                    *next_resolve = now + RESOLVE_INTERVAL;
                }
            }
            // Ignore if next attempt is already in the future
            if entry.next > now {
                continue;
            }
            // Exponential back-off: every 10 tries, the interval doubles
            entry.tries += 1;
            if entry.tries > 10 {
                entry.tries = 0;
                entry.timeout *= 2;
            }
            // Maximum interval is one hour
            if entry.timeout > MAX_RECONNECT_INTERVAL {
                entry.timeout = MAX_RECONNECT_INTERVAL;
            }
            // Schedule next connection attempt
            entry.next = now + Time::from(entry.timeout);
        }
        self.reconnect_peers.retain(|e| e.final_timeout.unwrap_or(now) >= now);
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        let now = TS::now();
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut del: SmallVec<[SocketAddr; 3]> = SmallVec::new();
        for (&addr, peer_data) in &self.peers {
            if peer_data.get_timeout() < now {
                del.push(addr);
            }
        }
        for addr in del {
            info!("Forgot peer {} due to timeout", addr_nice(addr));
            self.peers.remove(&addr);
            self.table.remove_claims(addr);
            self.connect_sock(addr)?; // Try to reconnect
        }
        self.table.housekeep();
        self.crypto_housekeep()?;
        // Periodically extend the port-forwarding
        if let Some(ref mut pfw) = self.port_forwarding {
            pfw.check_extend();
        }
        let now = TS::now();
        // Periodically send peer list to peers
        if self.next_peers <= now {
            debug!("Send peer list to all peers");
            let info = self.create_node_info();
            info.encode(&mut buffer);
            self.broadcast_msg(MESSAGE_TYPE_NODE_INFO, &mut buffer)?;
            // Reschedule for next update
            let min_peer_timeout =
                self.peers.iter().map(|p| p.1.get_peer_timeout()).min().unwrap_or(DEFAULT_PEER_TIMEOUT);
            let interval = min(self.update_freq, max(min_peer_timeout / 2 - 60, 1));
            self.next_peers = now + Time::from(interval);
        }
        self.reconnect_to_peers()?;
        if self.next_stats_out < now {
            // Write out the statistics
            self.write_out_stats().map_err(|err| Error::FileIo("Failed to write stats file", err))?;
            self.next_stats_out = now + STATS_INTERVAL;
            self.traffic.period(Some(5));
        }
        if let Some(peers) = self.beacon_serializer.get_cmd_results() {
            debug!("Loaded beacon with peers: {:?}", peers);
            for peer in peers {
                self.connect_sock(peer)?;
            }
        }
        if self.next_beacon < now {
            self.store_beacon()?;
            self.load_beacon()?;
            self.next_beacon = now + Time::from(self.config.beacon_interval);
        }
        // Periodically reset own peers
        if self.next_own_address_reset <= now {
            self.reset_own_addresses().map_err(|err| Error::SocketIo("Failed to get own addresses", err))?;
            self.next_own_address_reset = now + OWN_ADDRESS_RESET_INTERVAL;
        }
        Ok(())
    }

    /// Stores the beacon
    fn store_beacon(&mut self) -> Result<(), Error> {
        if let Some(ref path) = self.config.beacon_store {
            let peers: SmallVec<[SocketAddr; 3]> =
                self.own_addresses.choose_multiple(&mut thread_rng(), 3).cloned().collect();
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .write_to_cmd(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
            } else {
                self.beacon_serializer
                    .write_to_file(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to write beacon to file", e))?;
            }
        }
        Ok(())
    }

    /// Loads the beacon
    fn load_beacon(&mut self) -> Result<(), Error> {
        let peers;
        if let Some(ref path) = self.config.beacon_load {
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .read_from_cmd(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
                return Ok(());
            } else {
                peers = self
                    .beacon_serializer
                    .read_from_file(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to read beacon from file", e))?;
            }
        } else {
            return Ok(());
        }
        debug!("Loaded beacon with peers: {:?}", peers);
        for peer in peers {
            self.connect_sock(peer)?;
        }
        Ok(())
    }

    /// Writes out the statistics to a file
    fn write_out_stats(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut f) = self.stats_file {
            debug!("Writing out stats");
            f.seek(SeekFrom::Start(0))?;
            f.set_len(0)?;
            writeln!(f, "peers:")?;
            let now = TS::now();
            for (addr, peer_data) in &self.peers {
                writeln!(
                    f,
                    "  - \"{}\": {{ ttl_secs: {}, crypto: {} }}",
                    addr_nice(*addr),
                    peer_data.get_timeout() - now,
                    peer_data.algorithm_name()
                )?;
            }
            writeln!(f)?;
            self.table.write_out(f)?;
            writeln!(f)?;
            self.traffic.write_out(f)?;
            writeln!(f)?;
        }
        Ok(())
    }

    pub fn handle_interface_data(&mut self, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let (src, dst) = P::parse(data.message())?;
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, data.len());
        self.traffic.count_out_payload(dst, src, data.len());
        match self.table.lookup(dst) {
            Some(addr) => {
                // HOT PATH
                // Peer found for destination
                debug!("Found destination for {} => {}", dst, addr);
                self.send_msg(addr, MESSAGE_TYPE_DATA, data)?;
                if !self.peers.contains_key(&addr) {
                    // COLD PATH
                    // If the peer is not actually connected, remove the entry in the table and try
                    // to reconnect.
                    warn!("Destination for {} not found in peers: {}", dst, addr_nice(addr));
                    self.table.remove_claims(addr);
                    self.connect_sock(addr)?;
                }
            }
            None => {
                // COLD PATH
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    self.broadcast_msg(MESSAGE_TYPE_DATA, data)?;
                } else {
                    debug!("No destination for {} found, dropping", dst);
                    self.traffic.count_dropped_payload(data.len());
                }
            }
        }
        Ok(())
    }

    fn add_new_peer(&mut self, addr: SocketAddr, info: NodeInfo) -> Result<(), Error> {
        info!("Added peer {}", addr_nice(addr));
        self.config.call_hook(
            "peer_connected",
            vec![
                ("PEER", format!("{:?}", addr_nice(addr))),
                ("IFNAME", self.device.ifname().to_owned()),
                ("CLAIMS", info.claims.iter().map(|r| format!("{:?}", r)).collect::<Vec<String>>().join(" ")),
                ("NODE_ID", bytes_to_hex(&info.node_id)),
            ],
            true,
        );
        if let Some(init) = self.pending_inits.remove(&addr) {
            self.peers.insert(
                addr,
                PeerData::new(
                    info.addrs.clone(),
                    self.config.peer_timeout,
                    info.peer_timeout.unwrap_or(DEFAULT_PEER_TIMEOUT),
                    info.node_id,
                    init,
                ),
            );
            self.update_peer_info(addr, Some(info))?;
        } else {
            error!("No init for new peer {}", addr_nice(addr));
        }
        Ok(())
    }

    fn remove_peer(&mut self, addr: SocketAddr) {
        if let Some(peer_data) = self.peers.remove(&addr) {
            info!("Closing connection to {}", addr_nice(addr));
            self.table.remove_claims(addr);
            self.config.call_hook(
                "peer_disconnected",
                vec![
                    ("PEER", format!("{:?}", addr)),
                    ("IFNAME", self.device.ifname().to_owned()),
                    ("NODE_ID", bytes_to_hex(&peer_data.get_node_id())),
                ],
                true,
            );
        }
    }

    fn connect_to_peers(&mut self, peers: &[PeerInfo]) -> Result<(), Error> {
        'outer: for peer in peers {
            for addr in &peer.addrs {
                if self.peers.contains_key(addr) {
                    continue 'outer;
                }
            }
            if let Some(node_id) = peer.node_id {
                if self.node_id == node_id {
                    // Check addresses and add addresses that we don't know to own addresses
                    for addr in &peer.addrs {
                        if !self.own_addresses.contains(addr) {
                            self.own_addresses.push(*addr)
                        }
                    }
                    continue 'outer;
                }
                for p in self.peers.values() {
                    if p.get_node_id() == node_id {
                        continue 'outer;
                    }
                }
            }
            self.connect(&peer.addrs as &[SocketAddr])?;
        }
        Ok(())
    }

    fn update_peer_info(&mut self, addr: SocketAddr, info: Option<NodeInfo>) -> Result<(), Error> {
        if let Some(peer_data) = self.peers.get_mut(&addr) {
            peer_data.update_last_seen();
            peer_data.update_timeout(self.config.peer_timeout);
            if let Some(info) = &info {
                // Update peer addresses, always add seen address
                peer_data.clear_addrs();
                peer_data.add_addr(&addr);
                for addr in &info.addrs {
                    peer_data.add_addr(addr);
                }
            }
        } else {
            error!("Received peer update from non peer {}", addr_nice(addr));
            return Ok(());
        }
        if let Some(info) = info {
            debug!("Adding claims of peer {}: {:?}", addr_nice(addr), info.claims);
            self.table.set_claims(addr, info.claims);
            debug!("Received {} peers from {}: {:?}", info.peers.len(), addr_nice(addr), info.peers);
            self.connect_to_peers(&info.peers)?;
        }
        Ok(())
    }

    fn handle_payload_from(&mut self, peer: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let (src, dst) = P::parse(data.message())?;
        let len = data.len();
        debug!("Writing data to device: {} bytes. {} --> {}", len, &src, &dst);
        self.traffic.count_in_payload(src, dst, len);
        if let Err(e) = self.device.write(data) {
            error!("Failed to send via device: {}", e);
            return Err(e);
        }
        if self.learning {
            // Learn single address
            self.table.cache(src, peer);
        }
        Ok(())
    }

    fn handle_message(
        &mut self, src: SocketAddr, msg_result: MessageResult<NodeInfo>, data: &mut MsgBuffer,
    ) -> Result<(), Error> {
        // HOT PATH
        match msg_result {
            MessageResult::Message(type_) => {
                // HOT PATH
                match type_ {
                    MESSAGE_TYPE_DATA => {
                        // HOT PATH
                        self.handle_payload_from(src, data)?
                    }
                    MESSAGE_TYPE_NODE_INFO => {
                        // COLD PATH
                        let info = match NodeInfo::decode(Cursor::new(data.message())) {
                            Ok(val) => val,
                            Err(err) => {
                                self.traffic.count_invalid_protocol(data.len());
                                return Err(err);
                            }
                        };
                        self.update_peer_info(src, Some(info))?
                    }
                    MESSAGE_TYPE_KEEPALIVE => {
                        // COLD PATH
                        self.update_peer_info(src, None)?
                    }
                    MESSAGE_TYPE_CLOSE => {
                        // COLD PATH
                        self.remove_peer(src)
                    }
                    _ => {
                        // COLD PATH
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(Error::Message("Unknown message type"));
                    }
                }
            }
            MessageResult::Initialized(info) => {
                // COLD PATH
                self.add_new_peer(src, info)?
            }
            MessageResult::InitializedWithReply(info) => {
                // COLD PATH
                self.add_new_peer(src, info)?;
                self.send_to(src, data)?
            }
            MessageResult::Reply => {
                // COLD PATH
                self.send_to(src, data)?
            }
            MessageResult::None => {
                // COLD PATH
            }
        }
        Ok(())
    }

    pub fn handle_net_message(&mut self, src: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let src = mapped_addr(src);
        debug!("Received {} bytes from {}", data.len(), src);
        let msg_result = if let Some(init) = self.pending_inits.get_mut(&src) {
            // COLD PATH
            init.handle_message(data)
        } else if is_init_message(data.message()) {
            // COLD PATH
            let mut result = None;
            if let Some(peer_data) = self.peers.get_mut(&src) {
                if peer_data.has_init() {
                    result = Some(peer_data.handle_message(data))
                }
            }
            if let Some(result) = result {
                result
            } else {
                if let Some(init) = self.pending_inits.get_mut(&src) {
                    let msg_result = init.handle_message(data);
                    match msg_result {
                        Ok(res) => {
                            self.config.call_hook(
                                "peer_connecting",
                                vec![
                                    ("PEER", format!("{:?}", addr_nice(src))),
                                    ("IFNAME", self.device.ifname().to_owned()),
                                ],
                                true,
                            );
                            Ok(res)
                        }
                        Err(err) => {
                            self.traffic.count_invalid_protocol(data.len());
                            return Err(err);
                        }
                    }
                } else {
                    let mut init = crate::peer::peer_instance(&self.crypto, self.node_id, self.create_node_info());
                    let msg_result = init.handle_message(data);
                    match msg_result {
                        Ok(res) => {
                            self.config.call_hook(
                                "peer_connecting",
                                vec![
                                    ("PEER", format!("{:?}", addr_nice(src))),
                                    ("IFNAME", self.device.ifname().to_owned()),
                                ],
                                true,
                            );
                            self.pending_inits.insert(src, init);
                            Ok(res)
                        }
                        Err(err) => {
                            self.traffic.count_invalid_protocol(data.len());
                            return Err(err);
                        }
                    }
                }
            }
        } else if let Some(peer_data) = self.peers.get_mut(&src) {
            // HOT PATH
            peer_data.handle_message(data)
        } else {
            // COLD PATH
            info!("Ignoring non-init message from unknown peer {}", addr_nice(src));
            self.traffic.count_invalid_protocol(data.len());
            return Ok(());
        };
        // HOT PATH
        match msg_result {
            Ok(val) => {
                // HOT PATH
                self.handle_message(src, val, data)
            }
            Err(err) => {
                // COLD PATH
                self.traffic.count_invalid_protocol(data.len());
                Err(err)
            }
        }
    }

    fn initialize(&mut self) {
        if let Err(err) = self.reset_own_addresses() {
            error!("Failed to obtain local addresses: {}", err)
        }
    }

    fn handle_socket_event(&mut self, buffer: &mut MsgBuffer) {
        // HOT PATH
        let src = try_fail!(self.socket.receive(buffer), "Failed to read from network socket: {}");
        self.traffic.count_in_traffic(src, buffer.len());
        match self.handle_net_message(src, buffer) {
            Err(e @ Error::CryptoInitFatal(_)) => {
                // COLD PATH
                debug!("Fatal crypto init error from {}: {}", src, e);
                info!("Closing pending connection to {} due to error in crypto init", addr_nice(src));
                self.pending_inits.remove(&src);
                self.config.call_hook(
                    "peer_disconnected",
                    vec![("PEER", format!("{:?}", addr_nice(src))), ("IFNAME", self.device.ifname().to_owned())],
                    true,
                );
            }
            Err(e @ Error::CryptoInit(_)) => {
                // COLD PATH
                debug!("Recoverable init error from {}: {}", src, e);
                info!("Ignoring invalid init message from peer {}", addr_nice(src));
            }
            Err(e) => {
                // COLD PATH
                error!("{}", e);
            }
            Ok(_) => {} // HOT PATH
        }
    }

    fn handle_device_event(&mut self, buffer: &mut MsgBuffer) {
        // HOT PATH
        try_fail!(self.device.read(buffer), "Failed to read from device: {}");
        if let Err(e) = self.handle_interface_data(buffer) {
            error!("{}", e);
        }
    }

    /// The main method of the node
    ///
    /// This method will use epoll to wait in the sockets and the device at the same time.
    /// It will read from the sockets, decode and decrypt the message and then call the
    /// `handle_net_message` method. It will also read from the device and call
    /// `handle_interface_data` for each packet read.
    /// Also, this method will call `housekeep` every second.
    pub fn run(&mut self) {
        let ctrlc = CtrlC::new();

        let waiter = try_fail!(
            WaitImpl::new(self.socket.as_raw_fd(), self.device.as_raw_fd(), 1000),
            "Failed to setup poll: {}"
        );
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut poll_error = false;
        self.config.call_hook("vpn_started", vec![("IFNAME", self.device.ifname())], true);
        for evt in waiter {
            // HOT PATH
            match evt {
                WaitResult::Error(err) => {
                    // COLD PATH
                    if poll_error {
                        fail!("Poll wait failed again: {}", err);
                    }
                    debug!("Poll wait failed: {}, retrying...", err);
                    poll_error = true;
                }
                WaitResult::Timeout => {}
                WaitResult::Socket => self.handle_socket_event(&mut buffer),
                WaitResult::Device => self.handle_device_event(&mut buffer),
            }
            if self.next_housekeep < TS::now() {
                // COLD PATH
                poll_error = false;
                if ctrlc.was_pressed() {
                    break;
                }
                if let Err(e) = self.housekeep() {
                    error!("{}", e)
                }
                self.next_housekeep = TS::now() + 1
            }
        }
        info!("Shutting down...");
        self.config.call_hook("vpn_shutdown", vec![("IFNAME", self.device.ifname())], true);
        buffer.clear();
        self.broadcast_msg(MESSAGE_TYPE_CLOSE, &mut buffer).ok();
        if let Some(ref path) = self.config.beacon_store {
            let path = Path::new(path);
            if path.exists() {
                info!("Removing beacon file");
                if let Err(e) = fs::remove_file(path) {
                    error!("Failed to remove beacon file: {}", e)
                }
            }
        }
    }
}
