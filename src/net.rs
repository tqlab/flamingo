// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    io::{self},
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    os::unix::io::AsRawFd,
    str::FromStr,
};

use super::util::MsgBuffer;
use crate::{config::DEFAULT_PORT, port_forwarding::PortForwarding};

pub fn mapped_addr(addr: SocketAddr) -> SocketAddr {
    // HOT PATH
    match addr {
        SocketAddr::V4(addr4) => SocketAddr::new(IpAddr::V6(addr4.ip().to_ipv6_mapped()), addr4.port()),
        _ => addr,
    }
}

pub fn get_ip() -> IpAddr {
    let s = UdpSocket::bind("[::]:0").unwrap();
    s.connect("8.8.8.8:0").unwrap();
    s.local_addr().unwrap().ip()
}

pub trait Socket: AsRawFd + Sized {
    fn listen(addr: &str) -> Result<Self, io::Error>;
    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error>;
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    fn address(&self) -> Result<SocketAddr, io::Error>;
    fn create_port_forwarding(&self) -> Option<PortForwarding>;
}

pub fn parse_listen(port: &str, default_port: u16) -> SocketAddr {
    if let Ok(ip_addr) = IpAddr::from_str("::0") {
        let port = if let Ok(port) = port.parse::<u16>() { port } else { default_port };
        SocketAddr::new(ip_addr, port)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), default_port)
    }
}

impl Socket for UdpSocket {
    fn listen(addr: &str) -> Result<Self, io::Error> {
        let addr = parse_listen(addr, DEFAULT_PORT);
        UdpSocket::bind(addr)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let (size, addr) = self.recv_from(buffer.buffer())?;
        buffer.set_length(size);
        Ok(addr)
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.send_to(data, addr)
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        let mut addr = self.local_addr()?;
        addr.set_ip(get_ip());
        Ok(addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        PortForwarding::new(self.address().unwrap().port())
    }
}
