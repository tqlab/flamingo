// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{error::Error, types::Address};
use std::io::{Cursor, Read};

pub trait Protocol: Sized {
    fn parse(_: &[u8]) -> Result<(Address, Address), Error>;
}

/// An ethernet frame dissector
///
/// This dissector is able to extract the source and destination addresses of ethernet frames.
///
/// If the ethernet frame contains a VLAN tag, both addresses will be prefixed with that tag,
/// resulting in 8-byte addresses. Additional nested tags will be ignored.
///
/// <pre>
/// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// + Destnation Address + Source Address +--Type--+--------- Data---------+--FCS--+
/// +------6 byte--------+----6 byte -----+-2 byte-+------46~1500 byte-----+ 4byte +
/// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// </pre>
///
/// Type: 0x0800 IP Packet, 0x8100 IEEE 802.1 Q
pub struct Frame;

impl Protocol for Frame {
    /// Parses an ethernet frame and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ethernet frame.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        // HOT PATH
        let mut cursor = Cursor::new(data);
        let mut src = [0; 16];
        let mut dst = [0; 16];
        let mut proto = [0; 2];
        cursor
            .read_exact(&mut dst[..6])
            .and_then(|_| cursor.read_exact(&mut src[..6]))
            .and_then(|_| cursor.read_exact(&mut proto))
            .map_err(|_| Error::Parse("Frame is too short"))?;

        // If the ethernet frame contains a VLAN tag
        if proto == [0x81, 0x00] {
            src.copy_within(..6, 2);
            dst.copy_within(..6, 2);
            cursor.read_exact(&mut src[..2]).map_err(|_| Error::Parse("Vlan frame is too short"))?;
            src[0] &= 0x0f; // restrict vlan id to 12 bits
            dst[..2].copy_from_slice(&src[..2]);
            if src[0..1] == [0, 0] {
                // treat vlan id 0x000 as untagged
                src.copy_within(2..8, 0);
                dst.copy_within(2..8, 0);

                // mac address
                return Ok((Address { data: src, len: 6 }, Address { data: dst, len: 6 }));
            }
            // vlan
            Ok((Address { data: src, len: 8 }, Address { data: dst, len: 8 }))
        } else {
            // mac address
            Ok((Address { data: src, len: 6 }, Address { data: dst, len: 6 }))
        }
    }
}

/// An IP packet dissector
///
/// This dissector is able to extract the source and destination ip addresses of ipv4 packets and
/// ipv6 packets.
#[allow(dead_code)]
pub struct Packet;

impl Protocol for Packet {
    /// Parses an ip packet and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ipv4 and ipv6 packet.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        // HOT PATH
        if data.is_empty() {
            return Err(Error::Parse("Empty header"));
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                if data.len() < 20 {
                    return Err(Error::Parse("Truncated IPv4 header"));
                }
                let src = Address::read_from_fixed(&data[12..], 4)?;
                let dst = Address::read_from_fixed(&data[16..], 4)?;
                Ok((src, dst))
            }
            6 => {
                if data.len() < 40 {
                    return Err(Error::Parse("Truncated IPv6 header"));
                }
                let src = Address::read_from_fixed(&data[8..], 16)?;
                let dst = Address::read_from_fixed(&data[24..], 16)?;
                Ok((src, dst))
            }
            _ => Err(Error::Parse("Invalid IP protocol version")),
        }
    }
}
