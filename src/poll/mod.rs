// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[cfg(any(target_os = "linux", target_os = "android"))]
mod epoll;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::epoll::EpollWait as WaitImpl;

use std::io;

pub enum WaitResult {
    Timeout,
    Socket,
    Device,
    Error(io::Error),
}
