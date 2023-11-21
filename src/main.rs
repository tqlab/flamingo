// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

#[macro_use]
pub mod util;
pub mod beacon;
pub mod cloud;
pub mod config;
pub mod crypto;
pub mod device;
pub mod error;
pub mod logger;
pub mod messages;
pub mod net;
pub mod payload;
pub mod poll;
pub mod port_forwarding;
pub mod table;
pub mod traffic;
pub mod types;
#[cfg(feature = "wizard")]
pub mod wizard;

use structopt::StructOpt;

use std::{
    fs::{self, File, Permissions},
    io,
    net::UdpSocket,
    os::unix::fs::PermissionsExt,
    path::Path,
};

use crate::{
    cloud::GenericCloud,
    config::{Args, Command, Config, DEFAULT_PORT},
    crypto::Crypto,
    device::{TunTapDevice, Type},
    net::Socket,
    payload::Protocol,
    util::SystemTimeSource,
};

#[allow(clippy::cognitive_complexity)]
fn run<P: Protocol, S: Socket>(config: Config, socket: S) {
    let device = device::setup_device(&config);
    let port_forwarding = if config.port_forwarding { socket.create_port_forwarding() } else { None };
    let stats_file = match config.stats_file {
        None => None,
        Some(ref name) => {
            let path = Path::new(name);
            if path.exists() {
                try_fail!(fs::remove_file(path), "Failed to remove file {}: {}", name);
            }
            let file = try_fail!(File::create(name), "Failed to create stats file: {}");
            try_fail!(
                fs::set_permissions(name, Permissions::from_mode(0o644)),
                "Failed to set permissions on stats file: {}"
            );
            Some(file)
        }
    };
    let mut cloud =
        GenericCloud::<TunTapDevice, P, S, SystemTimeSource>::new(&config, socket, device, port_forwarding, stats_file);
    for mut addr in config.peers {
        if addr.find(':').unwrap_or(0) <= addr.find(']').unwrap_or(0) {
            // : not present or only in IPv6 address
            addr = format!("{}:{}", addr, DEFAULT_PORT)
        }
        try_fail!(cloud.connect(&addr as &str), "Failed to send message to {}: {}", &addr);
        cloud.add_reconnect_peer(addr);
    }
    if config.daemonize {
        info!("Running process as daemon");
        let mut daemonize = daemonize::Daemonize::new();
        if let Some(user) = config.user {
            daemonize = daemonize.user(&user as &str);
        }
        if let Some(group) = config.group {
            daemonize = daemonize.group(&group as &str);
        }
        if let Some(pid_file) = config.pid_file {
            daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
        }
        try_fail!(daemonize.start(), "Failed to daemonize: {}");
    } else if config.user.is_some() || config.group.is_some() {
        info!("Dropping privileges");
        let mut pd = privdrop::PrivDrop::default();
        if let Some(user) = config.user {
            pd = pd.user(user);
        }
        if let Some(group) = config.group {
            pd = pd.group(group);
        }
        try_fail!(pd.apply(), "Failed to drop privileges: {}");
    }
    cloud.run();
    if let Some(script) = config.ifdown {
        util::run_script(&script, cloud.ifname());
    }
}

fn main() {
    let args: Args = Args::from_args();
    if args.version {
        println!("Flamingo v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    logger::init_logger(args.log_file.as_ref(), args.verbose, args.quiet);

    if let Some(cmd) = args.cmd {
        match cmd {
            Command::GenKey { password } => {
                let (privkey, pubkey) = Crypto::generate_keypair(password.as_deref());
                println!("Private key: {}\nPublic key: {}\n", privkey, pubkey);
                println!(
                    "Attention: Keep the private key secret and use only the public key on other nodes to establish trust."
                );
            }
            Command::Completion { shell } => {
                Args::clap().gen_completions_to(env!("CARGO_PKG_NAME"), shell, &mut io::stdout());
            }
            #[cfg(feature = "wizard")]
            Command::Config { name } => {
                try_fail!(wizard::configure(name), "Wizard failed: {}");
            }
        }
        return;
    }
    let mut config = Config::default();
    if let Some(ref file) = args.config {
        info!("Reading config file '{}'", file);
        let f = try_fail!(File::open(file), "Failed to open config file: {:?}");
        let config_file = try_fail!(serde_yaml::from_reader(f), "Parse config file error: {:?}");
        config.merge_file(config_file)
    }
    config.merge_args(args);
    debug!("Config: {:?}", config);
    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        error!("Either password or private key must be set in config or given as parameter");
        return;
    }

    let socket = try_fail!(UdpSocket::listen(&config.listen), "Failed to open socket {}: {}", config.listen);
    match config.device_type {
        Type::Tap => run::<payload::Frame, _>(config, socket),
        Type::Tun => run::<payload::Packet, _>(config, socket),
    }
}
