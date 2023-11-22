// Flamingo - Peer-to-Peer VPN
// Copyright (C) 2023  John Lee
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{device::Type, types::Mode, util::run_cmd, util::Duration};
pub use crate::crypto::Config as CryptoConfig;

use std::{cmp::max, collections::HashMap, ffi::OsStr, process, thread};
use structopt::StructOpt;

pub const DEFAULT_PEER_TIMEOUT: u16 = 300;
pub const DEFAULT_PORT: u16 = 3210;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct Config {
    pub device_type: Type,
    pub device_name: String,
    pub device_path: Option<String>,
    pub fix_rp_filter: bool,

    pub ip: Option<String>,
    pub advertise_addresses: Vec<String>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,

    pub crypto: CryptoConfig,

    pub listen: String,
    pub peers: Vec<String>,
    pub peer_timeout: Duration,
    pub keepalive: Option<Duration>,
    pub beacon_store: Option<String>,
    pub beacon_load: Option<String>,
    pub beacon_interval: Duration,
    pub beacon_password: Option<String>,
    pub mode: Mode,
    pub switch_timeout: Duration,
    pub claims: Vec<String>,
    pub auto_claim: bool,
    pub port_forwarding: bool,
    pub daemonize: bool,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub hook: Option<String>,
    pub hooks: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_type: Type::Tun,
            device_name: "vpn%d".to_string(),
            device_path: None,
            fix_rp_filter: false,
            ip: None,
            advertise_addresses: vec![],
            ifup: None,
            ifdown: None,
            crypto: CryptoConfig::default(),
            listen: "3210".to_string(),
            peers: vec![],
            peer_timeout: DEFAULT_PEER_TIMEOUT as Duration,
            keepalive: None,
            beacon_store: None,
            beacon_load: None,
            beacon_interval: 3600,
            beacon_password: None,
            mode: Mode::Normal,
            switch_timeout: 300,
            claims: vec![],
            auto_claim: true,
            port_forwarding: true,
            daemonize: false,
            pid_file: None,
            stats_file: None,
            user: None,
            group: None,
            hook: None,
            hooks: HashMap::new(),
        }
    }
}

impl Config {
    #[allow(clippy::cognitive_complexity)]
    pub fn merge_file(&mut self, mut file: ConfigFile) {
        if let Some(device) = file.device {
            if let Some(val) = device.type_ {
                self.device_type = val;
            }
            if let Some(val) = device.name {
                self.device_name = val;
            }
            if let Some(val) = device.path {
                self.device_path = Some(val);
            }
            if let Some(val) = device.fix_rp_filter {
                self.fix_rp_filter = val;
            }
        }
        if let Some(val) = file.ip {
            self.ip = Some(val);
        }
        if let Some(mut val) = file.advertise_addresses {
            self.advertise_addresses.append(&mut val);
        }
        if let Some(val) = file.ifup {
            self.ifup = Some(val);
        }
        if let Some(val) = file.ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = file.listen {
            self.listen = val;
        }
        if let Some(mut val) = file.peers {
            self.peers.append(&mut val);
        }
        if let Some(val) = file.peer_timeout {
            self.peer_timeout = val;
        }
        if let Some(val) = file.keepalive {
            self.keepalive = Some(val);
        }
        if let Some(beacon) = file.beacon {
            if let Some(val) = beacon.store {
                self.beacon_store = Some(val);
            }
            if let Some(val) = beacon.load {
                self.beacon_load = Some(val);
            }
            if let Some(val) = beacon.interval {
                self.beacon_interval = val;
            }
            if let Some(val) = beacon.password {
                self.beacon_password = Some(val);
            }
        }
        if let Some(val) = file.mode {
            self.mode = val;
        }
        if let Some(val) = file.switch_timeout {
            self.switch_timeout = val;
        }
        if let Some(mut val) = file.claims {
            self.claims.append(&mut val);
        }
        if let Some(val) = file.auto_claim {
            self.auto_claim = val;
        }
        if let Some(val) = file.port_forwarding {
            self.port_forwarding = val;
        }
        if let Some(val) = file.pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = file.stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = file.user {
            self.user = Some(val);
        }
        if let Some(val) = file.group {
            self.group = Some(val);
        }
        if let Some(val) = file.crypto.password {
            self.crypto.password = Some(val)
        }
        self.crypto.trusted_keys.append(&mut file.crypto.trusted_keys);
        if !file.crypto.algorithms.is_empty() {
            self.crypto.algorithms = file.crypto.algorithms.clone();
        }
        if let Some(val) = file.hook {
            self.hook = Some(val)
        }
        for (k, v) in file.hooks {
            self.hooks.insert(k, v);
        }
    }

    pub fn merge_args(&mut self, args: Args) {
        if args.daemon {
            self.daemonize = true;
        }
        if let Some(val) = args.pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = args.stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = args.user {
            self.user = Some(val);
        }
        if let Some(val) = args.group {
            self.group = Some(val);
        }
    }

    pub fn into_config_file(self) -> ConfigFile {
        ConfigFile {
            auto_claim: Some(self.auto_claim),
            claims: Some(self.claims),
            beacon: Some(ConfigFileBeacon {
                store: self.beacon_store,
                load: self.beacon_load,
                interval: Some(self.beacon_interval),
                password: self.beacon_password,
            }),
            device: Some(ConfigFileDevice {
                name: Some(self.device_name),
                path: self.device_path,
                type_: Some(self.device_type),
                fix_rp_filter: Some(self.fix_rp_filter),
            }),
            crypto: self.crypto,
            group: self.group,
            user: self.user,
            ifup: self.ifup,
            ifdown: self.ifdown,
            ip: self.ip,
            advertise_addresses: Some(self.advertise_addresses),
            keepalive: self.keepalive,
            listen: Some(self.listen),
            mode: Some(self.mode),
            peer_timeout: Some(self.peer_timeout),
            peers: Some(self.peers),
            pid_file: self.pid_file,
            port_forwarding: Some(self.port_forwarding),
            stats_file: self.stats_file,
            switch_timeout: Some(self.switch_timeout),
            hook: self.hook,
            hooks: self.hooks,
        }
    }

    pub fn get_keepalive(&self) -> Duration {
        match self.keepalive {
            Some(dur) => dur,
            None => max(self.peer_timeout / 2 - 60, 1),
        }
    }

    pub fn call_hook(
        &self, event: &'static str, envs: impl IntoIterator<Item = (&'static str, impl AsRef<OsStr>)>, detach: bool,
    ) {
        let mut script = None;
        if let Some(ref s) = self.hook {
            script = Some(s);
        }
        if let Some(s) = self.hooks.get(event) {
            script = Some(s);
        }
        if script.is_none() {
            return;
        }
        let script = script.unwrap();
        let mut cmd = process::Command::new("sh");
        cmd.arg("-c").arg(script).envs(envs).env("EVENT", event);
        debug!("Running event script: {:?}", cmd);
        if detach {
            thread::spawn(move || run_cmd(cmd));
        } else {
            run_cmd(cmd)
        }
    }
}

#[derive(StructOpt, Debug, Default)]
pub struct Args {
    /// Read configuration options from the specified file.
    #[structopt(long)]
    pub config: Option<String>,

    /// Print debug information
    #[structopt(short, long, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Only print errors and warnings
    #[structopt(short, long)]
    pub quiet: bool,

    /// Print the version and exit
    #[structopt(long)]
    pub version: bool,

    /// Run the process in the background
    #[structopt(long)]
    pub daemon: bool,

    /// Store the process id in this file when daemonizing
    #[structopt(long)]
    pub pid_file: Option<String>,

    /// Print statistics to this file
    #[structopt(long)]
    pub stats_file: Option<String>,

    /// Run as other user
    #[structopt(long)]
    pub user: Option<String>,

    /// Run as other group
    #[structopt(long)]
    pub group: Option<String>,

    /// Print logs also to this file
    #[structopt(long)]
    pub log_file: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileDevice {
    #[serde(rename = "type")]
    pub type_: Option<Type>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub fix_rp_filter: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileBeacon {
    pub store: Option<String>,
    pub load: Option<String>,
    pub interval: Option<Duration>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFile {
    pub device: Option<ConfigFileDevice>,

    pub ip: Option<String>,
    pub advertise_addresses: Option<Vec<String>>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,

    pub crypto: CryptoConfig,
    pub listen: Option<String>,
    pub peers: Option<Vec<String>>,
    pub peer_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,

    pub beacon: Option<ConfigFileBeacon>,
    pub mode: Option<Mode>,
    pub switch_timeout: Option<Duration>,
    pub claims: Option<Vec<String>>,
    pub auto_claim: Option<bool>,
    pub port_forwarding: Option<bool>,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub hook: Option<String>,
    pub hooks: HashMap<String, String>,
}
