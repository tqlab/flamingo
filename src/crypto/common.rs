use super::{
    core::CryptoCore,
    init::{self, InitResult, InitState, CLOSING},
    random_data,
    rotate::RotationState,
    EXTRA_LEN,
};
use crate::{
    error::Error,
    types::NodeId,
    util::{from_base62, MsgBuffer},
};
use ring::{
    aead::{self, Algorithm, LessSafeKey, UnboundKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey},
    pbkdf2,
    signature::{Ed25519KeyPair, KeyPair, ED25519_PUBLIC_KEY_LEN},
};
use smallvec::{smallvec, SmallVec};
use std::{
    fmt::Debug,
    io::Read,
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

const SALT: &[u8; 32] = b"flamingoflamiNGOFlamingoflamingo";
const INIT_MESSAGE_FIRST_BYTE: u8 = 0xff;
const MESSAGE_TYPE_ROTATION: u8 = 0x10;

pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_LEN];
pub type EcdhPublicKey = UnparsedPublicKey<SmallVec<[u8; 96]>>;
pub type EcdhPrivateKey = EphemeralPrivateKey;
pub type Key = SmallVec<[u8; 32]>;

const DEFAULT_ALGORITHMS: [&str; 3] = ["AES128", "AES256", "CHACHA20"];

#[cfg(test)]
const SPEED_TEST_TIME: f32 = 0.02;
#[cfg(not(test))]
const SPEED_TEST_TIME: f32 = 0.1;

const ROTATE_INTERVAL: usize = 120;

pub trait Payload: Debug + PartialEq + Sized {
    fn write_to(&self, buffer: &mut MsgBuffer);
    fn read_from<R: Read>(r: R) -> Result<Self, Error>;
}

#[derive(Clone)]
pub struct Algorithms {
    pub algorithm_speeds: SmallVec<[(&'static Algorithm, f32); 3]>,
    pub allow_unencrypted: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct Config {
    pub password: Option<String>,
    pub trusted_keys: Vec<String>,
    pub algorithms: Vec<String>,
}

pub struct Crypto {
    key_pair: Arc<Ed25519KeyPair>,
    trusted_keys: Arc<[Ed25519PublicKey]>,
    algorithms: Algorithms,
}

impl Crypto {
    ///
    ///
    ///
    pub fn new(config: &Config) -> Result<Self, Error> {
        let key_pair = if let Some(password) = &config.password {
            Self::keypair_from_password(password)
        } else {
            return Err(Error::InvalidConfig("Either private_key or password must be set"));
        };
        let mut trusted_keys = vec![];
        for tn in &config.trusted_keys {
            trusted_keys.push(Self::parse_public_key(tn)?);
        }
        if trusted_keys.is_empty() {
            info!("Trusted keys not set, trusting only own public key");
            let mut key = [0; ED25519_PUBLIC_KEY_LEN];
            key.clone_from_slice(key_pair.public_key().as_ref());
            trusted_keys.push(key);
        }
        let (unencrypted, allowed_algos) = parse_algorithms(&config.algorithms)?;
        if unencrypted {
            warn!("Crypto settings allow unencrypted connections")
        }
        let mut algos = Algorithms { algorithm_speeds: smallvec![], allow_unencrypted: unencrypted };
        let duration = Duration::from_secs_f32(SPEED_TEST_TIME);
        let mut speeds = Vec::new();
        for algo in allowed_algos {
            let speed = test_speed(algo, &duration);
            algos.algorithm_speeds.push((algo, speed as f32));
            speeds.push((format!("{:?}", algo), speed as f32));
        }
        if !speeds.is_empty() {
            info!(
                "Crypto speeds: {}",
                speeds.into_iter().map(|(a, s)| format!("{}: {:.1} MiB/s", a, s)).collect::<Vec<_>>().join(", ")
            );
        }
        Ok(Self {
            key_pair: Arc::new(key_pair),
            trusted_keys: trusted_keys.into_boxed_slice().into(),
            algorithms: algos,
        })
    }

    fn keypair_from_password(password: &str) -> Ed25519KeyPair {
        let mut key = [0; 32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(4096).unwrap(), SALT, password.as_bytes(), &mut key);
        Ed25519KeyPair::from_seed_unchecked(&key).unwrap()
    }

    fn parse_public_key(pubkey: &str) -> Result<Ed25519PublicKey, Error> {
        let pubkey = from_base62(pubkey).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(Error::InvalidConfig("Failed to parse public key"));
        }
        let mut result = [0; ED25519_PUBLIC_KEY_LEN];
        result.clone_from_slice(&pubkey);
        Ok(result)
    }

    fn get_key_pair(&self) -> Arc<Ed25519KeyPair> {
        self.key_pair.clone()
    }

    fn get_trusted_keys(&self) -> Arc<[Ed25519PublicKey]> {
        self.trusted_keys.clone()
    }

    fn get_algorithms(&self) -> Algorithms {
        self.algorithms.clone()
    }
}

#[derive(Debug, PartialEq)]
pub enum MessageResult<P: Payload> {
    Message(u8),
    Initialized(P),
    InitializedWithReply(P),
    Reply,
    None,
}

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
        if init.stage() != init::STAGE_PING {
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
                if self.get_init()?.stage() == init::CLOSING {
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
pub fn parse_algorithms(algos: &[String]) -> Result<(bool, Vec<&'static aead::Algorithm>), Error> {
    let algorithms = algos.iter().map(|a| a as &str).collect::<Vec<_>>();
    let allowed = if algorithms.is_empty() { &DEFAULT_ALGORITHMS } else { &algorithms as &[&str] };
    let mut algos = vec![];
    let mut unencrypted = false;
    for name in allowed {
        let algo = match &name.to_uppercase() as &str {
            "UNENCRYPTED" | "NONE" | "PLAIN" => {
                unencrypted = true;
                continue;
            }
            "AES128" | "AES128_GCM" | "AES_128" | "AES_128_GCM" => &aead::AES_128_GCM,
            "AES256" | "AES256_GCM" | "AES_256" | "AES_256_GCM" => &aead::AES_256_GCM,
            "CHACHA" | "CHACHA20" | "CHACHA20_POLY1305" => &aead::CHACHA20_POLY1305,
            _ => return Err(Error::InvalidConfig("Unknown crypto method")),
        };
        algos.push(algo)
    }
    Ok((unencrypted, algos))
}

///
///
///
pub fn peer_instance<P: Payload>(crypto: &Crypto, node_id: NodeId, payload: P) -> PeerCrypto<P> {
    PeerCrypto::new(node_id, payload, crypto.get_key_pair(), crypto.get_trusted_keys(), crypto.get_algorithms())
}

///
///
///
fn create_dummy_pair(algo: &'static aead::Algorithm) -> (CryptoCore, CryptoCore) {
    let key_data = random_data(algo.key_len());
    let sender = CryptoCore::new(LessSafeKey::new(UnboundKey::new(algo, &key_data).unwrap()), true);
    let receiver = CryptoCore::new(LessSafeKey::new(UnboundKey::new(algo, &key_data).unwrap()), false);
    (sender, receiver)
}

///
///
///
fn test_speed(algo: &'static aead::Algorithm, max_time: &Duration) -> f64 {
    let mut buffer = MsgBuffer::new(EXTRA_LEN);
    buffer.set_length(1000);
    let (mut sender, mut receiver) = create_dummy_pair(algo);
    let mut iterations = 0;
    let start = Instant::now();
    while (Instant::now() - start).as_nanos() < max_time.as_nanos() {
        for _ in 0..1000 {
            sender.encrypt(&mut buffer);
            receiver.decrypt(&mut buffer).unwrap();
        }
        iterations += 1000;
    }
    let duration = (Instant::now() - start).as_secs_f64();
    let data = iterations * 1000 * 2;
    data as f64 / duration / 1_000_000.0
}
