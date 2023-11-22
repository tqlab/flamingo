use super::{core::CryptoCore, init::Algorithms, random_data, EXTRA_LEN};
use crate::{
    config::CryptoConfig,
    error::Error,
    util::{from_base62, MsgBuffer},
};
use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    pbkdf2,
    signature::{Ed25519KeyPair, KeyPair, ED25519_PUBLIC_KEY_LEN},
};
use smallvec::smallvec;
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

const SALT: &[u8; 32] = b"flamingoflamiNGOFlamingoflamingo";

pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_LEN];

const DEFAULT_ALGORITHMS: [&str; 3] = ["AES128", "AES256", "CHACHA20"];

const SPEED_TEST_TIME: f32 = 0.1;

pub struct Crypto {
    key_pair: Arc<Ed25519KeyPair>,
    trusted_keys: Arc<[Ed25519PublicKey]>,
    algorithms: Algorithms,
}

impl Crypto {
    ///
    ///
    ///
    pub fn new(config: &CryptoConfig) -> Result<Self, Error> {
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

    ///
    ///
    ///
    pub fn get_key_pair(&self) -> Arc<Ed25519KeyPair> {
        self.key_pair.clone()
    }

    ///
    ///
    ///
    pub fn get_trusted_keys(&self) -> Arc<[Ed25519PublicKey]> {
        self.trusted_keys.clone()
    }

    ///
    ///
    ///
    pub fn get_algorithms(&self) -> Algorithms {
        self.algorithms.clone()
    }
}

///
///
///
fn parse_algorithms(algos: &[String]) -> Result<(bool, Vec<&'static aead::Algorithm>), Error> {
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
