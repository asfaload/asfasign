pub mod scenarios;
pub mod signers_setup;

pub use signers_setup::*;

use signatures::keys::AsfaloadKeyPairTrait;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::keys::AsfaloadSecretKeyTrait;
use signatures::keys::KeyFormat;
use signatures::types::AsfaloadKeyPairs;
use signatures::types::AsfaloadPublicKeys;
use signatures::types::AsfaloadSecretKeys;
use signers_file_types::Forge;
use signers_file_types::ForgeOrigin;
use signers_file_types::SignersConfigMetadata;
use std::path::PathBuf;

/// Number of pre-generated fixture keypairs available.
const FIXTURE_KEY_COUNT: usize = 10;

/// Password used for all fixture keypairs.
const FIXTURE_PASSWORD: &str = "password";

/// Low-cost scrypt for fast test key generation. NOT for production.
/// Keep in sync with TEST_SCRYPT_LOG_N in signatures/src/keys/ed25519.rs.
const TEST_SCRYPT_LOG_N: u8 = 10;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}
pub fn fixtures_keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}
pub fn fixtures_pub_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("key_{}.pub", n))
}
pub fn fixtures_ed25519_pub_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("ed25519_key_{}.pub", n))
}

/// Select key algorithm from the KEY_TYPE env var, matching the e2e test convention.
/// Defaults to Minisign so existing tests are unaffected.
/// Panics on unrecognised values to surface typos early.
pub fn default_key_type() -> KeyFormat {
    match std::env::var("KEY_TYPE").as_deref() {
        Ok("ed25519") => KeyFormat::Ed25519,
        Ok("minisign") | Err(_) => KeyFormat::Minisign,
        Ok(other) => panic!("Unknown KEY_TYPE: {other} (expected: minisign or ed25519)"),
    }
}

pub struct TestKeys {
    key_pairs: Vec<AsfaloadKeyPairs>,
    pub_keys: Vec<AsfaloadPublicKeys>,
    sec_keys: Vec<AsfaloadSecretKeys>,
}

impl TestKeys {
    /// Load pre-generated keys based on KEY_TYPE env var.
    /// KEY_TYPE=ed25519 loads ed25519 fixtures, default loads minisign.
    pub fn new(n: usize) -> Self {
        Self::new_from(0, n)
    }

    /// Load pre-generated keys based on KEY_TYPE env var, starting at `start`.
    pub fn new_from(start: usize, n: usize) -> Self {
        match default_key_type() {
            KeyFormat::Ed25519 => Self::new_ed25519_from(start, n),
            KeyFormat::Minisign => Self::new_minisign_from(start, n),
        }
    }

    /// Load pre-generated minisign keys from fixture files starting at index 0.
    /// Much faster than generating. Panics if n > 10.
    pub fn new_minisign(n: usize) -> Self {
        Self::new_minisign_from(0, n)
    }

    /// Load pre-generated minisign keys from fixture files starting at `start`.
    /// Use this when you need multiple independent key sets in the same test
    /// (e.g., `TestKeys::new_minisign(2)` for existing and `TestKeys::new_minisign_from(2, 2)` for new).
    /// Panics if start + n > 10.
    pub fn new_minisign_from(start: usize, n: usize) -> Self {
        assert!(
            start + n <= FIXTURE_KEY_COUNT,
            "Only {FIXTURE_KEY_COUNT} fixture keypairs available, requested indices {start}..{}",
            start + n
        );
        let fixtures_dir = fixtures_keys_dir();

        let mut r = TestKeys {
            key_pairs: Vec::new(),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for i in start..start + n {
            let key_path = fixtures_dir.join(format!("key_{i}.pub"));
            let pk = AsfaloadPublicKeys::from_file(&key_path).unwrap_or_else(|e| {
                panic!(
                    "Failed to load fixture public key {}: {e}",
                    key_path.display()
                )
            });
            let sk = AsfaloadSecretKeys::from_file(
                fixtures_dir.join(format!("key_{i}")),
                FIXTURE_PASSWORD,
            )
            .unwrap_or_else(|e| panic!("Failed to load fixture secret key key_{i}: {e}"));
            r.pub_keys.push(pk);
            r.sec_keys.push(sk);
        }

        r
    }

    /// Generate fresh keypairs at runtime using KEY_TYPE env var to select format.
    pub fn new_generated(n: usize) -> Self {
        Self::new_generated_with_format(n, &default_key_type())
    }

    /// Generate fresh minisign keypairs at runtime. Use only when the full
    /// AsfaloadKeyPairs is needed (e.g., for .save() or .key_pair()).
    pub fn new_generated_minisign(n: usize) -> Self {
        Self::new_generated_with_format(n, &KeyFormat::Minisign)
    }

    /// Generate fresh keypairs at runtime with a specific algorithm format.
    pub fn new_generated_with_format(n: usize, format: &KeyFormat) -> Self {
        let mut r = TestKeys {
            key_pairs: Vec::with_capacity(n),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for _ in 0..n {
            let key_pair = AsfaloadKeyPairs::new_with_format_and_scrypt_log_n(
                FIXTURE_PASSWORD,
                format,
                TEST_SCRYPT_LOG_N,
            )
            .unwrap();
            let pub_key = key_pair.public_key();
            let sec_key = key_pair.secret_key(FIXTURE_PASSWORD).unwrap();
            r.key_pairs.push(key_pair);
            r.sec_keys.push(sec_key);
            r.pub_keys.push(pub_key);
        }

        r
    }

    /// Load pre-generated ed25519 keys from fixture files starting at index 0.
    pub fn new_ed25519(n: usize) -> Self {
        Self::new_ed25519_from(0, n)
    }

    /// Load pre-generated ed25519 keys from fixture files starting at `start`.
    pub fn new_ed25519_from(start: usize, n: usize) -> Self {
        assert!(
            start + n <= FIXTURE_KEY_COUNT,
            "Only {FIXTURE_KEY_COUNT} fixture keypairs available, requested indices {start}..{}",
            start + n
        );
        let fixtures_dir = fixtures_keys_dir();

        let mut r = TestKeys {
            key_pairs: Vec::new(),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for i in start..start + n {
            let pk =
                AsfaloadPublicKeys::from_file(fixtures_dir.join(format!("ed25519_key_{i}.pub")))
                    .unwrap_or_else(|e| {
                        panic!("Failed to load fixture ed25519 public key ed25519_key_{i}.pub: {e}")
                    });
            let sk = AsfaloadSecretKeys::from_file(
                fixtures_dir.join(format!("ed25519_key_{i}")),
                FIXTURE_PASSWORD,
            )
            .unwrap_or_else(|e| {
                panic!("Failed to load fixture ed25519 secret key ed25519_key_{i}: {e}")
            });
            r.pub_keys.push(pk);
            r.sec_keys.push(sk);
        }

        r
    }

    pub fn pub_key(&self, n: usize) -> Option<&AsfaloadPublicKeys> {
        self.pub_keys.get(n)
    }
    pub fn sec_key(&self, n: usize) -> Option<&AsfaloadSecretKeys> {
        self.sec_keys.get(n)
    }
    pub fn key_pair(&self, n: usize) -> Option<&AsfaloadKeyPairs> {
        self.key_pairs.get(n)
    }

    pub fn substitute_keys(&self, tpl: String) -> String {
        let result = self.pub_keys.iter().enumerate().fold(tpl, |t, (i, k)| {
            // Insert bare base64 (with "format:" prefix)
            let prefixed = k.to_base64();
            t.replace(format!("PUBKEY{}_PLACEHOLDER", i).as_str(), &prefixed)
        });
        // Replace FORMAT_PLACEHOLDER with the serialized key format string.
        // All keys in a TestKeys instance share the same format.
        if let Some(first_key) = self.pub_keys.first() {
            let format_str = first_key.key_format().to_string();
            result.replace("FORMAT_PLACEHOLDER", &format_str)
        } else {
            result
        }
    }
}

pub fn pause() {
    let mut s = "".to_string();
    println!("Pausing test, press enter when done");
    let _ = std::io::stdin().read_line(&mut s);
}

pub fn test_metadata() -> SignersConfigMetadata {
    SignersConfigMetadata::from_forge(ForgeOrigin::new(
        Forge::Github,
        "https://example.com/test".to_string(),
        chrono::Utc::now(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate minisign fixture keypairs and save them to fixtures/keys/.
    /// Run with: cargo test --package test_helpers -- gen_fixture_keys --ignored --nocapture
    #[test]
    #[ignore]
    fn gen_fixture_keys() {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("keys");
        std::fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures/keys dir");

        for i in 0..FIXTURE_KEY_COUNT {
            let kp = AsfaloadKeyPairs::new(FIXTURE_PASSWORD).expect("Failed to generate keypair");
            let key_path = fixtures_dir.join(format!("key_{i}"));
            kp.save(&key_path)
                .unwrap_or_else(|e| panic!("Failed to save keypair {i}: {e}"));
            println!("Generated key_{i}");
        }
        println!(
            "Done: generated {FIXTURE_KEY_COUNT} minisign keypairs in {}",
            fixtures_dir.display()
        );
    }

    /// Generate ed25519 fixture keypairs and save them to fixtures/keys/.
    /// Run with: cargo test --package test_helpers -- gen_fixture_ed25519_keys --ignored --nocapture
    #[test]
    #[ignore]
    fn gen_fixture_ed25519_keys() {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("keys");
        std::fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures/keys dir");

        for i in 0..FIXTURE_KEY_COUNT {
            let kp = AsfaloadKeyPairs::new_with_format_and_scrypt_log_n(
                FIXTURE_PASSWORD,
                &KeyFormat::Ed25519,
                TEST_SCRYPT_LOG_N,
            )
            .expect("Failed to generate ed25519 keypair");
            let key_path = fixtures_dir.join(format!("ed25519_key_{i}"));
            // Remove existing files to allow regeneration
            let _ = std::fs::remove_file(&key_path);
            let _ = std::fs::remove_file(key_path.with_extension("pub"));
            kp.save(&key_path)
                .unwrap_or_else(|e| panic!("Failed to save ed25519 keypair {i}: {e}"));
            println!("Generated ed25519_key_{i}");
        }
        println!(
            "Done: generated {FIXTURE_KEY_COUNT} ed25519 keypairs in {}",
            fixtures_dir.display()
        );
    }

    #[test]
    fn test_load_fixture_keys() {
        let keys = TestKeys::new(5);
        for i in 0..5 {
            assert!(keys.pub_key(i).is_some(), "pub_key({i}) should exist");
            assert!(keys.sec_key(i).is_some(), "sec_key({i}) should exist");
        }
        // Fixture-loaded keys don't have key_pairs
        assert!(keys.key_pair(0).is_none());
    }

    #[test]
    fn test_fixture_keys_can_sign_and_verify() {
        let keys = TestKeys::new(2);
        let data = common::sha512_for_content(b"test data".to_vec()).unwrap();
        let sig = keys.sec_key(0).unwrap().sign(&data).unwrap();
        keys.pub_key(0).unwrap().verify(&sig, &data).unwrap();
    }

    #[test]
    fn test_load_ed25519_fixture_keys() {
        let keys = TestKeys::new_ed25519(5);
        for i in 0..5 {
            assert!(
                keys.pub_key(i).is_some(),
                "ed25519 pub_key({i}) should exist"
            );
            assert!(
                keys.sec_key(i).is_some(),
                "ed25519 sec_key({i}) should exist"
            );
        }
        assert!(keys.key_pair(0).is_none());
    }

    #[test]
    fn test_ed25519_fixture_keys_can_sign_and_verify() {
        let keys = TestKeys::new_ed25519(2);
        let data = common::sha512_for_content(b"test data".to_vec()).unwrap();
        let sig = keys.sec_key(0).unwrap().sign(&data).unwrap();
        keys.pub_key(0).unwrap().verify(&sig, &data).unwrap();
    }
}
