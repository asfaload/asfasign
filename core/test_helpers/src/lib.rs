pub mod history_helpers;
pub mod scenarios;
pub mod signers_setup;

use signatures::keys::AsfaloadSecretKeyTrait;
pub use signers_setup::*;

use signatures::keys::AsfaloadKeyPairTrait;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::keys::KeyFormat;
use signatures::keys::asfaload::format::Argon2Params;
use signatures::types::AsfaloadKeyPairs;
use signatures::types::AsfaloadPublicKeys;
use signatures::types::AsfaloadSecretKeys;
use signers_file_types::Forge;
use signers_file_types::ForgeOrigin;
use signers_file_types::SignersConfigMetadata;
use signers_file_types::VerifiedForgeContent;
use std::path::PathBuf;
use tempfile::TempDir;

/// Number of pre-generated fixture keypairs available.
const FIXTURE_KEY_COUNT: usize = 10;

/// Password used for all fixture keypairs.
const FIXTURE_PASSWORD: &str = "password";

/// Low-cost argon2id for fast test key generation. NOT for production.
/// Keep in sync with Argon2Params::TEST in signatures/src/keys/asfaload/format.rs.
const TEST_ARGON2_PARAMS: Argon2Params = Argon2Params::TEST;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}
pub fn fixtures_keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}
pub fn fixtures_pub_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("key_{}.pub", n))
}
pub fn fixtures_asfaload_pub_key(n: usize) -> PathBuf {
    fixtures_keys_dir().join(format!("key_{}.pub", n))
}

/// Load a key pair from fixture files.
pub fn get_key_pair() -> anyhow::Result<(AsfaloadPublicKeys, AsfaloadSecretKeys)> {
    let dir = fixtures_keys_dir();
    let pk = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    Ok((pk, sk))
}
/// Load two key pairs from fixture files.
pub fn get_two_key_pairs() -> anyhow::Result<(
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
)> {
    let dir = fixtures_keys_dir();
    let pk1 = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk1 = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    let pk2 = AsfaloadPublicKeys::from_file(dir.join("key_1.pub"))?;
    let sk2 = AsfaloadSecretKeys::from_file(dir.join("key_1"), "password")?;
    Ok((pk1, sk1, pk2, sk2))
}

/// Generate a fresh asfaload key pair (fast TEST params) and save to temp dir.
/// Returns (public key, secret key) via the enum facade.
pub fn get_asfaload_key_pair() -> anyhow::Result<(TempDir, AsfaloadPublicKeys, AsfaloadSecretKeys)>
{
    let temp_dir = tempfile::tempdir()?;
    let kp = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp.save(temp_dir.path())?;
    let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "password")?;
    Ok((temp_dir, pk, sk))
}

/// Generate two fresh asfaload key pairs (fast TEST params).
pub fn get_two_asfaload_key_pairs() -> anyhow::Result<(
    TempDir,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
)> {
    let temp_dir = tempfile::tempdir()?;
    let kp1 = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password1",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp1.save(temp_dir.path().join("key1"))?;
    let kp2 = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password2",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp2.save(temp_dir.path().join("key2"))?;
    let pk1 = AsfaloadPublicKeys::from_file(temp_dir.path().join("key1.pub"))?;
    let sk1 = AsfaloadSecretKeys::from_file(temp_dir.path().join("key1"), "password1")?;
    let pk2 = AsfaloadPublicKeys::from_file(temp_dir.path().join("key2.pub"))?;
    let sk2 = AsfaloadSecretKeys::from_file(temp_dir.path().join("key2"), "password2")?;
    Ok((temp_dir, pk1, sk1, pk2, sk2))
}
/// Select key algorithm from the KEY_TYPE env var, matching the e2e test convention.
/// Panics on unrecognised values to surface typos early.
pub fn default_key_type() -> KeyFormat {
    match std::env::var("KEY_TYPE").as_deref() {
        Ok("asfaload") => KeyFormat::Asfaload,
        Err(_) => KeyFormat::Asfaload,
        Ok(other) => panic!("Unknown KEY_TYPE: {other} (expected: asfaload)"),
    }
}

pub struct TestKeys {
    key_pairs: Vec<AsfaloadKeyPairs>,
    pub_keys: Vec<AsfaloadPublicKeys>,
    sec_keys: Vec<AsfaloadSecretKeys>,
}

impl TestKeys {
    /// Load pre-generated keys based on KEY_TYPE env var.
    /// default is asfaload, KEY_TYPE=asfaload loads asfaload fixtures
    pub fn new(n: usize) -> Self {
        Self::new_from(0, n)
    }

    /// Load pre-generated keys based on KEY_TYPE env var, starting at `start`.
    pub fn new_from(start: usize, n: usize) -> Self {
        match default_key_type() {
            KeyFormat::Asfaload => Self::new_asfaload_from(start, n),
            KeyFormat::OpenSsh => {
                panic!("TestKeys does not support OpenSsh; use asfaload")
            }
        }
    }

    /// Generate fresh keypairs at runtime using KEY_TYPE env var to select format.
    pub fn new_generated(n: usize) -> Self {
        Self::new_generated_with_format(n, &default_key_type())
    }

    /// Generate fresh keypairs at runtime with a specific algorithm format.
    pub fn new_generated_with_format(n: usize, format: &KeyFormat) -> Self {
        let mut r = TestKeys {
            key_pairs: Vec::with_capacity(n),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for _ in 0..n {
            let key_pair = AsfaloadKeyPairs::new_with_format_and_argon2_params(
                FIXTURE_PASSWORD,
                format,
                TEST_ARGON2_PARAMS,
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

    /// Load pre-generated asfaload keys from fixture files starting at index 0.
    pub fn new_asfaload(n: usize) -> Self {
        Self::new_asfaload_from(0, n)
    }

    /// Load pre-generated asfaload keys from fixture files starting at `start`.
    pub fn new_asfaload_from(start: usize, n: usize) -> Self {
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
            let pk = AsfaloadPublicKeys::from_file(fixtures_dir.join(format!("key_{i}.pub")))
                .unwrap_or_else(|e| {
                    panic!("Failed to load fixture asfaload public key key_{i}.pub: {e}")
                });
            let sk = AsfaloadSecretKeys::from_file_for_format(
                fixtures_dir.join(format!("key_{i}")),
                FIXTURE_PASSWORD,
                &KeyFormat::Asfaload,
            )
            .unwrap_or_else(|e| panic!("Failed to load fixture asfaload secret key key_{i}: {e}"));
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
        VerifiedForgeContent::new_for_test(
            "https://raw.example.com/test/signers.json".to_string(),
            "test_hash_placeholder".to_string(),
        ),
        chrono::Utc::now(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use signatures::keys::AsfaloadSecretKeyTrait;

    /// Generate fixture keypairs and save them to fixtures/keys/.
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
            "Done: generated {FIXTURE_KEY_COUNT} keypairs in {}",
            fixtures_dir.display()
        );
    }

    /// Generate asfaload fixture keypairs and save them to fixtures/keys/.
    /// Run with: cargo test --package test_helpers -- gen_fixture_asfaload_keys --ignored --nocapture
    #[test]
    #[ignore]
    fn gen_fixture_asfaload_keys() {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("keys");
        std::fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures/keys dir");

        for i in 0..FIXTURE_KEY_COUNT {
            let kp = AsfaloadKeyPairs::new_with_format_and_argon2_params(
                FIXTURE_PASSWORD,
                &KeyFormat::Asfaload,
                TEST_ARGON2_PARAMS,
            )
            .expect("Failed to generate asfaload keypair");
            let key_path = fixtures_dir.join(format!("key_{i}"));
            // Remove existing files to allow regeneration
            let _ = std::fs::remove_file(&key_path);
            let _ = std::fs::remove_file(key_path.with_extension("pub"));
            kp.save(&key_path)
                .unwrap_or_else(|e| panic!("Failed to save asfaload keypair {i}: {e}"));
            println!("Generated key_{i}");
        }
        println!(
            "Done: generated {FIXTURE_KEY_COUNT} asfaload keypairs in {}",
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
    fn test_load_asfaload_fixture_keys() {
        let keys = TestKeys::new_asfaload(5);
        for i in 0..5 {
            assert!(
                keys.pub_key(i).is_some(),
                "asfaload pub_key({i}) should exist"
            );
            assert!(
                keys.sec_key(i).is_some(),
                "asfaload sec_key({i}) should exist"
            );
        }
        assert!(keys.key_pair(0).is_none());
    }

    #[test]
    fn test_asfaload_fixture_keys_can_sign_and_verify() {
        let keys = TestKeys::new_asfaload(2);
        let data = common::sha512_for_content(b"test data".to_vec()).unwrap();
        let sig = keys.sec_key(0).unwrap().sign(&data).unwrap();
        keys.pub_key(0).unwrap().verify(&sig, &data).unwrap();
    }
}
