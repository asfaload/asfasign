pub mod scenarios;
use signatures::keys::AsfaloadKeyPairTrait;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::keys::AsfaloadSecretKeyTrait;
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

pub struct TestKeys {
    key_pairs: Vec<AsfaloadKeyPairs>,
    pub_keys: Vec<AsfaloadPublicKeys>,
    sec_keys: Vec<AsfaloadSecretKeys>,
}

impl TestKeys {
    /// Load pre-generated keys from fixture files starting at index 0.
    /// Much faster than generating. Panics if n > 10.
    pub fn new(n: usize) -> Self {
        Self::new_from(0, n)
    }

    /// Load pre-generated keys from fixture files starting at `start`.
    /// Use this when you need multiple independent key sets in the same test
    /// (e.g., `TestKeys::new(2)` for existing and `TestKeys::new_from(2, 2)` for new).
    /// Panics if start + n > 10.
    pub fn new_from(start: usize, n: usize) -> Self {
        assert!(
            start + n <= FIXTURE_KEY_COUNT,
            "Only {FIXTURE_KEY_COUNT} fixture keypairs available, requested indices {start}..{}",
            start + n
        );
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("keys");

        let mut r = TestKeys {
            key_pairs: Vec::new(),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for i in start..start + n {
            let pk = AsfaloadPublicKeys::from_file(fixtures_dir.join(format!("key_{i}.pub")))
                .unwrap_or_else(|e| panic!("Failed to load fixture public key key_{i}.pub: {e}"));
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

    /// Generate fresh keypairs at runtime. Use only when the full
    /// AsfaloadKeyPairs is needed (e.g., for .save() or .key_pair()).
    pub fn new_generated(n: usize) -> Self {
        let mut r = TestKeys {
            key_pairs: Vec::with_capacity(n),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for _ in 0..n {
            let key_pair = AsfaloadKeyPairs::new(FIXTURE_PASSWORD).unwrap();
            let pub_key = key_pair.public_key();
            let sec_key = key_pair.secret_key(FIXTURE_PASSWORD).unwrap();
            r.key_pairs.push(key_pair);
            r.sec_keys.push(sec_key);
            r.pub_keys.push(pub_key);
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
        self.pub_keys.iter().enumerate().fold(tpl, |t, (i, k)| {
            t.replace(
                format!("PUBKEY{}_PLACEHOLDER", i).as_str(),
                k.to_base64().as_str(),
            )
        })
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
}
