use crate::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKey, AsfaloadPublicKeyTrait,
    AsfaloadSecretKey, AsfaloadSecretKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
    KeyFormat,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use common::{AsfaloadHashes, errors::keys::*};
pub use minisign::{KeyPair, PublicKey, SecretKey, SignatureBox};
use std::{fs, io::Cursor, path::Path, str::FromStr};

impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPair<minisign::KeyPair> {
    type PublicKey = AsfaloadPublicKey<minisign::PublicKey>;
    type SecretKey = AsfaloadSecretKey<minisign::SecretKey>;
    fn new(password: &str) -> Result<Self, KeyError> {
        let kp = KeyPair::generate_encrypted_keypair(Some(password.to_string()))?;
        Ok(AsfaloadKeyPair { key_pair: kp })
    }
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&AsfaloadKeyPair<minisign::KeyPair>, KeyError> {
        let (sk_path, pk_path) = super::resolve_save_paths(&p)?;

        let sk_string = self.key_pair.sk.to_box(None)?.into_string();
        fs::write(&sk_path, &sk_string)?;

        let pk_string = self.public_key().to_base64();
        fs::write(&pk_path, &pk_string)?;

        Ok(self)
    }
    fn public_key(&self) -> Self::PublicKey {
        AsfaloadPublicKey {
            key: self.key_pair.pk.clone(),
        }
    }
    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError> {
        let r = AsfaloadSecretKey {
            key: self
                .key_pair
                .sk
                .to_box(None)?
                .into_secret_key(Some(password.into()))?
                .clone(),
        };
        Ok(r)
    }
}

impl AsfaloadSecretKeyTrait for AsfaloadSecretKey<minisign::SecretKey> {
    type SecretKey = minisign::SecretKey;
    type Signature = AsfaloadSignature<minisign::SignatureBox>;

    fn sign(&self, data: &AsfaloadHashes) -> Result<Self::Signature, SignError> {
        let data_reader = match data {
            AsfaloadHashes::Sha512(data) => Cursor::new(data),
        };
        // Intermediate assignment for error conversion
        // https://doc.rust-lang.org/rust-by-example/std/result/question_mark.html
        let sig = minisign::sign(None, &self.key, data_reader, None, None)?;
        Ok(AsfaloadSignature { signature: sig })
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let k = minisign::SecretKey::from_bytes(data)?;
        Ok(AsfaloadSecretKey { key: k })
    }

    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        let k = minisign::SecretKeyBox::from_string(std::fs::read_to_string(path)?.as_str())?
            .into_secret_key(Some(password.into()))?;
        Ok(AsfaloadSecretKey { key: k })
    }
}

impl AsfaloadPublicKeyTrait for AsfaloadPublicKey<minisign::PublicKey> {
    type Signature = AsfaloadSignature<minisign::SignatureBox>;
    type KeyType = minisign::PublicKey;
    type SecretKeyType = AsfaloadSecretKey<minisign::SecretKey>;

    fn verify(
        &self,
        signature: &Self::Signature,
        data: &AsfaloadHashes,
    ) -> Result<(), VerifyError> {
        let data_reader = match data {
            AsfaloadHashes::Sha512(data) => Cursor::new(data),
        };
        minisign::verify(
            &self.key,
            &signature.signature,
            data_reader,
            true,
            false,
            false,
        )?;
        Ok(())
    }

    fn to_base64(&self) -> String {
        format!("{}:{}", KeyFormat::Minisign, self.key.to_base64())
    }

    // FIXME: what about the prefix here?
    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let k = minisign::PublicKey::from_bytes(data)?;
        Ok(AsfaloadPublicKey { key: k })
    }
    // When saving to a file, we store a PublicKeyBox as encouraged by minisign for storage.
    // Other methods manipulate the PublickKey directly
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let content = std::fs::read_to_string(&path)?;
        Self::from_base64(&content)
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        let bare = match s.split_once(':') {
            Some((prefix, rest)) => {
                if prefix != KeyFormat::Minisign.to_string() {
                    return Err(KeyError::CreationFailed(format!(
                        "Public key format prefix mismatch: expected {}, got {}",
                        KeyFormat::Minisign,
                        prefix
                    )));
                }
                rest
            }
            None => s,
        };
        let k = minisign::PublicKey::from_base64(bare)?;
        Ok(AsfaloadPublicKey { key: k })
    }

    fn from_secret_key(sk: &Self::SecretKeyType) -> Result<Self, KeyError> {
        let k = PublicKey::from_secret_key(&sk.key)?;
        Ok(AsfaloadPublicKey { key: k })
    }
    fn key_format(&self) -> KeyFormat {
        KeyFormat::Minisign
    }

    fn key(&self) -> minisign::PublicKey {
        self.key.clone()
    }
}

impl AsfaloadSignatureTrait for AsfaloadSignature<minisign::SignatureBox> {
    type PublicKeyType = AsfaloadPublicKey<minisign::PublicKey>;
    fn to_string(&self) -> String {
        self.signature.to_string()
    }

    fn from_string(data: &str) -> Result<Self, SignatureError> {
        let s = minisign::SignatureBox::from_string(data)?;
        Ok(AsfaloadSignature { signature: s })
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError> {
        // We save the signature field of the struct to a file as string
        let sig_string = self.signature.to_string();
        std::fs::write(path, sig_string)?;
        Ok(self)
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError> {
        // We read the signature from a string in the file, and build our struct
        let s = minisign::SignatureBox::from_file(path)?;
        Ok(AsfaloadSignature { signature: s })
    }
    fn from_base64(s: &str) -> Result<Self, SignatureError> {
        let s = BASE64_STANDARD.decode(s)?;
        Self::from_string(std::str::from_utf8(&s)?)
    }

    fn to_base64(&self) -> String {
        let s = self.signature.to_string();
        BASE64_STANDARD.encode(s)
    }
}

use std::hash::{Hash, Hasher};

impl PartialEq for AsfaloadPublicKey<minisign::PublicKey> {
    fn eq(&self, other: &Self) -> bool {
        self.key.to_base64() == other.key.to_base64()
    }
}

impl Eq for AsfaloadPublicKey<minisign::PublicKey> {}

impl Hash for AsfaloadPublicKey<minisign::PublicKey> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.to_base64().hash(state);
    }
}
#[cfg(test)]
mod asfaload_index_tests {

    use std::{fs::File, path::PathBuf};

    use anyhow::{Context, Result};
    use constants::PENDING_SIGNATURES_SUFFIX;
    use serde_json;
    use tempfile::TempDir;

    use super::*;
    use crate::keys::append_pub_extension;
    //------------------------------------------------------------
    // Keypairs
    //------------------------------------------------------------
    // Helper to initialise a new key pair and get its keys
    fn get_key_pair() -> Result<(
        AsfaloadPublicKey<minisign::PublicKey>,
        AsfaloadSecretKey<minisign::SecretKey>,
    )> {
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        Ok((kp.public_key(), kp.secret_key("mypass")?))
    }

    // FIXME: this function is duplicated. It can currently not be added to
    // test_helpers because test_helper depends on the crate signatures, and the crate
    // signature needs this function but depending on test_helpers would create a
    // cyclic dependency.
    // Will rework test helper later.
    pub fn create_file_to_sign(dir: PathBuf) -> Result<PathBuf, std::io::Error> {
        let to_signed_file_name = "my_signed_file";
        let to_signed_file_path = dir.as_path().join(to_signed_file_name);
        std::fs::write(&to_signed_file_path, "data").map(|_| to_signed_file_path)
    }
    #[test]
    fn test_new() -> Result<()> {
        // Assign keypair then save it on disk, passing a dir
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path();
        let kpr = kp.save(temp_file_path)?;
        assert!(temp_dir.path().join("key").exists());
        assert!(temp_dir.path().join("key.pub").exists());
        // Load keys from just created files
        let sk = AsfaloadSecretKey::<minisign::SecretKey>::from_file(
            temp_dir.path().join("key"),
            "mypass",
        )?;
        let pk =
            AsfaloadPublicKey::<minisign::PublicKey>::from_file(temp_dir.path().join("key.pub"))?;
        // The secret key returned in the key pair is encrypted and unusable as such.
        // To decrypted, put it in the box and reopen the box.
        // See https://github.com/jedisct1/rust-minisign/issues/3
        let sk_box = kp.key_pair.sk.to_box(None)?;
        let decrypted_sk = sk_box.into_secret_key(Some("mypass".into()))?;
        assert_eq!(sk.key, decrypted_sk);
        assert_eq!(pk.key, kpr.key_pair.pk);
        // Check we can sign and verify with these keys
        let data = common::sha512_for_content(b"lorem ipsum".to_vec())?;
        let sig = sk.sign(&data)?;
        pk.verify(&sig, &data)?;

        // Assign keypair then save it on disk, passing a file name
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("mykey");
        let _kpr = kp.save(&temp_file_path)?;
        assert!(temp_dir.path().join("mykey").exists());
        assert!(temp_dir.path().join("mykey.pub").exists());

        // Saving keys does not overwrite existing files
        // ---------------------------------------------
        fn panic_if_writing_file(
            save_result: Result<&AsfaloadKeyPair<minisign::KeyPair>, KeyError>,
        ) {
            match save_result {
                Ok(_) => panic!("should not overwrite existing file!"),
                Err(e) => match e {
                    KeyError::NotOverwriting(_) => (),
                    _ => panic!("should not overwrite files!"),
                },
            }
        }
        let temp_dir = tempfile::tempdir().unwrap();
        // Default name "key"
        let existing_default_path = temp_dir.path().join("key");
        File::create(&existing_default_path)?;
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let save_result = kp.save(&temp_dir);
        panic_if_writing_file(save_result);
        fs::remove_file(existing_default_path)?;

        // Default name "key.pub"
        let existing_default_path = temp_dir.path().join("key.pub");
        File::create(&existing_default_path)?;
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let save_result = kp.save(&temp_dir);
        panic_if_writing_file(save_result);
        fs::remove_file(existing_default_path)?;

        // Custom file name, priv exists
        let temp_file_path = temp_dir.path().join("mykey");
        File::create(&temp_file_path)?;
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let save_result = kp.save(&temp_file_path);
        panic_if_writing_file(save_result);
        fs::remove_file(&temp_file_path)?;

        // Custom file name, pub exists
        let pub_temp_file_path = temp_dir.path().join("mykey.pub");
        File::create(&pub_temp_file_path)?;
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let save_result = kp.save(&temp_file_path);
        panic_if_writing_file(save_result);
        fs::remove_file(pub_temp_file_path)?;

        // Call new and save on the same line
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("key");
        let _kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?.save(temp_file_path)?;

        Ok(())
    }

    #[test]
    fn test_append_pub_extension() {
        let p = Path::new("/home/asfa/key");
        let buf_with_ext = append_pub_extension(&p).unwrap();
        let with_ext = buf_with_ext.as_path();
        assert_eq!(with_ext.to_str(), Some("/home/asfa/key.pub"));

        // Illustration that the trailing / is dropped. See append_pub_extension comment.
        let p = Path::new("/home/asfa/key/");
        let buf_with_ext = append_pub_extension(&p).unwrap();
        let with_ext = buf_with_ext.as_path();
        assert_eq!(with_ext.to_str(), Some("/home/asfa/key.pub"));
    }
    //------------------------------------------------------------
    // AsfaloadSecretKey
    //------------------------------------------------------------
    #[test]
    fn test_keys_methods() -> Result<()> {
        // Save keypair in temp dir
        let temp_dir = tempfile::tempdir().unwrap();
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        kp.save(&temp_dir)?;

        // Load secret key from disk
        let secret_key_path = temp_dir.as_ref().to_path_buf().join("key");
        let secret_key =
            AsfaloadSecretKey::<minisign::SecretKey>::from_file(secret_key_path, "mypass")?;

        // Generate signature
        let bytes_to_sign = common::sha512_for_content(b"My string to sign".to_vec())?;
        let signature = secret_key.sign(&bytes_to_sign)?;

        // Load public key from disk
        let public_key_path = temp_dir.as_ref().to_path_buf().join("key.pub");
        let public_key = AsfaloadPublicKey::<minisign::PublicKey>::from_file(&public_key_path)?;

        // Verify signature
        public_key.verify(&signature, &bytes_to_sign)?;

        // Load key from base64 and validate
        let value_read = fs::read_to_string(&public_key_path)?;
        // When we saved the key to disk using the Box, it wrote a comment
        // followed by the base64 encoded key. Thus here we only need the second line.
        let public_key_string = value_read.lines().nth(1).ok_or_else(|| {
            KeyError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Public key file does not contain a second line",
            ))
        })?;
        let public_key_from_string =
            AsfaloadPublicKey::<minisign::PublicKey>::from_base64(public_key_string)?;
        public_key_from_string.verify(&signature, &bytes_to_sign)?;

        // Test AsfaloadPublicKey::from_base64
        let b64 = public_key_from_string.to_base64();
        assert_eq!(
            b64,
            format!("{}:{}", KeyFormat::Minisign, public_key_string)
        );

        Ok(())
    }
    #[test]
    fn test_from_base64_with_prefix() -> Result<()> {
        let (pk, _sk) = get_key_pair()?;
        let bare_b64 = pk.key().to_base64();
        let prefixed = format!("minisign:{}", bare_b64);
        let pk2 = AsfaloadPublicKey::<minisign::PublicKey>::from_base64(&prefixed)?;
        assert_eq!(pk.to_base64(), pk2.to_base64());
        Ok(())
    }

    #[test]
    fn test_from_base64_with_wrong_prefix_fails() -> Result<()> {
        let (pk, _sk) = get_key_pair()?;
        let bare_b64 = pk.key().to_base64();
        let prefixed = format!("ed25519:{}", bare_b64);
        let result = AsfaloadPublicKey::<minisign::PublicKey>::from_base64(&prefixed);
        match result {
            Err(KeyError::CreationFailed(_)) => Ok(()),
            Err(e) => panic!("Expected KeyError::CreationFailed, got {}", e),
            Ok(_) => panic!("Expected KeyError::CreationFailed, got Ok"),
        }
    }
    #[test]
    fn test_signature_from_string_formats() -> Result<()> {
        let (pk, sk) = get_key_pair()?;
        let data = common::sha512_for_content(b"lorem ipsum".to_vec())?;
        let sig = sk.sign(&data)?;

        // String serialisation
        let sig_str = sig.to_string();
        let sig_from_str =
            AsfaloadSignature::<minisign::SignatureBox>::from_string(sig_str.as_str())?;
        pk.verify(&sig_from_str, &data)?;

        // Base64 serialisation
        let sig_b64 = sig.to_base64();
        let sig_from_b64 = AsfaloadSignature::<minisign::SignatureBox>::from_base64(&sig_b64)?;
        pk.verify(&sig_from_b64, &data)?;

        // Saving signature to file
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.as_ref();
        let sig_path = root_dir.join("signature");
        sig.to_file(&sig_path)?;

        // Reading signature from file
        let sig_from_file = AsfaloadSignature::<minisign::SignatureBox>::from_file(sig_path)?;
        pk.verify(&sig_from_file, &data)?;

        Ok(())
    }
    #[test]
    fn test_add_to_aggregate() -> Result<()> {
        // Create a temporary directory
        let temp_dir = tempfile::tempdir()?;
        let dir_path = temp_dir.path();
        let signed_file_path = create_file_to_sign(dir_path.to_path_buf())?;
        std::fs::write(&signed_file_path, "test data")?;

        // Generate a keypair and create a signature
        let keypair = AsfaloadKeyPair::<minisign::KeyPair>::new("password")?;
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password")?;

        let keypair2 = AsfaloadKeyPair::<minisign::KeyPair>::new("password")?;
        let pubkey2 = keypair2.public_key();
        let seckey2 = keypair2.secret_key("password")?;

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let wrong_data = common::sha512_for_content(b"wrong data".to_vec())?;
        let signature = seckey.sign(&data)?;
        let signature2 = seckey2.sign(&data)?;
        let wrong_signature = seckey.sign(&wrong_data)?;

        // Signing a directory causes an error
        let result = signature.add_to_aggregate_for_file(dir_path, &pubkey);
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignatureError::IoError(io_err) => {
                let err: &std::io::Error = io_err; // Explicit type annotation
                if err.kind() != std::io::ErrorKind::IsADirectory {
                    panic!(
                        "Expected IoError with IsADirectory kind, got something else: {:?}",
                        err
                    )
                }
            }
            _ => panic!(
                "Expected SignatureError, got something else: {:?}",
                result.unwrap_err()
            ),
        }

        // Attempting to add the signature of another data than the signed file's hash to the aggregate should fail.
        let result = wrong_signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
        match result {
            Err(SignatureError::InvalidSignatureForAggregate(_)) => {
                // Expected
            }
            Ok(_) => panic!("Expected an error, but got Ok"),
            _ => panic!(
                "Expected InvalidsignatureForAggregate, got something else: {:?}",
                result.unwrap_err()
            ),
        }

        // Add the signature to the aggregate
        signature.add_to_aggregate_for_file(&signed_file_path, &pubkey)?;

        // Verify that the signature file was created
        let sig_file_path = signed_file_path.with_file_name(format!(
            "{}.{}",
            signed_file_path.to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(
            sig_file_path.exists(),
            "Pending signature file should exist"
        );

        // Verify the content of the signatures file
        let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
        let sig_file: crate::signatures_file::SignaturesFile =
            serde_json::from_str(&sig_file_content)?;
        let pubkey_b64 = pubkey.to_base64();
        let pubkey2_b64 = pubkey2.to_base64();
        assert!(
            sig_file.entries.contains_key(&pubkey_b64),
            "Signatures file should contain an entry for the public key"
        );
        assert!(
            !sig_file.entries.contains_key(&pubkey2_b64),
            "Signatures file should NOT contain an entry for the second public key"
        );
        assert_eq!(
            sig_file.entries.get(&pubkey_b64).unwrap().signature,
            signature.to_base64(),
            "Signatures file should contain the correct signature"
        );

        // Add second signature to aggregate
        signature2.add_to_aggregate_for_file(&signed_file_path, &pubkey2)?;

        // Re-read the signatures file as it should have been modified
        let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
        let sig_file: crate::signatures_file::SignaturesFile =
            serde_json::from_str(&sig_file_content)?;
        // First signature is still there
        assert!(
            sig_file.entries.contains_key(&pubkey_b64),
            "Signatures file should contain an entry for the public key"
        );
        assert_eq!(
            sig_file.entries.get(&pubkey_b64).unwrap().signature,
            signature.to_base64(),
            "Signatures file should contain the correct signature"
        );
        // Second signature is added
        assert!(
            sig_file.entries.contains_key(&pubkey2_b64),
            "Signatures file should contain an entry for the second public key"
        );
        assert_eq!(
            sig_file.entries.get(&pubkey2_b64).unwrap().signature,
            signature2.to_base64(),
            "Signatures file should contain the correct second signature"
        );

        // Adding a duplicate signature (same key) should fail
        let result = signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
        match result {
            Err(SignatureError::DuplicateSignature) => {
                // Expected
            }
            Ok(_) => panic!("Expected DuplicateSignature error, but got Ok"),
            Err(e) => panic!("Expected DuplicateSignature error, got: {:?}", e),
        }
        Ok(())
    }
    #[test]
    fn test_signature_trait_error_mapping() -> Result<()> {
        // Check underlying IO errors are mapped correctly to our IO error.
        let r = AsfaloadSignature::<minisign::SignatureBox>::from_file("/tmp/inexisting_path");
        assert!(matches!(r, Err(SignatureError::IoError(_))));

        let r = AsfaloadSignature::<minisign::SignatureBox>::from_base64("invalid");
        assert!(matches!(r, Err(SignatureError::Base64DecodeFailed(_))));

        // This seems to be reported as IO error by minisign
        let r = AsfaloadSignature::<minisign::SignatureBox>::from_string("invalid");
        assert!(matches!(r, Err(SignatureError::IoError(_))));
        Ok(())
    }

    #[test]
    fn test_public_key_from_secret_key() -> Result<()> {
        let kp = AsfaloadKeyPair::<minisign::KeyPair>::new("mypass")?;
        let pubkey = kp.public_key();
        let seckey = kp.secret_key("mypass")?;

        let derived_pubkey = AsfaloadPublicKey::<minisign::PublicKey>::from_secret_key(&seckey)?;
        assert_eq!(derived_pubkey.to_base64(), pubkey.to_base64());
        Ok(())
    }
}
