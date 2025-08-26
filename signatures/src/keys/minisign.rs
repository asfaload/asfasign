use base64::{Engine, prelude::BASE64_STANDARD};
pub use minisign::KeyPair;
use std::{
    ffi::OsString,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use crate::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKey, AsfaloadPublicKeyTrait,
    AsfaloadSecretKey, AsfaloadSecretKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
};

pub mod errs {
    use thiserror::Error;
    #[derive(Error, Debug)]
    pub enum KeyError {
        #[error("Key creation failed")]
        CreationFailed(#[from] minisign::PError),
        #[error("Keypair fs io error")]
        IOError(#[from] std::io::Error),
        #[error("Refusing to overwrite existing files")]
        NotOverwriting(String),
    }
    #[derive(Error, Debug)]
    pub enum SignError {
        #[error("Signature failed")]
        SignatureFailed(#[from] minisign::PError),
    }
    #[derive(Error, Debug)]
    pub enum VerifyError {
        #[error("Verification failed")]
        VerificationFailed(#[from] minisign::PError),
    }

    #[derive(Error, Debug)]
    pub enum SignatureError {
        #[error("Signature verification failed")]
        VerificationFailed(#[from] minisign::PError),
        #[error("base64 decoding of signature failed")]
        Base64DecodeFailed(#[from] base64::DecodeError),
        #[error("Invalid Utf8 string")]
        Utf8DecodeFailed(#[from] std::str::Utf8Error),
    }
}

// Beware, if the path ends with /, it is dropped before appending .pub.
// See https://www.reddit.com/r/rust/comments/ooh5wn/damn_trailing_slash/
fn append_pub_extension<T: AsRef<Path>>(p: &T) -> PathBuf {
    let path = p.as_ref();
    let file_name = path
        // returns an option as path might not include file name
        .file_name()
        // this function always gets a file name
        .unwrap();
    // Append .pub extension
    let mut osstring: OsString = file_name.to_os_string();
    osstring.push(".pub");
    let pub_os_str = osstring.as_os_str();
    let mut pub_path_buf = path.to_path_buf();
    pub_path_buf.set_file_name(pub_os_str);
    pub_path_buf
}
fn save_to_file_path<T: AsRef<Path>>(
    keypair: &AsfaloadKeyPair<minisign::KeyPair>,
    p: T,
) -> Result<&AsfaloadKeyPair<minisign::KeyPair>, errs::KeyError> {
    let path = p.as_ref();
    // Use "key"" as default name
    // Secret key to disk
    let sk_string = keypair.key_pair.sk.to_box(None)?.into_string();
    let () = fs::write(path, &sk_string)?;

    // Pub key to disk
    let pk_string = keypair.key_pair.pk.to_box()?.into_string();
    let pub_path_buf = append_pub_extension(&p);
    let () = fs::write(pub_path_buf.as_path(), &pk_string)?;

    Ok(keypair)
}
impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPair<minisign::KeyPair> {
    type PublicKey = AsfaloadPublicKey<minisign::PublicKey>;
    type SecretKey = AsfaloadSecretKey<minisign::SecretKey>;
    type KeyErr = errs::KeyError;
    fn new(password: &str) -> Result<Self, errs::KeyError> {
        let kp = KeyPair::generate_encrypted_keypair(Some(password.to_string()))?;
        Ok(AsfaloadKeyPair { key_pair: kp })
    }
    fn save<T: AsRef<Path>>(
        &self,
        p: T,
    ) -> Result<&AsfaloadKeyPair<minisign::KeyPair>, errs::KeyError> {
        let path = p.as_ref();
        // If this is a path to an existing dir
        if path.is_dir() {
            // Need assignments to avoid E0716
            let path_buf = path.to_path_buf();
            let key_path_buf = path_buf.join("key");
            let file_path = key_path_buf.as_path();
            // Do not go further if we would overwrite a file (either for secret key of pub key)
            if file_path.exists() || (append_pub_extension(&file_path).as_path().exists()) {
                Err(errs::KeyError::NotOverwriting(
                    "Refusing to write key to default name \"key\" in directory!".to_string(),
                ))
            } else {
                save_to_file_path(self, file_path)
            }
        // Do not go further if we would overwrite a file (either for secret key of pub key)
        } else if path.exists() || (append_pub_extension(&path).exists()) {
            Err(errs::KeyError::NotOverwriting(
                "Refusing to write key to existing file!".to_string(),
            ))
        // In this case we got a path to a file to be created
        } else {
            save_to_file_path(self, path)
        }
    }
    fn public_key(&self) -> Self::PublicKey {
        AsfaloadPublicKey {
            key: self.key_pair.pk.clone(),
        }
    }
    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, Self::KeyErr> {
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
    type SignError = errs::SignError;
    type KeyError = errs::KeyError;

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, errs::SignError> {
        let data_reader = Cursor::new(data);
        // Intermediate assignment for error conversion
        // https://doc.rust-lang.org/rust-by-example/std/result/question_mark.html
        let sig = minisign::sign(None, &self.key, data_reader, None, None)?;
        Ok(AsfaloadSignature { signature: sig })
    }

    fn from_bytes(data: &[u8]) -> Result<Self, errs::KeyError> {
        let k = minisign::SecretKey::from_bytes(data)?;
        Ok(AsfaloadSecretKey { key: k })
    }

    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, errs::KeyError> {
        let k = minisign::SecretKeyBox::from_string(std::fs::read_to_string(path)?.as_str())?
            .into_secret_key(Some(password.into()))?;
        Ok(AsfaloadSecretKey { key: k })
    }
}

impl AsfaloadPublicKeyTrait for AsfaloadPublicKey<minisign::PublicKey> {
    type Signature = AsfaloadSignature<minisign::SignatureBox>;
    type VerifyError = errs::VerifyError;
    type KeyError = errs::KeyError;

    fn verify(&self, signature: &Self::Signature, data: &[u8]) -> Result<(), errs::VerifyError> {
        let data_reader = Cursor::new(data);
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
        self.key.to_base64()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, Self::KeyError> {
        let k = minisign::PublicKey::from_bytes(data)?;
        Ok(AsfaloadPublicKey { key: k })
    }
    // When saving to a file, we store a PublicKeyBox as encouraged by minisign for storage.
    // Other methods manipulate the PublickKey directly
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Self::KeyError> {
        let k = minisign::PublicKeyBox::from_string(std::fs::read_to_string(path)?.as_str())?
            .into_public_key()?;
        Ok(AsfaloadPublicKey { key: k })
    }

    fn from_base64(s: String) -> Result<Self, Self::KeyError> {
        let k = minisign::PublicKey::from_base64(s.as_str())?;
        Ok(AsfaloadPublicKey { key: k })
    }
}

impl AsfaloadSignatureTrait for AsfaloadSignature<minisign::SignatureBox> {
    type SignatureError = errs::SignatureError;

    fn to_string(&self) -> String {
        self.signature.to_string()
    }

    fn from_string(
        data: &str,
    ) -> Result<AsfaloadSignature<minisign::SignatureBox>, errs::SignatureError> {
        let s = minisign::SignatureBox::from_string(data)?;
        Ok(AsfaloadSignature { signature: s })
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, errs::SignatureError> {
        let s = minisign::SignatureBox::from_file(path)?;
        Ok(AsfaloadSignature { signature: s })
    }
    fn from_base64(s: &str) -> Result<Self, Self::SignatureError>
    where
        Self: Sized,
    {
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

    use std::fs::File;

    use anyhow::{Context, Result};

    use super::*;
    //------------------------------------------------------------
    // Keypairs
    //------------------------------------------------------------
    // Helper to initialise a new key pair and get its keys
    fn get_key_pair() -> Result<(
        AsfaloadPublicKey<minisign::PublicKey>,
        AsfaloadSecretKey<minisign::SecretKey>,
    )> {
        let kp = AsfaloadKeyPair::new("mypass")?;
        Ok((kp.public_key(), kp.secret_key("mypass")?))
    }
    #[test]
    fn test_new() -> Result<()> {
        // Assign keypair then save it on disk, passing a dir
        let kp = AsfaloadKeyPair::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path();
        let kpr = kp.save(temp_file_path)?;
        assert!(temp_dir.path().join("key").exists());
        assert!(temp_dir.path().join("key.pub").exists());
        // Load keys from just created files
        let sk = AsfaloadSecretKey::from_file(temp_dir.path().join("key"), "mypass")?;
        let pk = AsfaloadPublicKey::from_file(temp_dir.path().join("key.pub"))?;
        // The secret key returned in the key pair is encrypted and unusable as such.
        // To decrypted, put it in the box and reopen the box.
        // See https://github.com/jedisct1/rust-minisign/issues/3
        let sk_box = kp.key_pair.sk.to_box(None)?;
        let decrypted_sk = sk_box.into_secret_key(Some("mypass".into()))?;
        assert_eq!(sk.key, decrypted_sk);
        assert_eq!(pk.key, kpr.key_pair.pk);
        // Check we can sign and verify with these keys
        let data = b"lorem ipsum";
        let sig = sk.sign(data)?;
        pk.verify(&sig, data)?;

        // Assign keypair then save it on disk, passing a file name
        let kp = AsfaloadKeyPair::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("mykey");
        let _kpr = kp.save(&temp_file_path)?;
        assert!(temp_dir.path().join("mykey").exists());
        assert!(temp_dir.path().join("mykey.pub").exists());

        // Saving keys does not overwrite existing files
        // ---------------------------------------------
        fn panic_if_writing_file(
            save_result: Result<&AsfaloadKeyPair<minisign::KeyPair>, errs::KeyError>,
        ) {
            match save_result {
                Ok(_) => panic!("should not overwrite existing file!"),
                Err(e) => match e {
                    errs::KeyError::NotOverwriting(_) => (),
                    _ => panic!("should not overwrite files!"),
                },
            }
        }
        let temp_dir = tempfile::tempdir().unwrap();
        // Default name "key"
        let existing_default_path = temp_dir.path().join("key");
        File::create(&existing_default_path)?;
        let kp = AsfaloadKeyPair::new("mypass")?;
        let save_result = kp.save(&temp_dir);
        panic_if_writing_file(save_result);
        fs::remove_file(existing_default_path)?;

        // Default name "key.pub"
        let existing_default_path = temp_dir.path().join("key.pub");
        File::create(&existing_default_path)?;
        let kp = AsfaloadKeyPair::new("mypass")?;
        let save_result = kp.save(&temp_dir);
        panic_if_writing_file(save_result);
        fs::remove_file(existing_default_path)?;

        // Custom file name, priv exists
        let temp_file_path = temp_dir.path().join("mykey");
        File::create(&temp_file_path)?;
        let kp = AsfaloadKeyPair::new("mypass")?;
        let save_result = kp.save(&temp_file_path);
        panic_if_writing_file(save_result);
        fs::remove_file(&temp_file_path)?;

        // Custom file name, pub exists
        let pub_temp_file_path = temp_dir.path().join("mykey.pub");
        File::create(&pub_temp_file_path)?;
        let kp = AsfaloadKeyPair::new("mypass")?;
        let save_result = kp.save(&temp_file_path);
        panic_if_writing_file(save_result);
        fs::remove_file(pub_temp_file_path)?;

        // Call new and save on the same line
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("key");
        let _kp = AsfaloadKeyPair::new("mypass")?.save(temp_file_path)?;

        Ok(())
    }

    #[test]
    fn test_append_pub_extension() {
        let p = Path::new("/home/asfa/key");
        let buf_with_ext = append_pub_extension(&p);
        let with_ext = buf_with_ext.as_path();
        assert_eq!(with_ext.to_str(), Some("/home/asfa/key.pub"));

        // Illustration that the trailing / is dropped. See append_pub_extension comment.
        let p = Path::new("/home/asfa/key/");
        let buf_with_ext = append_pub_extension(&p);
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
        let kp = AsfaloadKeyPair::new("mypass")?;
        kp.save(&temp_dir)?;

        // Load secret key from disk
        let secret_key_path = temp_dir.as_ref().to_path_buf().join("key");
        let secret_key = AsfaloadSecretKey::from_file(secret_key_path, "mypass")?;

        // Generate signature
        let bytes_to_sign = &"My string to sign".to_string().into_bytes();
        let signature = secret_key.sign(bytes_to_sign)?;

        // Load public key from disk
        let public_key_path = temp_dir.as_ref().to_path_buf().join("key.pub");
        let public_key = AsfaloadPublicKey::from_file(&public_key_path)?;

        // Verify signature
        public_key.verify(&signature, bytes_to_sign)?;

        // Load key from base64 and validate
        let value_read = fs::read_to_string(&public_key_path)?;
        // When we saved the key to disk using the Box, it wrote a comment
        // followed by the base64 encoded key. Thus here we only need the second line.
        let public_key_string = value_read.lines().nth(1).ok_or_else(|| {
            errs::KeyError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Public key file does not contain a second line",
            ))
        })?;
        let public_key_from_string = AsfaloadPublicKey::from_base64(public_key_string.to_string())?;
        public_key_from_string.verify(&signature, bytes_to_sign)?;

        // Test AsfaloadPublicKey::from_base64
        let b64 = public_key_from_string.to_base64();
        assert_eq!(b64, public_key_string);

        Ok(())
    }
    #[test]
    fn test_signature_from_string_formats() -> Result<()> {
        let (pk, sk) = get_key_pair()?;
        let data = b"lorem ipsum";
        let sig = sk.sign(data)?;

        // String serialisation
        let sig_str = sig.to_string();
        let sig_from_str = AsfaloadSignature::from_string(sig_str.as_str())?;
        pk.verify(&sig_from_str, data)?;

        // Base64 serialisation
        let sig_b64 = sig.to_base64();
        let sig_from_b64 = AsfaloadSignature::from_base64(&sig_b64)?;
        pk.verify(&sig_from_b64, data)?;

        Ok(())
    }
}
