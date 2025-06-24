use std::{ffi::OsStr, fs, path::Path};

pub use minisign::KeyPair;

use crate::keys::AsfaloadKeyPair;

pub mod errs {
    use thiserror::Error;
    #[derive(Error, Debug)]
    pub enum KeyError {
        #[error("Key creation failed")]
        CreationFailed(#[from] minisign::PError),
        #[error("Keypair fs io error")]
        IOError(#[from] std::io::Error),
    }
}

impl<'a> AsfaloadKeyPair<'a> for minisign::KeyPair {
    type KeyErr = errs::KeyError;
    fn new(password: &str) -> Result<Self, errs::KeyError> {
        let kp = KeyPair::generate_encrypted_keypair(Some(password.to_string()))?;
        Ok(kp)
    }

    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&KeyPair, errs::KeyError> {
        let path = p.as_ref();
        let file_name = path
            // returns an option as path might not include file name
            .file_name()
            // convert to str to use if in format! below
            // if the filename cannot be converted to str, default to "key"
            .map(|s| s.to_str().unwrap_or("key"))
            // If there was no file name in the path, default to "key"
            .unwrap_or("key");
        // Secret key to disk
        let sk_bytes = self.sk.to_box(None)?.to_bytes();
        let () = fs::write(path, &sk_bytes)?;

        // Pub key to disk
        let pk_bytes = self.pk.to_box()?.to_bytes();
        // Appen .pub extension
        let mut base_path_buf = path.to_path_buf();
        base_path_buf.set_file_name(OsStr::new(format!("{file_name}.pub").as_str()));
        let () = fs::write(base_path_buf.as_path(), &pk_bytes)?;

        Ok(self)
    }
}

#[cfg(test)]
mod asfaload_index_tests {

    use anyhow::{Context, Result};

    use super::*;

    #[test]
    fn test_new() -> Result<()> {
        // Assign keypair then save it on disk
        let kp: minisign::KeyPair = AsfaloadKeyPair::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("key");
        let kpr = kp.save(&temp_file_path)?;
        assert!(temp_dir.path().join("key").exists());
        assert!(temp_dir.path().join("key.pub").exists());
        assert_eq!(kp.pk, kpr.pk);
        assert_eq!(kp.sk, kpr.sk);

        // Call new and save on the same line
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("key");
        let _kp = minisign::KeyPair::new("mypass")?.save(temp_file_path)?;

        Ok(())
    }
}
