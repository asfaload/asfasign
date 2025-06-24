pub use minisign::KeyPair;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use crate::keys::{AsfaloadKeyPair, minisign::errs::KeyError};

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
}

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
    keypair: &minisign::KeyPair,
    p: T,
) -> Result<&minisign::KeyPair, errs::KeyError> {
    let path = p.as_ref();
    // Use "key"" as default name
    // Secret key to disk
    let sk_bytes = keypair.sk.to_box(None)?.to_bytes();
    let () = fs::write(path, &sk_bytes)?;

    // Pub key to disk
    let pk_bytes = keypair.pk.to_box()?.to_bytes();
    let pub_path_buf = append_pub_extension(&p);

    let () = fs::write(pub_path_buf.as_path(), &pk_bytes)?;

    Ok(keypair)
}
impl<'a> AsfaloadKeyPair<'a> for minisign::KeyPair {
    type KeyErr = errs::KeyError;
    fn new(password: &str) -> Result<Self, errs::KeyError> {
        let kp = KeyPair::generate_encrypted_keypair(Some(password.to_string()))?;
        Ok(kp)
    }
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&KeyPair, errs::KeyError> {
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
}

#[cfg(test)]
mod asfaload_index_tests {

    use std::fs::File;

    use anyhow::{Context, Result};

    use super::*;

    #[test]
    fn test_new() -> Result<()> {
        // Assign keypair then save it on disk, passing a file name
        let kp: minisign::KeyPair = AsfaloadKeyPair::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("mykey");
        let kpr = kp.save(&temp_file_path)?;
        assert!(temp_dir.path().join("mykey").exists());
        assert!(temp_dir.path().join("mykey.pub").exists());
        assert_eq!(kp.pk, kpr.pk);
        assert_eq!(kp.sk, kpr.sk);

        // Assign keypair then save it on disk, passing a dir
        let kp: minisign::KeyPair = AsfaloadKeyPair::new("mypass")?;
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path();
        let kpr = kp.save(temp_file_path)?;
        assert!(temp_dir.path().join("key").exists());
        assert!(temp_dir.path().join("key.pub").exists());
        assert_eq!(kp.pk, kpr.pk);
        assert_eq!(kp.sk, kpr.sk);

        // Not overwriting
        // ---------------
        fn panic_if_writing_file(save_result: Result<&KeyPair, KeyError>) {
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
        let kp = minisign::KeyPair::new("mypass")?;
        let save_result = kp.save(&temp_dir);
        panic_if_writing_file(save_result);
        fs::remove_file(existing_default_path)?;

        // Default name "key.pub"
        let existing_default_path = temp_dir.path().join("key.pub");
        File::create(&existing_default_path)?;
        let kp = minisign::KeyPair::new("mypass")?;
        let save_result = kp.save(&temp_dir);
        panic_if_writing_file(save_result);
        fs::remove_file(existing_default_path)?;

        // Custom file name, priv exists
        let temp_file_path = temp_dir.path().join("mykey");
        File::create(&temp_file_path)?;
        let kp = minisign::KeyPair::new("mypass")?;
        let save_result = kp.save(&temp_file_path);
        panic_if_writing_file(save_result);
        fs::remove_file(&temp_file_path)?;

        // Custom file name, pub exists
        let pub_temp_file_path = temp_dir.path().join("mykey.pub");
        File::create(&pub_temp_file_path)?;
        let kp = minisign::KeyPair::new("mypass")?;
        let save_result = kp.save(&temp_file_path);
        panic_if_writing_file(save_result);
        fs::remove_file(pub_temp_file_path)?;

        // Call new and save on the same line
        let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
        let temp_file_path = temp_dir.path().join("key");
        let _kp = minisign::KeyPair::new("mypass")?.save(temp_file_path)?;

        Ok(())
    }

    #[test]
    fn test_prevent_overwrite() {}
}
