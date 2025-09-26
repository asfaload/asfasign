pub mod fs;

use sha2::{Digest, Sha512, digest::typenum};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub enum AsfaloadHashes {
    Sha512(sha2::digest::generic_array::GenericArray<u8, typenum::consts::U64>),
}
pub fn sha512_for_content(content: Vec<u8>) -> Result<AsfaloadHashes, std::io::Error> {
    if content.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ))
    } else {
        Ok(AsfaloadHashes::Sha512(Sha512::digest(content)))
    }
}

pub fn sha512_for_file<P: AsRef<Path>>(path_in: P) -> Result<AsfaloadHashes, std::io::Error> {
    let file = File::open(path_in.as_ref())?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; 8192];
    let mut total_bytes_read = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of file
        }

        total_bytes_read += bytes_read;
        hasher.update(&buffer[..bytes_read]);
    }

    if total_bytes_read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ));
    }
    let result = hasher.finalize();
    Ok(AsfaloadHashes::Sha512(result))
}

#[cfg(test)]
mod asfaload_common_tests {
    use super::*;
    use anyhow::Result;
    use sha2::{Digest, Sha512};
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;
    //
    // Helper to convert byte array to hex string
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_sha512_for_content() -> Result<()> {
        // Test with empty content
        let empty_content = Vec::new();
        let hash = sha512_for_content(empty_content);
        match hash {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {} //expected
            _ => panic!("Computing sha of empty value should be an error"),
        }

        // Test with known content
        let content = b"hello world";
        let hash = sha512_for_content(content.to_vec())?;
        let expected = Sha512::digest(content);
        match hash {
            AsfaloadHashes::Sha512(h) => assert_eq!(h, expected),
        }
        Ok(())
    }

    #[test]
    fn test_sha512_for_nonexistent_file() {
        let result = sha512_for_file(Path::new("nonexistent_file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sha512_for_file() -> Result<(), Box<dyn std::error::Error>> {
        // Test without looking at the sha computed
        let temp_file = NamedTempFile::new()?;
        let content = b"hello world";
        std::fs::write(temp_file.path(), content)?;

        // Compute hash for the file
        let hash = sha512_for_file(temp_file.path())?;
        let expected = Sha512::digest(content);
        match hash {
            AsfaloadHashes::Sha512(h) => assert_eq!(h, expected),
        }

        // Test by validating we always get the exepcted sha value.
        // The fist test might pass but compute the value ortherwise and still pass
        // (eg if it first appends "\n" to the content).
        // Here we validate it still works for previously computed shas.
        let mut temp_file = NamedTempFile::new()?;
        let content = b"hello world";
        temp_file.write_all(content)?;
        temp_file.flush()?;

        let hash = sha512_for_file(temp_file.path())?;
        match hash {
            AsfaloadHashes::Sha512(arr) => {
                let expected = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
                assert_eq!(to_hex(arr.as_slice()), expected);
            }
        }

        // An empty file causes an error
        let temp_file = NamedTempFile::new()?;
        let hash = sha512_for_file(temp_file.path());
        match hash {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {} //expected
            _ => panic!("Computing sha of empty value should be an error"),
        }

        Ok(())
    }
}
