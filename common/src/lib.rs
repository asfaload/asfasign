pub mod fs;

use sha2::{Digest, Sha512, digest::typenum};
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::fs::names::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE, find_global_signers_for};

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
    let mut file = File::open(path_in.as_ref())?;
    let mut hasher = Sha512::new();
    let bytes_copied = std::io::copy(&mut file, &mut hasher)?;
    if bytes_copied == 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ))
    } else {
        let result = hasher.finalize();
        Ok(AsfaloadHashes::Sha512(result))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Artifact,
    Signers,
    InitialSigners,
}

impl Display for FileType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            FileType::Artifact => write!(f, "Artifact"),
            FileType::Signers => write!(f, "Signers"),
            FileType::InitialSigners => write!(f, "InitialSigners"),
        }
    }
}

pub fn determine_file_type<P: AsRef<Path>>(file_path: P) -> FileType {
    let path = file_path.as_ref();
    let global_signers = find_global_signers_for(file_path.as_ref());
    let is_in_signers_dir = path
        .parent()
        .and_then(|dir| dir.file_name())
        .is_some_and(|name| name == SIGNERS_DIR || name == PENDING_SIGNERS_DIR);
    let is_signers_file = path.file_name().is_some_and(|fname| fname == SIGNERS_FILE);

    // Signers file if {SIGNERS_DIR}/{SIGNERSFILE}
    match (is_in_signers_dir, is_signers_file, global_signers) {
        (true, true, Err(_)) => FileType::InitialSigners,
        (true, true, Ok(_)) => FileType::Signers,
        (_, _, _) => FileType::Artifact,
    }
}

#[derive(Clone)]
pub struct SignedFile {
    pub kind: FileType,
    pub path: PathBuf,
}

impl AsRef<Path> for SignedFile {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}
impl SignedFile {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let file_type = determine_file_type(&path);
        Self {
            kind: file_type,
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(test)]
mod asfaload_common_tests {
    use super::*;
    use anyhow::Result;
    use sha2::{Digest, Sha512};
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use tempfile::{NamedTempFile, TempDir};
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

    #[test]
    fn test_determine_file_type() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        //  Regular file (should be Artifact)
        let regular_file = temp_path.join("regular_file.txt");
        fs::write(&regular_file, "content").unwrap();
        assert_eq!(determine_file_type(&regular_file), FileType::Artifact);

        //  File in a regular directory (should be Artifact)
        let regular_dir = temp_path.join("regular_dir");
        fs::create_dir(&regular_dir).unwrap();
        let file_in_regular_dir = regular_dir.join("some_file.json");
        fs::write(&file_in_regular_dir, "content").unwrap();
        assert_eq!(
            determine_file_type(&file_in_regular_dir),
            FileType::Artifact
        );

        //  File in "asfaload.signers.pending" but not named "index.json" (should be Artifact)
        let pending_signers_dir = temp_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir(&pending_signers_dir).unwrap();
        let other_file = pending_signers_dir.join("other_file.json");
        fs::write(&other_file, "content").unwrap();
        assert_eq!(determine_file_type(&other_file), FileType::Artifact);

        //  File named "index.json" but not in "asfaload.signers.pending" (should be Artifact)
        let index_in_regular_dir = regular_dir.join(SIGNERS_FILE);
        fs::write(&index_in_regular_dir, "content").unwrap();
        assert_eq!(
            determine_file_type(&index_in_regular_dir),
            FileType::Artifact
        );

        //  File named "index.json" in "asfaload.signers.pending" (should be Signers)
        let index_file = pending_signers_dir.join(SIGNERS_FILE);
        fs::write(&index_file, "content").unwrap();
        assert_eq!(determine_file_type(&index_file), FileType::InitialSigners);

        //  Nested "asfaload.signers.pending" directory (should still work)
        let nested_dir = temp_path.join("nested").join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&nested_dir).unwrap();
        let nested_index = nested_dir.join(SIGNERS_FILE);
        fs::write(&nested_index, "content").unwrap();
        assert_eq!(determine_file_type(&nested_index), FileType::InitialSigners);

        //  Directory named similarly but not exactly "asfaload.signers.pending" (should be Artifact)
        let similar_dir = temp_path.join(format!("{}.{}", PENDING_SIGNERS_DIR, "backup"));
        fs::create_dir(&similar_dir).unwrap();
        let similar_index = similar_dir.join(SIGNERS_FILE);
        fs::write(&similar_index, "content").unwrap();
        assert_eq!(determine_file_type(&similar_index), FileType::Artifact);

        //  Case sensitivity check (should be Artifact since exact match is required)
        let case_dir = temp_path.join(PENDING_SIGNERS_DIR.to_uppercase());
        fs::create_dir(&case_dir).unwrap();
        let case_index = case_dir.join(SIGNERS_FILE);
        fs::write(&case_index, "content").unwrap();
        assert_eq!(determine_file_type(&case_index), FileType::Artifact);

        //  File named "INDEX.JSON" (uppercase) in "asfaload.signers.pending" (should be Artifact)
        let upper_index = pending_signers_dir.join("INDEX.JSON");
        fs::write(&upper_index, "content").unwrap();
        assert_eq!(determine_file_type(&upper_index), FileType::Artifact);

        // Create a current signers file, and validate that tests that
        // previously returned initial signers now return signers.
        let current_signers_dir = temp_path.join(SIGNERS_DIR);
        fs::create_dir(&current_signers_dir).unwrap();
        let file_in_regular_dir = current_signers_dir.join("index.json");
        fs::write(
            &file_in_regular_dir,
            "dummy signers content ok as only presence is checked",
        )
        .unwrap();

        //  File named "index.json" in "asfaload.signers.pending" (should be Signers)
        let index_file = pending_signers_dir.join(SIGNERS_FILE);
        fs::write(&index_file, "content").unwrap();
        assert_eq!(determine_file_type(&index_file), FileType::Signers);

        //  Nested "asfaload.signers.pending" directory (should still work)
        let nested_dir = temp_path.join("nested").join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&nested_dir).unwrap();
        let nested_index = nested_dir.join(SIGNERS_FILE);
        fs::write(&nested_index, "content").unwrap();
        assert_eq!(determine_file_type(&nested_index), FileType::Signers);
    }
}
