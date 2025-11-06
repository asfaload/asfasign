use std::{
    fmt::{Display, Formatter},
    path::{Path, PathBuf},
};

// FIXME: we could improve this by reusing defined const in future consts,
// but it seems too much of a burden at this time.
// We might want to look at https://crates.io/crates/constcat
pub const PENDING_SUFFIX: &str = "pending";

pub const SIGNATURES_SUFFIX: &str = "signatures.json";
pub const PENDING_SIGNATURES_SUFFIX: &str = "signatures.json.pending";
pub const SIGNERS_SUFFIX: &str = "signers.json";
pub const SIGNERS_DIR: &str = "asfaload.signers";
pub const PENDING_SIGNERS_DIR: &str = "asfaload.signers.pending";
pub const SIGNERS_FILE: &str = "index.json";
pub const PENDING_SIGNERS_FILE: &str = "index.json.pending";
pub const SIGNERS_HISTORY_SUFFIX: &str = "history.json";
pub const SIGNERS_HISTORY_FILE: &str = "asfaload.signers.history.json";

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

/// Find the active signers file by traversing parent directories
pub fn find_global_signers_for(file_path: &Path) -> Result<PathBuf, std::io::Error> {
    // We accept looking for the global signer for a directory.
    let mut current_dir = {
        if file_path.is_dir() {
            Ok(file_path)
        } else {
            file_path.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "File has no parent directory",
                )
            })
        }
    }?;

    // If we work on a signers file, we go up one level, so we do not
    // consider a signers file for itself
    current_dir = if file_path
        .file_name()
        .is_some_and(|name| name == SIGNERS_FILE)
        && file_path
            .parent()
            .is_some_and(|p| p.file_name().unwrap_or_default() == SIGNERS_DIR)
    {
        current_dir
            .parent()
            .and_then(|d| d.parent())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "File has no parent directory",
                )
            })?
    } else {
        current_dir
    };

    loop {
        let candidate = current_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        if candidate.exists() {
            return Ok(candidate);
        }

        // Move up to the parent directory
        current_dir = match current_dir.parent() {
            Some(parent) => parent,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No signers file found in parent directories",
                ));
            }
        };
    }
}

pub fn create_local_signers_for<P: AsRef<Path>>(
    file_path_in: P,
) -> Result<PathBuf, std::io::Error> {
    let file_path = file_path_in.as_ref();

    // Not working on directories
    if file_path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Not creating local signers for a directory.",
        ));
    }

    let local_signers_path = local_signers_path_for(file_path)?;

    // Not overwriting existing files
    if local_signers_path.exists() {
        return Err({
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "Not overwriting existing local signers file at {}",
                    local_signers_path.to_string_lossy()
                ),
            )
        });
    }

    let global_signers = find_global_signers_for(file_path)?;
    std::fs::copy(global_signers, &local_signers_path)?;
    Ok(local_signers_path)
}

fn file_path_with_suffix<P: AsRef<Path>>(path_in: P, suffix: &str) -> std::io::Result<PathBuf> {
    let file_path = path_in.as_ref();
    file_path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Input path has no file name",
        )
    })?;
    let new_path_str = format!("{}.{}", file_path.to_string_lossy(), suffix);
    Ok(std::path::PathBuf::from(new_path_str))
}
// Get the signatures file path for a file path.
// It doesn't check on disk that the path received is effectively a file.
pub fn signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, SIGNATURES_SUFFIX)
}
pub fn pending_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, PENDING_SIGNATURES_SUFFIX)
}

// Return the copy of the signers file taken when initialising the signature
// procedure for the file at path_in.
pub fn local_signers_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, SIGNERS_SUFFIX)
}
// Get the signatures file path for a file on disk. This chekcs on disk if the file
// exists.
pub fn signatures_path_on_disk_for<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
    let file_path = path_in.as_ref();
    // This checks on disk
    if !file_path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Input path is not a file: {}", file_path.to_string_lossy()),
        ));
    }
    file_path_with_suffix(path_in, SIGNATURES_SUFFIX)
}
#[cfg(test)]
mod asfaload_index_tests {

    use std::{fs, str::FromStr};

    use anyhow::Result;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    #[test]
    fn test_signature_path_on_disk_for() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "My data")?;
        let input_path = file.path().to_path_buf();
        let expected_str = format!(
            "{}.{}",
            input_path.clone().into_os_string().to_string_lossy(),
            SIGNATURES_SUFFIX
        );
        let expected_path = PathBuf::from_str(&expected_str)?;
        let signatures_path = signatures_path_on_disk_for(input_path)?;
        assert_eq!(signatures_path, expected_path);

        let input_path = TempDir::new().unwrap().path().to_path_buf();
        let res = signatures_path_on_disk_for(input_path);
        assert!(res.is_err());
        let error = res.err().unwrap();
        assert!(error.to_string().starts_with("Input path is not a file"));

        Ok(())
    }

    #[test]
    fn test_simple_signature_path_for() -> Result<()> {
        let input = Path::new("/my/path/to/file");
        let output = signatures_path_for(input)?;
        assert_eq!(
            output,
            PathBuf::from_str("/my/path/to/file.signatures.json")?
        );

        // FIXME: this should cause an error as it is clearly a path to a directory
        let input = Path::new("/my/path/to/file/");
        let output = signatures_path_for(input)?;
        assert_eq!(
            output,
            PathBuf::from_str("/my/path/to/file/.signatures.json")?
        );

        let input = Path::new("/");
        let result = signatures_path_for(input);
        assert!(result.is_err());
        match result.as_ref().unwrap_err().kind() {
            std::io::ErrorKind::InvalidInput => {}
            err => {
                panic!(
                    "Expected IoError with InvalidInput kind, got something else: {:?}",
                    err
                )
            }
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
