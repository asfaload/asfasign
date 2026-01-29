use std::path::{Path, PathBuf};

use constants::{
    PENDING_SIGNATURES_SUFFIX, PENDING_SIGNERS_DIR, REVOCATION_SUFFIX, REVOKED_SUFFIX,
    SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_SUFFIX,
};

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

pub fn pending_signers_file_in_dir<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let path = path_in.as_ref();
    if !path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Looking for pending signers file in dir only works with a directory",
        ));
    }
    let p = path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
    if p.exists() && p.is_file() {
        Ok(p)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Pending signers file not found or is directory",
        ))
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
pub fn subject_path_from_pending_signatures<P: AsRef<Path>>(
    path_in: P,
) -> std::io::Result<PathBuf> {
    let suffix = format!(".{}", PENDING_SIGNATURES_SUFFIX);
    let path_str = path_in.as_ref().to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid path: cannot convert to string",
        )
    })?;
    let subject_str = path_str.trim_end_matches(&suffix);
    Ok(PathBuf::from(subject_str))
}
// Return the copy of the signers file taken when initialising the signature
// procedure for the file at path_in.
pub fn local_signers_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, SIGNERS_SUFFIX)
}

pub fn revocation_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    file_path_with_suffix(path_in, REVOCATION_SUFFIX)
}

pub fn revocation_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = revocation_path_for(path_in)?;
    file_path_with_suffix(rev_path, SIGNATURES_SUFFIX)
}

pub fn revocation_signers_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = revocation_path_for(path_in)?;
    file_path_with_suffix(rev_path, SIGNERS_SUFFIX)
}

pub fn revoked_signatures_path_for<P: AsRef<Path>>(path_in: P) -> std::io::Result<PathBuf> {
    let rev_path = signatures_path_for(path_in)?;
    file_path_with_suffix(rev_path, REVOKED_SUFFIX)
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
    // test pending_signers_file_in_dir
    // --------------------------------
    #[test]
    fn test_pending_signers_file_in_dir_success() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file = pending_dir.join(SIGNERS_FILE);
        fs::write(&pending_file, "{}")?;

        let result = pending_signers_file_in_dir(dir_path)?;

        let expected_path = pending_dir.join(SIGNERS_FILE);
        assert_eq!(result, expected_path);

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_path_is_a_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("not_a_dir.txt");
        fs::write(&file_path, "content")?;

        let result = pending_signers_file_in_dir(&file_path);

        // Should return an error
        match result.unwrap_err().kind() {
            std::io::ErrorKind::InvalidInput => {}
            k => panic!("Expected InvalidInput error, got {}", k),
        }

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_missing_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        // We don't create the PENDING_SIGNERS_FILE

        // Call the function
        let result = pending_signers_file_in_dir(dir_path);

        // Should return an error
        assert!(result.is_err());
        match result.unwrap_err().kind() {
            std::io::ErrorKind::NotFound => {}
            _ => panic!("Expected NotFound error"),
        }

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_file_is_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create the directory structure but make the pending file a directory
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file = pending_dir.join(SIGNERS_FILE);
        fs::create_dir(&pending_file)?; // Create as directory instead of file

        // Call the function
        let result = pending_signers_file_in_dir(dir_path);

        // Should return an error
        assert!(result.is_err());
        match result.unwrap_err().kind() {
            std::io::ErrorKind::NotFound => {} // It should report as not found since it's not a file
            _ => panic!("Expected NotFound error"),
        }

        Ok(())
    }

    #[test]
    fn test_pending_signers_file_in_dir_nested_path() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        fs::create_dir_all(&nested_dir)?;

        // Create the expected directory structure in the nested directory
        let pending_dir = nested_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file = pending_dir.join(SIGNERS_FILE);
        fs::write(&pending_file, "{}")?;

        // Call the function with the nested directory
        let result = pending_signers_file_in_dir(&nested_dir)?;

        // Verify the result
        let expected_path = pending_dir.join(SIGNERS_FILE);
        assert_eq!(result, expected_path);

        Ok(())
    }

    // test subject_path_from_pending_signatures
    // ----------------------------------------
    #[test]
    fn test_subject_path_from_pending_signatures_basic_path() -> Result<()> {
        let input = PathBuf::from_str("/my/path/to/file.signatures.json.pending")?;
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::from_str("/my/path/to/file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_pending_signatures_simple_filename() -> Result<()> {
        let input = PathBuf::from_str("file.signatures.json.pending")?;
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::from_str("file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_pending_signatures_without_suffix() -> Result<()> {
        let input = PathBuf::from_str("/my/path/to/file")?;
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::from_str("/my/path/to/file")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_subject_path_from_pending_signatures_empty_path() -> Result<()> {
        let input = PathBuf::new();
        let result = subject_path_from_pending_signatures(&input)?;
        let expected = PathBuf::new();
        assert_eq!(result, expected);
        Ok(())
    }
}
