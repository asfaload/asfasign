use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use normalize_path::NormalizePath;
use rest_api_types::errors::ApiError;

#[derive(Debug, Clone)]
pub struct NormalisedPaths {
    // The directory in which we want to add a file
    base_dir: PathBuf,
    // The absolute path to the file to add under base_dir
    absolute_path: PathBuf,
    // The path to the file relative to the base_dir
    relative_path: PathBuf,
}

impl NormalisedPaths {
    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(
        base_repo_path: P1,
        requested_path: P2,
    ) -> Result<Self, ApiError> {
        let r = build_normalised_absolute_path(base_repo_path, requested_path)?;
        Ok(r)
    }
    pub fn base_dir(&self) -> PathBuf {
        self.base_dir.clone()
    }
    pub fn absolute_path(&self) -> PathBuf {
        self.absolute_path.clone()
    }
    pub fn relative_path(&self) -> PathBuf {
        self.relative_path.clone()
    }
}

/// Build the absolute path for the requested_path relative to the base_repo_path.
/// Note that the base_repo_path must exist.
fn build_normalised_absolute_path<P1: AsRef<Path>, P2: AsRef<Path>>(
    base_repo_path: P1,
    requested_path: P2,
) -> Result<NormalisedPaths, ApiError> {
    // Create and validate the requested path
    // Replace backslashes with forward slashes for cross-platform compatibility
    let requested_path_str = requested_path.as_ref().to_string_lossy().replace('\\', "/");
    let requested_path = PathBuf::from(requested_path_str);

    // If we get an absolute path, make it relative
    let requested_path = if requested_path.is_absolute() {
        requested_path
            .components()
            .filter(|c| !matches!(c, Component::RootDir))
            .collect()
    } else {
        requested_path
    };

    // Reject all path traversal to parent
    for component in requested_path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(ApiError::InvalidFilePath(
                "Path traversal attempt through parent dir".to_string(),
            ));
        }
    }

    // Normalize the requested path to remove any . or .. components
    let normalized_requested = requested_path.normalize();

    // Ensure normalization didn't create an absolute path
    if normalized_requested.is_absolute() {
        return Err(ApiError::InvalidFilePath(
            "Invalid path after normalization".to_string(),
        ));
    }

    // Canonicalize the base repository path
    let canonical_base = fs::canonicalize(base_repo_path).map_err(|e| {
        ApiError::InvalidFilePath(format!("Failed to resolve repository path: {}", e))
    })?;

    // Join and normalize the full path
    let full_path = canonical_base.join(&normalized_requested);
    let normalized_full_path = full_path.normalize();

    // Verify the normalized path starts with the canonical base
    // (We normalize the base too for consistent comparison)
    let normalized_canonical_base = canonical_base.normalize();

    if !normalized_full_path.starts_with(&normalized_canonical_base) {
        return Err(ApiError::InvalidFilePath(
            "Path traversal attempt detected".to_string(),
        ));
    }

    // Now we need to resolve symlinks in the path that actually exist
    // We'll walk the path components, canonicalizing as we go for security checks
    let mut security_check_path = canonical_base.clone();

    for component in normalized_requested.components() {
        security_check_path = security_check_path.join(component);

        // If this component exists, canonicalize it to resolve any symlinks for security check
        if security_check_path.exists() {
            let canonicalized = fs::canonicalize(&security_check_path).map_err(|e| {
                ApiError::InvalidFilePath(format!("Failed to resolve path component: {}", e))
            })?;

            // Verify we're still within the repository after resolving symlinks
            if !canonicalized.starts_with(&canonical_base) {
                return Err(ApiError::InvalidFilePath(
                    "Symlink points outside repository".to_string(),
                ));
            }

            // Update the security check path to the canonicalized version
            security_check_path = canonicalized;
        }
    }

    // Ensure we are still in the base dir
    if !security_check_path.starts_with(&canonical_base) {
        return Err(ApiError::InvalidFilePath(
            "Path traversal attempt detected".to_string(),
        ));
    }

    // Return the normalized requested path (preserving the original path structure)
    Ok(NormalisedPaths {
        base_dir: canonical_base,
        absolute_path: security_check_path,
        relative_path: normalized_requested,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_valid_relative_path() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("valid/path/file.txt"));
        assert!(result.is_ok());
        let NormalisedPaths {
            absolute_path,
            relative_path,
            base_dir: _,
        } = result.unwrap();
        assert_eq!(absolute_path, base_path.join("valid/path/file.txt"));
        assert_eq!(relative_path, Path::new("valid/path/file.txt"));
    }

    #[test]
    fn test_valid_single_file() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("file.txt"));
        assert!(result.is_ok());

        let NormalisedPaths {
            absolute_path,
            relative_path,
            base_dir: _,
        } = result.unwrap();
        assert_eq!(absolute_path, base_path.join("file.txt"));
        assert_eq!(relative_path, Path::new("file.txt"));
    }

    #[test]
    fn test_empty_path() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new(""));
        assert!(result.is_ok());
        let NormalisedPaths {
            absolute_path,
            relative_path,
            base_dir: _,
        } = result.unwrap();
        assert_eq!(absolute_path, base_path);
        assert_eq!(relative_path, Path::new(""));
    }

    #[test]
    fn test_absolute_path_made_relative() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        let absolute_path = Path::new("/etc/passwd").to_string_lossy().to_string();

        let result = build_normalised_absolute_path(base_path, Path::new(&absolute_path));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().absolute_path, base_path.join("etc/passwd"));
    }

    #[test]
    fn test_path_traversal_with_dot_dot_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("../../../etc/passwd"));

        match result {
            Err(ApiError::InvalidFilePath(s)) => {
                assert_eq!(s, "Path traversal attempt through parent dir")
            }
            Err(e) => panic!("Expected InvalidFilePath, got {}", e),
            Ok(_) => panic!("Expected InvalidFilePath, got ok result"),
        }
    }

    #[test]
    fn test_path_traversal_with_current_dir() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("./file.txt"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().absolute_path, base_path.join("file.txt"));
    }

    #[test]
    fn test_path_traversal_with_mixed_components() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result =
            build_normalised_absolute_path(base_path, Path::new("valid/../../../etc/passwd"));
        match result {
            Err(ApiError::InvalidFilePath(s)) => {
                assert_eq!(s, "Path traversal attempt through parent dir")
            }
            Err(e) => panic!("Expected InvalidFilePath, got {}", e),
            Ok(_) => panic!("Expected InvalidFilePath, got ok result"),
        }
    }

    #[test]
    fn test_path_with_backslashes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result =
            build_normalised_absolute_path(base_path, Path::new("folder\\subfolder\\file.txt"));
        assert!(result.is_ok());
        // Note: The exact behavior might depend on the OS but we target Linux-like OSs
        assert_eq!(
            result.unwrap().absolute_path,
            base_path.join("folder/subfolder/file.txt")
        );
    }

    #[test]
    fn test_path_with_special_characters() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result =
            build_normalised_absolute_path(base_path, Path::new("folder with spaces/file (1).txt"));
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().absolute_path,
            base_path.join("folder with spaces/file (1).txt")
        );
    }

    #[test]
    fn test_path_with_unicode_characters() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("文件夹/文件.txt"));
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().absolute_path,
            base_path.join("文件夹/文件.txt")
        );
    }

    #[test]
    fn test_path_with_dot_and_dot_dot_components() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result =
            build_normalised_absolute_path(base_path, Path::new("folder/./subfolder/../file.txt"));
        match result {
            Err(ApiError::InvalidFilePath(s)) => {
                assert_eq!(s, "Path traversal attempt through parent dir")
            }
            Err(e) => panic!("Expected InvalidFilePath, got {}", e),
            Ok(_) => panic!("Expected InvalidFilePath, got ok result"),
        }
    }

    #[test]
    fn test_path_with_many_dot_components() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("./././file.txt"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().absolute_path, base_path.join("file.txt"));
    }

    #[test]
    fn test_path_with_dotdot_components_staying_within_repo() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create some directories
        fs::create_dir_all(base_path.join("a/b/c")).unwrap();

        let result =
            build_normalised_absolute_path(base_path, Path::new("a/b/c/../../../file.txt"));

        match result {
            Err(ApiError::InvalidFilePath(s)) => {
                assert_eq!(s, "Path traversal attempt through parent dir")
            }
            Err(e) => panic!("Expected InvalidFilePath, got {}", e),
            Ok(_) => panic!("Expected InvalidFilePath, got ok result"),
        }
    }

    #[test]
    fn test_symlink_within_repo() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a directory and file
        fs::create_dir_all(base_path.join("target")).unwrap();
        fs::write(base_path.join("target/file.txt"), "content").unwrap();

        // Create a symlink within the repo
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(base_path.join("target"), base_path.join("symlink"))
                .unwrap();

            let result = build_normalised_absolute_path(base_path, Path::new("symlink/file.txt"));
            assert!(result.is_ok());
            assert_eq!(
                result.unwrap().absolute_path,
                base_path.join("target/file.txt")
            );
        }

        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(base_path.join("target"), base_path.join("symlink"))
                .unwrap();

            let result = build_normalised_absolute_path(base_path, "symlink/file.txt");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), base_path.join("target/file.txt"));
        }
    }

    #[test]
    fn test_symlink_pointing_outside_repo() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a directory outside the repo
        let outside_dir = TempDir::new().unwrap();
        fs::write(outside_dir.path().join("file.txt"), "content").unwrap();

        // Create a symlink pointing outside the repo
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside_dir.path(), base_path.join("symlink")).unwrap();

            let result = build_normalised_absolute_path(base_path, Path::new("symlink/file.txt"));
            match result {
                Err(ApiError::InvalidFilePath(s)) => {
                    assert_eq!(s, "Symlink points outside repository")
                }
                Err(e) => panic!("Expected InvalidFilePath, got {}", e),
                Ok(_) => panic!("Expected InvalidFilePath, got ok result"),
            }
        }

        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(outside_dir.path(), base_path.join("symlink"))
                .unwrap();

            let result = build_normalised_absolute_path(base_path, "symlink/file.txt");
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), ApiError::InvalidFilePath(_)));
        }
    }

    #[test]
    fn test_nonexistent_base_path() {
        let nonexistent_path = PathBuf::from("/this/path/does/not/exist");

        let result = build_normalised_absolute_path(&nonexistent_path, Path::new("file.txt"));
        match result {
            Err(ApiError::InvalidFilePath(s)) => {
                assert_eq!(
                    s,
                    "Failed to resolve repository path: No such file or directory (os error 2)"
                )
            }
            Err(e) => panic!("Expected InvalidFilePath, got {}", e),
            Ok(_) => panic!("Expected InvalidFilePath, got ok result"),
        }
    }

    #[test]
    fn test_path_with_null_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, Path::new("folder\0/file.txt"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_path() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let long_component = "a".repeat(255);
        let long_path = format!(
            "{}/{}/{}/{}",
            long_component, long_component, long_component, "file.txt"
        );

        let result = build_normalised_absolute_path(base_path, Path::new(&long_path));
        assert_eq!(
            result.unwrap().absolute_path,
            base_path
                .join(&long_component)
                .join(&long_component)
                .join(&long_component)
                .join("file.txt")
        );
    }

    #[test]
    fn test_path_with_trailing_slash() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, "folder/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().absolute_path, base_path.join("folder"));
    }

    #[test]
    fn test_path_with_multiple_slashes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let result = build_normalised_absolute_path(base_path, "folder//subfolder///file.txt");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().absolute_path,
            base_path.join("folder/subfolder/file.txt")
        );
    }
}
