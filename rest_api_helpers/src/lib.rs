//! Shared helpers for REST API URL validation and path handling.

use url::Url;

/// Represents a validated common base path shared by a set of URLs.
pub struct CommonBasePath {
    pub host: String,
    pub parent_path: String,
}

/// Errors that can occur during URL validation.
#[derive(Debug, thiserror::Error)]
pub enum UrlValidationError {
    #[error("At least one URL must be provided")]
    EmptyUrls,
    #[error("URL missing host: {0}")]
    MissingHost(String),
    #[error("All URLs must have the same host. Found '{0}' and '{1}'")]
    DifferentHosts(String, String),
    #[error("All URLs must be in the same directory. Found '{0}' and '{1}'")]
    DifferentParents(String, String),
}

/// Extracts the parent directory from a URL path.
///
/// For example, "/releases/v1.0/SHA256SUMS" yields "/releases/v1.0/".
/// Falls back to "/" when no slash is found.
pub fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) => path[..=pos].to_string(),
        None => "/".to_string(),
    }
}

/// Validates that all URLs share the same host and parent directory.
///
/// Returns the common host and parent path on success.
pub fn validate_common_parent(urls: &[Url]) -> Result<CommonBasePath, UrlValidationError> {
    let first = urls.first().ok_or(UrlValidationError::EmptyUrls)?;

    let first_host = first
        .host_str()
        .ok_or_else(|| UrlValidationError::MissingHost(first.to_string()))?
        .to_string();

    let first_parent = parent_path(first.path());

    for url in &urls[1..] {
        let host = url
            .host_str()
            .ok_or_else(|| UrlValidationError::MissingHost(url.to_string()))?
            .to_string();

        if host != first_host {
            return Err(UrlValidationError::DifferentHosts(first_host, host));
        }

        let parent = parent_path(url.path());
        if parent != first_parent {
            return Err(UrlValidationError::DifferentParents(first_parent, parent));
        }
    }

    Ok(CommonBasePath {
        host: first_host,
        parent_path: first_parent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // parent_path tests
    // -----------------

    #[test]
    fn test_parent_path_with_file() {
        assert_eq!(parent_path("/releases/v1.0/SHA256SUMS"), "/releases/v1.0/");
    }

    #[test]
    fn test_parent_path_root_file() {
        assert_eq!(parent_path("/SHA256SUMS"), "/");
    }

    #[test]
    fn test_parent_path_no_slash() {
        assert_eq!(parent_path("SHA256SUMS"), "/");
    }

    // validate_common_parent tests
    // ----------------------------

    #[test]
    fn test_validate_single_url() -> anyhow::Result<()> {
        let urls = vec![Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?];
        let result = validate_common_parent(&urls)?;
        assert_eq!(result.host, "example.com");
        assert_eq!(result.parent_path, "/releases/v1.0/");
        Ok(())
    }

    #[test]
    fn test_validate_multiple_same_parent() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com/releases/v1.0/archive.tar.gz")?,
        ];
        let result = validate_common_parent(&urls)?;
        assert_eq!(result.host, "example.com");
        assert_eq!(result.parent_path, "/releases/v1.0/");
        Ok(())
    }

    #[test]
    fn test_validate_different_hosts() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://other.com/releases/v1.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentHosts(a, b)) => {
                assert_eq!(a, "example.com");
                assert_eq!(b, "other.com");
            }
            Err(e) => panic!("Expected DifferentHosts error, got: {e}"),
            Ok(_) => panic!("Expected DifferentHosts error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_different_parents() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com/releases/v2.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentParents(a, b)) => {
                assert_eq!(a, "/releases/v1.0/");
                assert_eq!(b, "/releases/v2.0/");
            }
            Err(e) => panic!("Expected DifferentParents error, got: {e}"),
            Ok(_) => panic!("Expected DifferentParents error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_empty_urls() {
        let urls: Vec<Url> = vec![];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::EmptyUrls) => {}
            Err(e) => panic!("Expected EmptyUrls error, got: {e}"),
            Ok(_) => panic!("Expected EmptyUrls error, got Ok"),
        }
    }

    #[test]
    fn test_validate_missing_host() -> anyhow::Result<()> {
        // file:// URLs have no host
        let urls = vec![Url::parse("file:///tmp/test.txt")?];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::MissingHost(url_str)) => {
                assert!(url_str.starts_with("file:///"));
            }
            Err(e) => panic!("Expected MissingHost error, got: {e}"),
            Ok(_) => panic!("Expected MissingHost error, got Ok"),
        }
        Ok(())
    }
}
