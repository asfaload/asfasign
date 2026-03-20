use url::Url;

use crate::ForgeUrlError;

/// Build the filesystem-safe path prefix from a URL's scheme, host, and port.
/// Always includes port (using default for scheme when not explicit).
/// Each component is a separate path segment for cross-platform compatibility.
///
/// Examples:
///   `https://github.com/...`         -> `"https/github.com/443"`
///   `http://localhost:9090/...`      -> `"http/localhost/9090"`
///   `https://gitlab.co.com:8443/...` -> `"https/gitlab.co.com/8443"`
pub fn path_prefix_from_url(url: &Url) -> Result<String, ForgeUrlError> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ForgeUrlError::InvalidFormat(format!(
            "Unsupported URL scheme: '{}'. Only http and https are supported",
            scheme
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| ForgeUrlError::InvalidFormat("URL has no host".to_string()))?;

    // After validating scheme is http or https, port_or_known_default() always
    // returns Some(80) or Some(443). This branch is defensive only.
    let port = url.port_or_known_default().ok_or_else(|| {
        ForgeUrlError::InvalidFormat(format!(
            "Cannot determine port for URL with scheme '{}'",
            scheme
        ))
    })?;

    Ok(format!("{}/{}/{}", scheme, host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_default_port() {
        let url = Url::parse("https://github.com/owner/repo").unwrap();
        assert_eq!(path_prefix_from_url(&url).unwrap(), "https/github.com/443");
    }

    #[test]
    fn https_explicit_default_port() {
        let url = Url::parse("https://github.com:443/owner/repo").unwrap();
        assert_eq!(path_prefix_from_url(&url).unwrap(), "https/github.com/443");
    }

    #[test]
    fn https_custom_port() {
        let url = Url::parse("https://gitlab.company.com:8443/team/app").unwrap();
        assert_eq!(
            path_prefix_from_url(&url).unwrap(),
            "https/gitlab.company.com/8443"
        );
    }

    #[test]
    fn http_default_port() {
        let url = Url::parse("http://files.example.com/releases/v1.0/SHA256SUMS").unwrap();
        assert_eq!(
            path_prefix_from_url(&url).unwrap(),
            "http/files.example.com/80"
        );
    }

    #[test]
    fn http_custom_port() {
        let url = Url::parse("http://localhost:9090/project/file.json").unwrap();
        assert_eq!(path_prefix_from_url(&url).unwrap(), "http/localhost/9090");
    }

    #[test]
    fn unsupported_scheme_file_url_returns_error() {
        let url = Url::parse("file:///some/path").unwrap();
        let err = path_prefix_from_url(&url).unwrap_err();
        assert!(err.to_string().contains("Unsupported URL scheme"));
    }

    #[test]
    fn unsupported_scheme_returns_error() {
        let url = Url::parse("ftp://files.example.com/file.txt").unwrap();
        assert!(path_prefix_from_url(&url).is_err());
    }
}
