mod v1;

use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::constants::INDEX_FILE;
use reqwest::Url;

// Re-export v1's download function as the current API surface
pub use v1::download_file_with_verification;

fn construct_index_file_path(file_url: &Url) -> AsfaloadLibResult<String> {
    construct_file_repo_path(file_url, INDEX_FILE)
}

fn construct_file_repo_path(file_url: &Url, filename: &str) -> AsfaloadLibResult<String> {
    let host = file_url
        .host_str()
        .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
    let path = file_url.path();

    let path = path.strip_prefix('/').unwrap_or(path);

    let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

    let translated_path = translate_download_to_release_path(host, dir_path)?;

    Ok(format!("{}/{}/{}", host, translated_path, filename))
}

enum Forges {
    Github,
}

impl Forges {
    pub fn from_host(host: &str) -> AsfaloadLibResult<Self> {
        if host.contains("github.com") {
            Ok(Self::Github)
        } else {
            Err(ClientLibError::UnsupportedForge(host.to_string()))
        }
    }
}

fn translate_download_to_release_path(host: &str, path: &str) -> AsfaloadLibResult<String> {
    let forge = Forges::from_host(host)?;
    match forge {
        Forges::Github => Ok(translate_github_release_path(path)),
    }
}

fn translate_github_release_path(path: &str) -> String {
    path.replace("/releases/download/", "/releases/tag/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Url;

    // --- translate_github_release_path ---

    #[test]
    fn translate_github_release_path_standard() {
        let result = translate_github_release_path("owner/repo/releases/download/v1.0");
        assert_eq!(result, "owner/repo/releases/tag/v1.0");
    }

    #[test]
    fn translate_github_release_path_no_match() {
        let result = translate_github_release_path("owner/repo/some/path");
        assert_eq!(result, "owner/repo/some/path");
    }

    #[test]
    fn translate_github_release_path_empty() {
        let result = translate_github_release_path("");
        assert_eq!(result, "");
    }

    // --- Forges::from_host ---

    #[test]
    fn forges_from_host_github() {
        assert!(matches!(
            Forges::from_host("github.com"),
            Ok(Forges::Github)
        ));
    }

    #[test]
    fn forges_from_host_api_github() {
        assert!(matches!(
            Forges::from_host("api.github.com"),
            Ok(Forges::Github)
        ));
    }

    #[test]
    fn forges_from_host_gitlab_unsupported() {
        assert!(matches!(
            Forges::from_host("gitlab.com"),
            Err(ClientLibError::UnsupportedForge(_))
        ));
    }

    #[test]
    fn forges_from_host_unknown_unsupported() {
        assert!(matches!(
            Forges::from_host("example.com"),
            Err(ClientLibError::UnsupportedForge(_))
        ));
    }

    // --- construct_file_repo_path ---

    #[test]
    fn construct_file_repo_path_standard_github_url() {
        let url =
            Url::parse("https://github.com/owner/repo/releases/download/v1.0/file.tar.gz").unwrap();
        let result = construct_file_repo_path(&url, "index.json").unwrap();
        assert_eq!(result, "github.com/owner/repo/releases/tag/v1.0/index.json");
    }

    #[test]
    fn construct_file_repo_path_no_host() {
        // A URL like "file:///path" has no host
        let url = Url::parse("file:///some/path/file.txt").unwrap();
        assert!(matches!(
            construct_file_repo_path(&url, "index.json"),
            Err(ClientLibError::InvalidUrl(_))
        ));
    }

    // --- construct_index_file_path ---

    #[test]
    fn construct_index_file_path_happy_path() {
        let url = Url::parse("https://github.com/owner/repo/releases/download/v2.0/artifact.zip")
            .unwrap();
        let result = construct_index_file_path(&url).unwrap();
        assert!(result.ends_with(INDEX_FILE));
        assert!(result.starts_with("github.com/owner/repo/releases/tag/v2.0/"));
    }
}
