mod github;
mod v1;

use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::constants::INDEX_FILE;
use reqwest::Url;

// Re-export v1's download function as the current API surface
pub use v1::download_file_with_verification;

trait ForgeTrait {
    fn construct_index_file_path(file_url: &Url) -> AsfaloadLibResult<String> {
        Self::construct_file_repo_path(file_url, INDEX_FILE)
    }

    fn construct_file_repo_path(file_url: &Url, filename: &str) -> AsfaloadLibResult<String> {
        let host = file_url
            .host_str()
            .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
        let path = file_url.path();

        let path = path.strip_prefix('/').unwrap_or(path);

        let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

        let translated_path = Self::translate_download_to_release_path(dir_path);

        Ok(format!("{}/{}/{}", host, translated_path, filename))
    }
    fn translate_download_to_release_path(path: &str) -> String;
}

enum Forges {
    Github(GithubForge),
}

impl Forges {
    pub fn from_host(host: &str) -> AsfaloadLibResult<Self> {
        if host.contains("github.com") {
            Ok(Self::Github(GithubForge))
        } else {
            Err(ClientLibError::UnsupportedForge(host.to_string()))
        }
    }
}

use github::GithubForge;

fn get_forge(file_url: &Url) -> AsfaloadLibResult<Forges> {
    let host = file_url
        .host_str()
        .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
    Forges::from_host(host)
}

fn construct_index_file_path(file_url: &Url) -> AsfaloadLibResult<String> {
    let forge = get_forge(file_url)?;
    match forge {
        Forges::Github(_) => GithubForge::construct_index_file_path(file_url),
    }
}

fn construct_file_repo_path(file_url: &Url, filename: &str) -> AsfaloadLibResult<String> {
    let forge = get_forge(file_url)?;
    match forge {
        Forges::Github(_) => GithubForge::construct_file_repo_path(file_url, filename),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Url;

    fn translate_github_release_path(path: &str) -> String {
        GithubForge::translate_download_to_release_path(path)
    }

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
            Ok(Forges::Github(_))
        ));
    }

    #[test]
    fn forges_from_host_api_github() {
        assert!(matches!(
            Forges::from_host("api.github.com"),
            Ok(Forges::Github(_))
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

    #[test]
    fn construct_index_file_path_no_host() {
        let url = Url::parse("file:///some/path/file.txt").unwrap();
        assert!(matches!(
            construct_index_file_path(&url),
            Err(ClientLibError::InvalidUrl(_))
        ));
    }

    #[test]
    fn construct_index_file_path_unsupported_forge() {
        let url =
            Url::parse("https://gitlab.com/owner/repo/-/releases/file.tar.gz").unwrap();
        assert!(matches!(
            construct_index_file_path(&url),
            Err(ClientLibError::UnsupportedForge(_))
        ));
    }


    #[test]
    fn get_forge_test_cases() {
        struct TestCase {
            url: &'static str,
            expected: &'static str,
        }

        let cases = vec![
            TestCase {
                url: "https://github.com/owner/repo/releases/download/v1.0/file.tar.gz",
                expected: "ok_github",
            },
            TestCase {
                url: "https://api.github.com/repos/owner/repo",
                expected: "ok_github",
            },
            TestCase {
                url: "https://gitlab.com/owner/repo/-/releases/file.tar.gz",
                expected: "err_unsupported",
            },
            TestCase {
                url: "https://example.com/some/file.tar.gz",
                expected: "err_unsupported",
            },
            TestCase {
                url: "file:///some/path/file.txt",
                expected: "err_invalid_url",
            },
        ];

        for case in &cases {
            let url = Url::parse(case.url).unwrap();
            let result = get_forge(&url);
            match case.expected {
                "ok_github" => assert!(
                    matches!(result, Ok(Forges::Github(_))),
                    "Expected Ok(Forges::Github(_)) for URL: {}",
                    case.url
                ),
                "err_unsupported" => assert!(
                    matches!(result, Err(ClientLibError::UnsupportedForge(_))),
                    "Expected Err(UnsupportedForge) for URL: {}",
                    case.url
                ),
                "err_invalid_url" => assert!(
                    matches!(result, Err(ClientLibError::InvalidUrl(_))),
                    "Expected Err(InvalidUrl) for URL: {}",
                    case.url
                ),
                _ => unreachable!("Unknown expected value: {}", case.expected),
            }
        }
    }
}
