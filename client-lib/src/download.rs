mod fileserver;
mod github;
mod gitlab;
mod revocation;
mod v1;

use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::constants::INDEX_FILE;
use reqwest::Url;

// Re-export v1's download function as the current API surface
pub use v1::download_file_with_verification;

trait ForgesPathMethods {
    fn construct_index_file_path(&self, file_url: &Url) -> AsfaloadLibResult<String> {
        self.construct_file_repo_path(file_url, INDEX_FILE)
    }

    fn construct_file_repo_path(
        &self,
        file_url: &Url,
        filename: &str,
    ) -> AsfaloadLibResult<String> {
        let prefix = forge_url::path_prefix_from_url(file_url)
            .map_err(|e| ClientLibError::InvalidUrl(e.to_string()))?;
        let path = file_url.path();

        let path = path.strip_prefix('/').unwrap_or(path);

        let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

        let translated_path = self.translate_download_to_release_path(dir_path);

        Ok(format!("{}/{}/{}", prefix, translated_path, filename))
    }
    fn translate_download_to_release_path(&self, path: &str) -> String;
}

enum Forges {
    Github(GithubForge),
    Gitlab(GitlabForge),
    FileServer(FileServerForge),
}

impl Forges {
    pub fn from_host(host: &str) -> AsfaloadLibResult<Self> {
        use forge_url::github::GITHUB_HOSTS;
        use forge_url::gitlab::GITLAB_HOSTS;

        if GITHUB_HOSTS.contains(&host) {
            Ok(Self::Github(GithubForge))
        } else if GITLAB_HOSTS.contains(&host) {
            Ok(Self::Gitlab(GitlabForge))
        } else {
            Ok(Self::FileServer(FileServerForge))
        }
    }

    pub fn from_type_str(type_str: &str) -> AsfaloadLibResult<Self> {
        match type_str {
            "github" => Ok(Self::Github(GithubForge)),
            "gitlab" => Ok(Self::Gitlab(GitlabForge)),
            "fileserver" => Ok(Self::FileServer(FileServerForge)),
            other => Err(ClientLibError::UnsupportedForge(other.to_string())),
        }
    }
}

impl ForgesPathMethods for Forges {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        match self {
            Self::Github(f) => f.translate_download_to_release_path(path),
            Self::Gitlab(f) => f.translate_download_to_release_path(path),
            Self::FileServer(f) => f.translate_download_to_release_path(path),
        }
    }
}

use fileserver::FileServerForge;
use github::GithubForge;
use gitlab::GitlabForge;

fn get_forge(file_url: &Url) -> AsfaloadLibResult<Forges> {
    let host = file_url
        .host_str()
        .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
    Forges::from_host(host)
}

#[cfg(test)]
mod tests {
    use super::fileserver;
    use super::gitlab;
    use super::*;
    use reqwest::Url;

    fn translate_github_release_path(path: &str) -> String {
        GithubForge.translate_download_to_release_path(path)
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
    fn forges_from_host_gitlab() {
        assert!(matches!(
            Forges::from_host("gitlab.com"),
            Ok(Forges::Gitlab(_))
        ));
    }

    #[test]
    fn forges_from_host_unknown_falls_back_to_fileserver() {
        assert!(matches!(
            Forges::from_host("example.com"),
            Ok(Forges::FileServer(_))
        ));
    }

    // --- construct_file_repo_path ---

    #[test]
    fn construct_file_repo_path_standard_github_url() {
        let url =
            Url::parse("https://github.com/owner/repo/releases/download/v1.0/file.tar.gz").unwrap();
        let forge = get_forge(&url).unwrap();
        let result = forge.construct_file_repo_path(&url, "index.json").unwrap();
        assert_eq!(
            result,
            "https/github.com/443/owner/repo/releases/tag/v1.0/index.json"
        );
    }

    #[test]
    fn construct_file_repo_path_no_host() {
        // A URL like "file:///path" has no host — get_forge fails
        let url = Url::parse("file:///some/path/file.txt").unwrap();
        let result = get_forge(&url);
        assert!(matches!(result, Err(ClientLibError::InvalidUrl(_))));
    }

    // --- construct_index_file_path ---

    #[test]
    fn construct_index_file_path_happy_path() {
        let url = Url::parse("https://github.com/owner/repo/releases/download/v2.0/artifact.zip")
            .unwrap();
        let forge = get_forge(&url).unwrap();
        let result = forge.construct_index_file_path(&url).unwrap();
        assert!(result.ends_with(INDEX_FILE));
        assert!(result.starts_with("https/github.com/443/owner/repo/releases/tag/v2.0/"));
    }

    #[test]
    fn construct_index_file_path_no_host() {
        let url = Url::parse("file:///some/path/file.txt").unwrap();
        let result = get_forge(&url);
        assert!(matches!(result, Err(ClientLibError::InvalidUrl(_))));
    }

    #[test]
    fn construct_index_file_path_unknown_host_uses_fileserver() {
        let url = Url::parse("https://example.com/owner/repo/-/releases/file.tar.gz").unwrap();
        let forge = get_forge(&url).unwrap();
        assert!(matches!(forge, Forges::FileServer(_)));
        let result = forge.construct_index_file_path(&url).unwrap();
        assert_eq!(
            result,
            format!("https/example.com/443/owner/repo/-/releases/{}", INDEX_FILE)
        );
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
                url: "https://gitlab.com/owner/repo/-/releases/file.tar.gz",
                expected: "ok_gitlab",
            },
            TestCase {
                url: "https://example.com/some/file.tar.gz",
                expected: "ok_fileserver",
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
                "ok_gitlab" => assert!(
                    matches!(result, Ok(Forges::Gitlab(_))),
                    "Expected Ok(Forges::Gitlab(_)) for URL: {}",
                    case.url
                ),
                "ok_fileserver" => assert!(
                    matches!(result, Ok(Forges::FileServer(_))),
                    "Expected Ok(Forges::FileServer(_)) for URL: {}",
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

    #[test]
    fn construct_signers_file_path_standard_github_url() {
        use features_lib::constants::INDEX_FILE;
        use features_lib::local_signers_path_for;
        let url =
            Url::parse("https://github.com/owner/repo/releases/download/v1.0/file.tar.gz").unwrap();
        let forge = get_forge(&url).unwrap();
        let signers_filename = local_signers_path_for(INDEX_FILE).unwrap();
        let result = forge
            .construct_file_repo_path(&url, &signers_filename.to_string_lossy())
            .unwrap();
        assert_eq!(
            result,
            "https/github.com/443/owner/repo/releases/tag/v1.0/asfaload.index.json.signers.json"
        );
    }

    // --- FileServerForge ---

    fn translate_fileserver_path(path: &str) -> String {
        fileserver::FileServerForge.translate_download_to_release_path(path)
    }

    #[test]
    fn translate_fileserver_path_identity() {
        let result = translate_fileserver_path("some/path/to/files");
        assert_eq!(result, "some/path/to/files");
    }

    #[test]
    fn translate_fileserver_path_empty() {
        let result = translate_fileserver_path("");
        assert_eq!(result, "");
    }

    // --- GitlabForge ---

    fn translate_gitlab_release_path_via_forge(path: &str) -> String {
        gitlab::GitlabForge.translate_download_to_release_path(path)
    }

    #[test]
    fn translate_gitlab_release_path_standard() {
        let result =
            translate_gitlab_release_path_via_forge("namespace/project/-/releases/v1.0/downloads");
        assert_eq!(result, "namespace/project/-/releases/v1.0/downloads");
    }

    #[test]
    fn translate_gitlab_release_path_empty() {
        let result = translate_gitlab_release_path_via_forge("");
        assert_eq!(result, "");
    }

    // --- Forges::from_type_str ---

    #[test]
    fn forges_from_type_str_github() {
        assert!(matches!(
            Forges::from_type_str("github"),
            Ok(Forges::Github(_))
        ));
    }

    #[test]
    fn forges_from_type_str_gitlab() {
        assert!(matches!(
            Forges::from_type_str("gitlab"),
            Ok(Forges::Gitlab(_))
        ));
    }

    #[test]
    fn forges_from_type_str_fileserver() {
        assert!(matches!(
            Forges::from_type_str("fileserver"),
            Ok(Forges::FileServer(_))
        ));
    }

    #[test]
    fn forges_from_type_str_unknown() {
        assert!(matches!(
            Forges::from_type_str("bitbucket"),
            Err(ClientLibError::UnsupportedForge(_))
        ));
    }

    // --- construct_file_repo_path for new forges ---

    #[test]
    fn construct_file_repo_path_fileserver_url() {
        let url =
            Url::parse("https://files.example.com/public/releases/v1.0/installer.tar.gz").unwrap();
        let forge = Forges::from_type_str("fileserver").unwrap();
        let result = forge
            .construct_file_repo_path(&url, "asfaload.index.json")
            .unwrap();
        assert_eq!(
            result,
            "https/files.example.com/443/public/releases/v1.0/asfaload.index.json"
        );
    }

    #[test]
    fn construct_file_repo_path_gitlab_url() {
        let url = Url::parse("https://gitlab.com/ns/project/-/releases/v1.0/downloads/file.tar.gz")
            .unwrap();
        let forge = Forges::from_type_str("gitlab").unwrap();
        let result = forge
            .construct_file_repo_path(&url, "asfaload.index.json")
            .unwrap();
        assert_eq!(
            result,
            "https/gitlab.com/443/ns/project/-/releases/v1.0/downloads/asfaload.index.json"
        );
    }
}
