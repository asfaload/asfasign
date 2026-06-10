use config::{Config, Environment};
use rest_api_types::errors::ServerConfigError;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GitBackendConfig {
    #[default]
    Sha1,
    Sha256,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server_address: IpAddr,
    pub server_port: u16,
    pub git_repo_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub git_backend: GitBackendConfig,
    pub git_signing_pub_key_path: PathBuf,
    pub github_api_key: Option<String>,
    pub gitlab_api_key: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AppConfigOptions {
    pub server_address: Option<IpAddr>,
    pub server_port: Option<u16>,
    pub git_repo_path: Option<PathBuf>,
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_backend: Option<GitBackendConfig>,
    pub git_signing_pub_key_path: Option<PathBuf>,
    pub github_api_key: Option<String>,
    pub gitlab_api_key: Option<String>,
}

impl Default for AppConfigOptions {
    fn default() -> Self {
        Self {
            server_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            server_port: Some(3000),
            git_repo_path: None,
            log_level: Some("info".to_string()),
            git_backend: Some(GitBackendConfig::Sha1),
            git_signing_pub_key_path: None,
            github_api_key: None,
            gitlab_api_key: None,
        }
    }
}

/// Minimum git version required for SHA-256 object format support.
const MIN_GIT_VERSION_FOR_SHA256: (u32, u32) = (2, 42);

/// Validate that the system's git binary supports SHA-256 repositories.
fn validate_git_for_sha256() -> Result<(), ServerConfigError> {
    let output = std::process::Command::new("git")
        .arg("--version")
        .output()
        .map_err(|e| {
            ServerConfigError::InvalidConfig(format!(
                "git_backend=sha256 requires git >= {}.{}, but git could not be executed: {}",
                MIN_GIT_VERSION_FOR_SHA256.0, MIN_GIT_VERSION_FOR_SHA256.1, e
            ))
        })?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version_part = version_str
        .trim()
        .strip_prefix("git version ")
        .ok_or_else(|| {
            ServerConfigError::InvalidConfig(format!(
                "git_backend=sha256 requires git >= {}.{}, but could not parse git version output: '{}'",
                MIN_GIT_VERSION_FOR_SHA256.0, MIN_GIT_VERSION_FOR_SHA256.1, version_str.trim()
            ))
        })?;

    let parts: Vec<&str> = version_part.split('.').collect();
    let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    if (major, minor) < MIN_GIT_VERSION_FOR_SHA256 {
        return Err(ServerConfigError::InvalidConfig(format!(
            "git_backend=sha256 requires git >= {}.{}, but found {}.{}",
            MIN_GIT_VERSION_FOR_SHA256.0, MIN_GIT_VERSION_FOR_SHA256.1, major, minor
        )));
    }

    Ok(())
}

pub fn get_config() -> Result<AppConfig, ServerConfigError> {
    build_config_from_defaults(AppConfigOptions::default())
}
pub fn build_config_from_defaults(
    defaults: AppConfigOptions,
) -> Result<AppConfig, ServerConfigError> {
    // Create a config source from the provided defaults struct.
    // This requires the AppConfigOptions to be serialisable
    let defaults_source = Config::try_from(&defaults)?;

    // Build the configuration by layering sources.
    // Sources added later have higher priority.
    let config = Config::builder()
        .add_source(defaults_source)
        .add_source(
            Environment::with_prefix("ASFALOAD")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?;

    // Deserialize the merged configuration into our strongly-typed struct
    let app_config: AppConfig = config.try_deserialize()?;

    // Perform final validation that can't be handled by serde.
    if app_config.git_repo_path.as_os_str().is_empty() {
        return Err(ServerConfigError::InvalidConfig(
            "git_repo_path cannot be empty".to_string(),
        ));
    }
    if app_config.git_signing_pub_key_path.as_os_str().is_empty() {
        return Err(ServerConfigError::InvalidConfig(
            "git_signing_pub_key_path cannot be empty".to_string(),
        ));
    }

    // Canonicalise git repo path in config used in backend
    let canonical_git_repo_path = std::fs::canonicalize(app_config.git_repo_path)
        .map_err(|e| ServerConfigError::InvalidConfig(format!("Invalid git repo path: {}", e)))?;
    let canonical_git_signing_pub_key_path =
        std::fs::canonicalize(app_config.git_signing_pub_key_path).map_err(|e| {
            ServerConfigError::InvalidConfig(format!("Invalid git signing key path: {}", e))
        })?;
    let app_config = AppConfig {
        git_repo_path: canonical_git_repo_path,
        git_signing_pub_key_path: canonical_git_signing_pub_key_path,
        ..app_config
    };

    if app_config.git_backend == GitBackendConfig::Sha256 {
        validate_git_for_sha256()?;
    }

    Ok(app_config)
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;

    fn git_backend_from_env() -> GitBackendConfig {
        match std::env::var("ASFALOAD_GIT_BACKEND")
            .unwrap_or("sha1".to_string())
            .as_str()
        {
            "sha1" => GitBackendConfig::Sha1,
            "sha256" => GitBackendConfig::Sha256,
            other => panic!("Unkown value for ASFALOAD_GIT_BACKEND: {}", other),
        }
    }
    #[test]
    fn test_build_config_from_defaults_no_env_vars() {
        // Test that build_config_from_defaults fails when no git_repo_path is provided
        // and no environment variables are set
        let defaults = AppConfigOptions {
            server_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            server_port: Some(3000),
            git_repo_path: None,
            log_level: None,
            git_backend: None,
            git_signing_pub_key_path: None,
            github_api_key: None,
            gitlab_api_key: None,
        };

        let result = build_config_from_defaults(defaults);

        // Should fail because git_repo_path is required but not provided
        // This should be a BuildError from the config crate during deserialization
        assert!(result.is_err());
        match result {
            Err(ServerConfigError::BuildError(e)) => {
                assert!(
                    e.to_string()
                        .contains("expected a string for key `git_repo_path`")
                        || e.to_string()
                            .contains("expected a string for key `log_level`")
                );
            }
            Err(e) => {
                panic!("Expected BuildError, got: {:?}", e);
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[test]
    fn test_build_config_from_defaults_with_git_path() {
        // We run the tests with and without ASFALOAD_GIT_BACKEND set, so this will return once the
        // value from the env, and once the default value sha1
        let expected_git_backend = git_backend_from_env();
        // Test that build_config_from_defaults succeeds when required values are provided
        let temp_dir = tempfile::tempdir().unwrap();
        let git_path = temp_dir.path().to_path_buf();

        let defaults = AppConfigOptions {
            server_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            server_port: Some(8080),
            git_repo_path: Some(git_path.clone()),
            log_level: Some("info".to_string()),
            git_backend: Some(GitBackendConfig::Sha1),
            git_signing_pub_key_path: None,
            github_api_key: None,
            gitlab_api_key: None,
        };

        let result = build_config_from_defaults(defaults);

        match result {
            Ok(_) => {}
            Err(e) => panic!("Could not build config from defaults: {}", e),
        }
        let config = result.unwrap();
        assert_eq!(config.server_port, 8080);
        assert_eq!(config.git_repo_path, git_path);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.git_backend, expected_git_backend);
    }

    #[test]
    fn test_build_config_from_defaults_no_log_level() {
        let temp_dir = tempfile::tempdir().unwrap();
        let git_path = temp_dir.path().to_path_buf();
        // Test that build_config_from_defaults fails when no log_level is provided
        // and no environment variables are set
        let defaults = AppConfigOptions {
            server_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            server_port: Some(3000),
            git_repo_path: Some(git_path.clone()),
            log_level: None,
            git_backend: None,
            git_signing_pub_key_path: None,
            github_api_key: None,
            gitlab_api_key: None,
        };

        let result = build_config_from_defaults(defaults);

        // Should fail because log_level is required but not provided
        assert!(result.is_err());
        match result {
            Err(ServerConfigError::BuildError(e)) => {
                assert!(
                    e.to_string()
                        .contains("expected a string for key `log_level`")
                );
            }
            Err(e) => {
                panic!("Expected BuildError, got: {:?}", e);
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[test]
    fn test_build_config_from_defaults_git_backend_defaults_to_sha1() {
        // We run the tests with and without ASFALOAD_GIT_BACKEND set, so this will return once the
        // value from the env, and once the default value sha1
        let expected_git_backend = git_backend_from_env();
        let temp_dir = tempfile::tempdir().unwrap();
        let defaults = AppConfigOptions {
            server_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            server_port: Some(3000),
            git_repo_path: Some(temp_dir.path().to_path_buf()),
            log_level: Some("info".to_string()),
            git_backend: None,
            git_signing_pub_key_path: None,
            github_api_key: None,
            gitlab_api_key: None,
        };

        let config = build_config_from_defaults(defaults).expect("Could not build config");
        assert_eq!(config.git_backend, expected_git_backend);
    }

    #[test]
    fn test_build_config_from_defaults_accepts_sha256_with_valid_git() {
        let temp_dir = tempfile::tempdir().unwrap();
        let defaults = AppConfigOptions {
            server_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            server_port: Some(3000),
            git_repo_path: Some(temp_dir.path().to_path_buf()),
            log_level: Some("info".to_string()),
            git_backend: Some(GitBackendConfig::Sha256),
            git_signing_pub_key_path: None,
            github_api_key: None,
            gitlab_api_key: None,
        };

        // This test assumes git >= 2.42 is available (per project requirement)
        let result = build_config_from_defaults(defaults);
        assert!(
            result.is_ok(),
            "sha256 config should be accepted: {:?}",
            result
        );
    }
}
