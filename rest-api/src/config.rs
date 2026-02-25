use config::{Config, Environment};
use rest_api_types::errors::ServerConfigError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub server_port: u16,
    pub git_repo_path: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub git_backend: GitBackendConfig,
    pub github_api_key: Option<String>,
    pub gitlab_api_key: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AppConfigOptions {
    pub server_port: Option<u16>,
    pub git_repo_path: Option<PathBuf>,
    pub log_level: Option<String>,
    pub git_backend: Option<GitBackendConfig>,
    pub github_api_key: Option<String>,
    pub gitlab_api_key: Option<String>,
}

impl Default for AppConfigOptions {
    fn default() -> Self {
        Self {
            server_port: Some(3000),
            git_repo_path: None,
            log_level: Some("info".to_string()),
            git_backend: Some(GitBackendConfig::Sha1),
            github_api_key: None,
            gitlab_api_key: None,
        }
    }
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
    #[cfg(not(feature = "sha256"))]
    if app_config.git_backend == GitBackendConfig::Sha256 {
        return Err(ServerConfigError::InvalidConfig(
            "git_backend=sha256 requires building rest-api with the 'sha256' feature".to_string(),
        ));
    }

    Ok(app_config)
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;

    #[test]
    fn test_build_config_from_defaults_no_env_vars() {
        // Test that build_config_from_defaults fails when no git_repo_path is provided
        // and no environment variables are set
        let defaults = AppConfigOptions {
            server_port: Some(3000),
            git_repo_path: None,
            log_level: None,
            git_backend: None,
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
        // Test that build_config_from_defaults succeeds when required values are provided
        let temp_dir = tempfile::tempdir().unwrap();
        let git_path = temp_dir.path().to_path_buf();

        let defaults = AppConfigOptions {
            server_port: Some(8080),
            git_repo_path: Some(git_path.clone()),
            log_level: Some("info".to_string()),
            git_backend: Some(GitBackendConfig::Sha1),
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
        assert_eq!(config.git_backend, GitBackendConfig::Sha1);
    }

    #[test]
    fn test_build_config_from_defaults_no_log_level() {
        let temp_dir = tempfile::tempdir().unwrap();
        let git_path = temp_dir.path().to_path_buf();
        // Test that build_config_from_defaults fails when no log_level is provided
        // and no environment variables are set
        let defaults = AppConfigOptions {
            server_port: Some(3000),
            git_repo_path: Some(git_path.clone()),
            log_level: None,
            git_backend: None,
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
        let temp_dir = tempfile::tempdir().unwrap();
        let defaults = AppConfigOptions {
            server_port: Some(3000),
            git_repo_path: Some(temp_dir.path().to_path_buf()),
            log_level: Some("info".to_string()),
            git_backend: None,
            github_api_key: None,
            gitlab_api_key: None,
        };

        let config = build_config_from_defaults(defaults).expect("Could not build config");
        assert_eq!(config.git_backend, GitBackendConfig::Sha1);
    }

    #[cfg(not(feature = "sha256"))]
    #[test]
    fn test_build_config_from_defaults_rejects_sha256_without_feature() {
        let temp_dir = tempfile::tempdir().unwrap();
        let defaults = AppConfigOptions {
            server_port: Some(3000),
            git_repo_path: Some(temp_dir.path().to_path_buf()),
            log_level: Some("info".to_string()),
            git_backend: Some(GitBackendConfig::Sha256),
            github_api_key: None,
            gitlab_api_key: None,
        };

        let result = build_config_from_defaults(defaults);
        assert!(result.is_err());
        match result {
            Err(ServerConfigError::InvalidConfig(message)) => {
                assert!(message.contains("git_backend=sha256 requires building rest-api"));
            }
            Err(other) => panic!("Expected InvalidConfig, got {:?}", other),
            Ok(_) => panic!("Expected error but got success"),
        }
    }
}
