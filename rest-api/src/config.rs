use config::{Config, Environment};
use rest_api_types::errors::ServerConfigError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server_port: u16,
    pub git_repo_path: PathBuf,
}

#[derive(Debug, Serialize, Clone)]
pub struct AppConfigOptions {
    pub server_port: Option<u16>,
    pub git_repo_path: Option<PathBuf>,
}

impl Default for AppConfigOptions {
    fn default() -> Self {
        Self {
            server_port: Some(3000),
            git_repo_path: None,
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
            Environment::with_prefix("ASFASIGN")
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

    Ok(app_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_config_from_defaults_no_env_vars() {
        // Test that build_config_from_defaults fails when no git_repo_path is provided
        // and no environment variables are set
        let defaults = AppConfigOptions {
            server_port: Some(3000),
            git_repo_path: None,
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
        // Test that build_config_from_defaults succeeds when git_repo_path is provided
        let temp_dir = tempfile::tempdir().unwrap();
        let git_path = temp_dir.path().to_path_buf();

        let defaults = AppConfigOptions {
            server_port: Some(8080),
            git_repo_path: Some(git_path.clone()),
        };

        let result = build_config_from_defaults(defaults);

        // Should succeed because git_repo_path is provided
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.server_port, 8080);
        assert_eq!(config.git_repo_path, git_path);
    }
}
