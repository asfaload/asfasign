use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use reqwest::Client;
use rest_api_types::errors::ApiError;
use signers_file_types::SignersConfig;

use crate::file_auth::github::parse_github_url;

#[derive(Debug, Clone)]
pub struct AuthenticateProjectRequest {
    pub signers_file_url: String,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct ProjectSignersProposal {
    pub project_id: String,
    pub signers_config: SignersConfig,
    pub request_id: String,
}

pub struct GitHubProjectAuthenticator {
    http_client: Client,
}

const MAX_SIGNERS_FILE_SIZE: usize = 64 * 1024; // 64KB
const ALLOWED_EXTENSIONS: &[&str] = &["json"];

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 30000;

pub fn validate_file_extension(file_path: &std::path::Path) -> Result<(), String> {
    let extension = file_path.extension().and_then(|e| e.to_str());
    if !ALLOWED_EXTENSIONS.iter().any(|&ext| Some(ext) == extension) {
        let file_ext = extension.unwrap_or("none");
        return Err(format!(
            "Signers file must have .json extension, got .{}",
            file_ext
        ));
    }
    Ok(())
}

pub fn validate_body_size(body: &[u8]) -> Result<(), String> {
    if body.len() > MAX_SIGNERS_FILE_SIZE {
        return Err(format!(
            "Signers file too large: {} bytes exceeds {} byte limit",
            body.len(),
            MAX_SIGNERS_FILE_SIZE
        ));
    }
    Ok(())
}

impl GitHubProjectAuthenticator {
    pub fn new() -> Self {
        tracing::info!("GitHubProjectAuthenticator created");
        Self {
            http_client: Client::new(),
        }
    }

    async fn fetch_with_retry(&self, url: &str, request_id: &str) -> Result<String, ApiError> {
        let mut retries = 0;
        let mut backoff_ms = INITIAL_BACKOFF_MS;

        loop {
            let response = self.http_client.get(url).send().await.map_err(|e| {
                tracing::error!(request_id = %request_id, url = %url, error = %e, "Failed to fetch signers file");
                ApiError::ActorOperationFailed(format!("Failed to fetch: {}", e))
            })?;

            if response.status() == 429 {
                if retries >= MAX_RETRIES {
                    return Err(ApiError::ActorOperationFailed(
                        "GitHub rate limit exceeded after max retries".to_string(),
                    ));
                }

                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(backoff_ms);

                tracing::warn!(request_id = %request_id, retry_after_ms = %retry_after, "Rate limited by GitHub, waiting before retry");

                tokio::time::sleep(std::time::Duration::from_millis(retry_after)).await;

                retries += 1;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }

            if !response.status().is_success() {
                return Err(ApiError::ActorOperationFailed(format!(
                    "GitHub returned status: {}",
                    response.status()
                )));
            }

            let content = response.text().await.map_err(|e| {
                tracing::error!(request_id = %request_id, error = %e, "Failed to read response body");
                ApiError::ActorOperationFailed(format!("Failed to read response: {}", e))
            })?;

            return Ok(content);
        }
    }

    async fn authenticate_project(
        &self,
        signers_file_url: &str,
        request_id: &str,
    ) -> Result<ProjectSignersProposal, ApiError> {
        tracing::info!(
            request_id = %request_id,
            signers_file_url = %signers_file_url,
            "Attempting to authenticate project"
        );

        let repo_info = parse_github_url(signers_file_url).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                url = %signers_file_url,
                error = %e,
                "Failed to parse GitHub URL"
            );
            ApiError::InvalidRequestBody(format!("Invalid GitHub URL: {}", e))
        })?;

        tracing::info!(
            request_id = %request_id,
            owner = %repo_info.owner,
            repo = %repo_info.repo,
            branch = %repo_info.branch,
            file_path = %repo_info.file_path.display(),
            "Parsed GitHub URL successfully"
        );

        validate_file_extension(&repo_info.file_path).map_err(|e| {
            tracing::error!(request_id = %request_id, error = %e, "Invalid file extension");
            ApiError::InvalidRequestBody(e)
        })?;

        let content = self
            .fetch_with_retry(&repo_info.raw_url, request_id)
            .await?;

        tracing::info!(
            request_id = %request_id,
            content_length = content.len(),
            "Fetched signers file content successfully"
        );

        validate_body_size(content.as_bytes()).map_err(|e| {
            tracing::error!(request_id = %request_id, error = %e, "Body size exceeds limit");
            ApiError::InvalidRequestBody(e)
        })?;

        let signers_config: SignersConfig = signers_file_types::parse_signers_config(&content)
            .map_err(|e| {
                tracing::error!(
                    request_id = %request_id,
                    raw_url = %repo_info.raw_url,
                    error = %e,
                    "Failed to parse signers config JSON"
                );
                ApiError::InvalidRequestBody(format!("Invalid signers config JSON: {}", e))
            })?;

        // NOTE: This validation is intentionally duplicated from SignerGroup's
        // deserializer for defense-in-depth, providing clearer error messages
        // and logging at the API layer. The deserializer enforces the constraint
        // during JSON parsing, but we validate again here for better error reporting.
        for group in signers_config.artifact_signers() {
            if group.threshold > group.signers.len() as u32 {
                tracing::error!(
                    request_id = %request_id,
                    group_threshold = group.threshold,
                    signer_count = group.signers.len(),
                    "Artifact signers group threshold exceeds signer count"
                );
                return Err(ApiError::InvalidRequestBody(format!(
                    "Artifact signers group threshold ({}) exceeds signer count ({})",
                    group.threshold,
                    group.signers.len()
                )));
            }
        }

        for group in signers_config.admin_keys() {
            if group.threshold > group.signers.len() as u32 {
                tracing::error!(
                    request_id = %request_id,
                    group_threshold = group.threshold,
                    signer_count = group.signers.len(),
                    "Admin keys group threshold exceeds signer count"
                );
                return Err(ApiError::InvalidRequestBody(format!(
                    "Admin keys group threshold ({}) exceeds signer count ({})",
                    group.threshold,
                    group.signers.len()
                )));
            }
        }

        if let Some(master_keys) = signers_config.master_keys() {
            for group in master_keys {
                if group.threshold > group.signers.len() as u32 {
                    tracing::error!(
                        request_id = %request_id,
                        group_threshold = group.threshold,
                        signer_count = group.signers.len(),
                        "Master keys group threshold exceeds signer count"
                    );
                    return Err(ApiError::InvalidRequestBody(format!(
                        "Master keys group threshold ({}) exceeds signer count ({})",
                        group.threshold,
                        group.signers.len()
                    )));
                }
            }
        }

        tracing::info!(
            request_id = %request_id,
            owner = %repo_info.owner,
            repo = %repo_info.repo,
            "Signers config validated successfully"
        );

        let project_id = format!("github.com/{}/{}", repo_info.owner, repo_info.repo);

        tracing::info!(
            request_id = %request_id,
            project_id = %project_id,
            "Project authentication successful"
        );

        Ok(ProjectSignersProposal {
            project_id,
            signers_config,
            request_id: request_id.to_string(),
        })
    }
}

impl Message<AuthenticateProjectRequest> for GitHubProjectAuthenticator {
    type Reply = Result<ProjectSignersProposal, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: AuthenticateProjectRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            signers_file_url = %msg.signers_file_url,
            "GitHubProjectAuthenticator received authentication request"
        );

        self.authenticate_project(&msg.signers_file_url, &msg.request_id)
            .await
    }
}

impl Actor for GitHubProjectAuthenticator {
    type Args = ();
    type Error = String;

    async fn on_start(
        _args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!("GitHubProjectAuthenticator starting");
        Ok(Self::new())
    }
}

impl Default for GitHubProjectAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_validate_file_extension_accepts_json() {
        let result = validate_file_extension(PathBuf::from("signers.json").as_path());
        assert!(result.is_ok(), "Should accept .json extension");
    }

    #[test]
    fn test_validate_file_extension_rejects_txt() {
        let result = validate_file_extension(PathBuf::from("signers.txt").as_path());
        assert!(result.is_err(), "Should reject .txt extension");
        let err = result.unwrap_err();
        assert!(
            err.contains(".json"),
            "Error should mention .json, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_file_extension_rejects_no_extension() {
        let result = validate_file_extension(PathBuf::from("signers").as_path());
        assert!(result.is_err(), "Should reject files without extension");
    }

    #[test]
    fn test_validate_body_size_accepts_small() {
        let result = validate_body_size(b"small content");
        assert!(result.is_ok(), "Should accept small body");
    }

    #[test]
    fn test_validate_body_size_rejects_over_max() {
        let large_content = vec![b'x'; MAX_SIGNERS_FILE_SIZE + 1];
        let result = validate_body_size(&large_content);
        assert!(result.is_err(), "Should reject body over max size");
        let err = result.unwrap_err();
        assert!(
            err.contains("too large") || err.contains("limit"),
            "Error should mention size limit, got: {}",
            err
        );
    }

    #[test]
    fn test_constants_are_correct() {
        assert_eq!(MAX_SIGNERS_FILE_SIZE, 64 * 1024, "Max size should be 64KB");
        assert_eq!(
            ALLOWED_EXTENSIONS,
            &["json"],
            "Only .json should be allowed"
        );
    }

    #[tokio::test]
    async fn test_retries_on_rate_limiting() {
        let mock_server = httpmock::MockServer::start();

        let signers_json = r#"{
            "version": 1,
            "timestamp": "2024-01-01T00:00:00Z",
            "artifact_signers": []
        }"#;

        // Test with a localhost URL
        let url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let mut mock_429 = mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(429).header("Retry-After", "200");
        });

        let authenticator = GitHubProjectAuthenticator::new();

        // Start the authentication in the background
        let handle = tokio::spawn({
            async move {
                authenticator
                    .authenticate_project(&url, "test-rate-limit")
                    .await
            }
        });

        let start = std::time::Instant::now();

        // Poll for the first hit, then delete the mock and create the success mock
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if mock_429.hits() > 0 {
                mock_429.delete();
                mock_server.mock(|when, then| {
                    when.method(httpmock::Method::GET)
                        .path("/owner/repo/main/signers.json");
                    then.status(200)
                        .header("Content-Type", "application/json")
                        .body(signers_json);
                });
                break;
            }
            if start.elapsed().as_secs() > 5 {
                panic!("Timeout waiting for first hit, hits: {}", mock_429.hits());
            }
        }

        // Wait for the result
        let result = handle.await.unwrap();
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "Should eventually succeed after retry: {:?}",
            result
        );
        assert!(
            elapsed.as_millis() >= 200,
            "Should have waited for Retry-After, got: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_authenticate_with_localhost_url() {
        let mock_server = httpmock::MockServer::start();
        use features_lib::AsfaloadKeyPairTrait;

        let test_password = "test_password";
        let key_pair = features_lib::AsfaloadKeyPairs::new(test_password).unwrap();
        let public_key = key_pair.public_key();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )
        .unwrap();

        let signers_json = serde_json::to_string_pretty(&signers_config).unwrap();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json);
        });

        let url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let authenticator = GitHubProjectAuthenticator::new();
        let result = authenticator
            .authenticate_project(&url, "test-request")
            .await;

        assert!(
            result.is_ok(),
            "Should authenticate with localhost URL: {:?}",
            result
        );
        let auth_result = result.unwrap();
        assert_eq!(auth_result.project_id, "github.com/owner/repo");

        mock.assert();
    }
}
