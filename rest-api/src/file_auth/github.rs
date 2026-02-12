use std::path::Path;

use rest_api_types::errors::ApiError;

use crate::path_validation::NormalisedPaths;

/// Get the project's normalised paths in the repo
pub async fn get_project_normalised_paths<P: AsRef<Path>>(
    git_repo_path: P,
    project_id_in: impl Into<String>,
) -> Result<NormalisedPaths, ApiError> {
    let project_id = project_id_in.into();
    if project_id.contains('\0') {
        return Err(ApiError::InvalidRequestBody(
            "Project ID must not contain null bytes".to_string(),
        ));
    }

    if project_id.contains('\\') {
        return Err(ApiError::InvalidRequestBody(
            "Project ID must not contain backslashes".to_string(),
        ));
    }

    let normalised_paths = NormalisedPaths::new(git_repo_path, project_id).await?;

    Ok(normalised_paths)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_validate_project_id_with_null_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = get_project_normalised_paths(&git_repo_path, "github.com/user/repo\0").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("null bytes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }
    }

    #[tokio::test]
    async fn test_validate_project_id_with_backslashes() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = get_project_normalised_paths(&git_repo_path, "github.com\\user\\repo").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("backslashes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }
    }

    #[tokio::test]
    async fn test_validate_project_id_valid() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = get_project_normalised_paths(&git_repo_path, "github.com/user/repo").await;
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.absolute_path().starts_with(&git_repo_path));
        assert!(path.absolute_path().ends_with("github.com/user/repo"));
    }

    #[tokio::test]
    async fn test_validate_project_id_with_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let project_id = "github.com/user/repo";
        let project_path = git_repo_path.join(project_id);
        fs::create_dir_all(&project_path).unwrap();

        let result = get_project_normalised_paths(&git_repo_path, project_id).await;
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.absolute_path(), project_path);
    }

    #[tokio::test]
    async fn test_validate_project_id_with_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let project_id = "../../../etc/passwd";

        let result = get_project_normalised_paths(&git_repo_path, project_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidFilePath(msg) => {
                assert!(msg.contains("traversal"));
            }
            e => panic!("Expected InvalidFilePath error, got {}", e),
        }
    }
}
