mod git_actor {

use rest_api::actors::git_actor::CommitFile;
use rest_api::actors::git_actor::logic;
use rest_api::path_validation::NormalisedPaths;
use rest_api_types::errors::ApiError;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_plan_commit_success() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path();
    let file_path = PathBuf::from("test.txt");
    let normalised_paths = NormalisedPaths::new(repo_path.to_path_buf(), file_path.clone())
        .await
        .unwrap();

    let msg = CommitFile {
        file_paths: normalised_paths,
        commit_message: "Add test file".to_string(),
    };

    let result = logic::plan_commit(msg);
    assert!(result.is_ok());

    let plan = result.unwrap();
    assert_eq!(plan.relative_path, file_path);
    assert_eq!(plan.commit_message, "Add test file");
}

#[tokio::test]
async fn test_plan_commit_empty_message() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = PathBuf::from("test.txt");
    let normalised_paths = NormalisedPaths::new(temp_dir.path().to_path_buf(), file_path)
        .await
        .unwrap();

    let msg = CommitFile {
        file_paths: normalised_paths,
        commit_message: "   ".to_string(), // Whitespace only
    };

    let result = logic::plan_commit(msg);
    assert!(result.is_err());
    assert!(matches!(result, Err(ApiError::ActorOperationFailed(_))));
}

}
