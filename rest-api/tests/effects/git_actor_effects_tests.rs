// Create rest-api/tests/effects/git_actor_effects_tests.rs
use rest_api::actors::git_actor::logic::CommitPlan;
use rest_api::actors::git_actor::effects;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_execute_commit_success() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path();
    
    // Initialize git repo
    git2::Repository::init(repo_path).unwrap();
    
    // Create a test file
    let test_file = repo_path.join("test.txt");
    let mut file = File::create(&test_file).await.unwrap();
    file.write_all(b"test content").await.unwrap();
    file.flush().await.unwrap();
    
    let plan = CommitPlan {
        repo_path: repo_path.to_path_buf(),
        relative_path: PathBuf::from("test.txt"),
        commit_message: "Test commit".to_string(),
    };
    
    let result = effects::execute_commit(plan).await;
    assert!(result.is_ok());
}