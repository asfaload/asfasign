use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::errors::ApiError;
use git2::{Repository, Signature};

use crate::path_validation::NormalisedPaths;

#[derive(Debug)]
pub struct ArtifactSignersSource {
    // The commit that committed the copy at artifact_signers
    commit: String,
    // The timestamp of the commit that introduced the copy
    commit_time: DateTime<Utc>,
    // The signers file path the artifact_signers file was copied from
    path: NormalisedPaths,
    // copy of signers file taken when artifact signature completed
    artifact_signers: NormalisedPaths,
}

impl ArtifactSignersSource {
    pub fn commit(&self) -> &str {
        &self.commit
    }

    pub fn commit_time(&self) -> DateTime<Utc> {
        self.commit_time
    }

    pub fn path(&self) -> &NormalisedPaths {
        &self.path
    }

    pub fn artifact_signers(&self) -> &NormalisedPaths {
        &self.artifact_signers
    }
}

/// Trait abstracting git commit operations.
///
/// This allows swapping the underlying git implementation (e.g., SHA-1 vs SHA-256)
/// without changing the GitActor's external interface.
pub trait GitBackend: Send + Sync + 'static {
    /// Commit files to the repository at `repo_path`.
    ///
    /// `file_paths` are absolute paths on disk. The implementation is responsible
    /// for staging and committing them.
    fn commit_files(
        &self,
        file_paths: &[NormalisedPaths],
        commit_message: &str,
    ) -> Result<(), ApiError>;

    fn new<P: AsRef<Path>>(root: P) -> Self
    where
        Self: Sized;
    fn root(&self) -> &PathBuf;

    /// Read file content at a specific git commit.
    ///
    /// Uses `git show {commit}:{path}` to retrieve file content from history.
    fn file_content_at_commit(
        &self,
        commit: &str,
        relative_path: &Path,
    ) -> Result<String, ApiError> {
        let spec = format!("{}:{}", commit, relative_path.to_string_lossy());
        let content = GitCommand::git(self.root(), &["show", &spec]).map_err(|e| {
            ApiError::GitError(format!(
                "Failed to read {} at commit {}: {}",
                relative_path.display(),
                commit,
                e
            ))
        })?;
        Ok(content)
    }

    // When an artifact signature is completed, a copy of the signers file is
    // stored alongside it. This method traces back to the original source of
    // that signers file using git copy detection.
    fn artifact_signers_source(
        &self,
        signers: NormalisedPaths,
    ) -> Result<ArtifactSignersSource, ApiError> {
        let first_commit = GitCommand::git(
            self.root(),
            &[
                "log",
                "--diff-filter=A",
                "--format=%H",
                "-1",
                "--",
                signers.relative_path().to_string_lossy().as_ref(),
            ],
        )?;

        if first_commit.is_empty() {
            return Err(ApiError::GitError(format!(
                "No commit found introducing {}",
                signers.relative_path().display()
            )));
        }

        let commit_time_str =
            GitCommand::git(self.root(), &["log", "--format=%cI", "-1", &first_commit])?;
        let commit_time: DateTime<Utc> = commit_time_str.parse().map_err(|e| {
            ApiError::GitError(format!(
                "Failed to parse commit time '{}': {}",
                commit_time_str, e
            ))
        })?;

        let git_output = GitCommand::git(
            self.root(),
            &[
                "diff-tree",
                "-r",
                "-C",
                "--find-copies-harder",
                &first_commit,
            ],
        )?;
        let found = git_output
            .lines()
            .find(|l| l.split('\t').next_back() == Some(&signers.relative_path().to_string_lossy()))
            .ok_or(ApiError::GitError(
                "Error extracting signers source from git diff-tree.".to_string(),
            ))?;

        // diff-tree raw output format:
        // :100644 100644 <old_hash> <new_hash> C100\tsource_path\tdest_path
        // The metadata and paths are separated by a tab. `split_whitespace` is not
        // safe as paths can contain spaces.
        let source_path_str = found
            .split_once('\t')
            .and_then(|(_, paths)| paths.split('\t').next())
            .ok_or_else(|| {
                ApiError::GitError(format!("Could not parse source path from: {}", found))
            })?;

        // The signers copy is always taken from the active signers dir,
        // never from the pending dir. However, git copy detection can be
        // ambiguous when both directories contain the same file content
        // (same blob). If git reports the pending dir as the source,
        // verify the active dir has the same file at that commit and use
        // it instead. If the active dir doesn't have it, that's an error.
        use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR};
        let pending_component = format!("/{}/", PENDING_SIGNERS_DIR);
        let source_path_str = if source_path_str.contains(&pending_component) {
            let active_candidate =
                source_path_str.replace(&pending_component, &format!("/{}/", SIGNERS_DIR));
            // Verify the active signers file exists at this commit
            let active_path = Path::new(&active_candidate);
            self.file_content_at_commit(&first_commit, active_path)
                .map_err(|_| {
                    ApiError::GitError(format!(
                        "Signers copy source is in pending dir ({}) \
                         but no matching active signers file found at commit {}",
                        source_path_str, first_commit
                    ))
                })?;
            active_candidate
        } else {
            source_path_str.to_string()
        };
        let source_path = NormalisedPaths::new_sync(self.root(), &source_path_str)?;

        let res = ArtifactSignersSource {
            commit: first_commit,
            commit_time,
            path: source_path,
            artifact_signers: signers,
        };
        Ok(res)
    }
}

const GIT_ACTOR_NAME: &str = "git-actor";
const GIT_USER_EMAIL: &str = "git-actor@rest-api.asfaload.com";

/// Collect relative file paths from a list of absolute targets, skipping
/// `.git` and `.app_cache` directories. Rejects symlinks.
///
/// This is the shared file-walk logic used by both the git2-based and
/// CLI-based backends.
fn collect_relative_paths(
    repo_workdir: &Path,
    target_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, git2::Error> {
    let mut result = Vec::new();
    let mut paths_to_visit: Vec<PathBuf> = target_paths.to_vec();

    while let Some(current_path) = paths_to_visit.pop() {
        let metadata = match fs::symlink_metadata(&current_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(git2::Error::from_str(&format!(
                        "Encountered a symlink!{}",
                        current_path.display()
                    )));
                }
                meta
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(e) => {
                return Err(git2::Error::from_str(&format!(
                    "Failed to read path {:?}: {}",
                    current_path, e
                )));
            }
        };

        if metadata.is_file() {
            let rel_path = current_path
                .strip_prefix(repo_workdir)
                .map_err(|_| git2::Error::from_str("Target path is outside repository"))?;
            result.push(rel_path.to_path_buf());
        } else if metadata.is_dir() {
            if let Some(name) = current_path.file_name()
                && (name == ".git" || name == ".app_cache")
            {
                tracing::debug!("Skipping ignored directory: {}", current_path.display());
                continue;
            }
            for entry in fs::read_dir(&current_path).map_err(|e| {
                git2::Error::from_str(&format!(
                    "Failed to read directory {:?}: {}",
                    current_path, e
                ))
            })? {
                let entry =
                    entry.map_err(|e| git2::Error::from_str(&format!("Dir entry error: {}", e)))?;
                paths_to_visit.push(entry.path());
            }
        }
    }
    Ok(result)
}

/// Add files to the git2 index using the shared file-walk logic.
pub(crate) fn add_path_recursively(
    index: &mut git2::Index,
    target_path: &NormalisedPaths,
) -> Result<(), git2::Error> {
    let rel_paths = collect_relative_paths(
        target_path.base_dir().as_path(),
        &[target_path.absolute_path()],
    )?;
    for rel_path in &rel_paths {
        index.add_path(rel_path)?;
    }
    Ok(())
}

/// Shared commit logic for the git2-based Sha1GitBackend.
fn sha1_commit_files(
    repo: &Repository,
    file_paths: &[NormalisedPaths],
    commit_message: &str,
) -> Result<(), ApiError> {
    let signature = Signature::now(GIT_ACTOR_NAME, GIT_USER_EMAIL)?;

    let mut index = repo.index()?;
    for file_path in file_paths {
        add_path_recursively(&mut index, file_path)?;
    }

    let tree_oid = index.write_tree()?;
    index.write()?;
    let tree = repo.find_tree(tree_oid)?;

    let parent_commit = repo.head().and_then(|head| head.peel_to_commit()).ok();
    if let Some(parent) = &parent_commit
        && parent.tree_id() == tree_oid
    {
        return Err(ApiError::InvalidRequestBody(
            "No changes to commit".to_string(),
        ));
    }
    let parents: Vec<&git2::Commit> = parent_commit.as_ref().into_iter().collect();

    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        commit_message,
        &tree,
        &parents,
    )?;

    Ok(())
}

pub struct Sha1GitBackend {
    root: PathBuf,
}

impl GitBackend for Sha1GitBackend {
    fn root(&self) -> &PathBuf {
        &self.root
    }
    fn commit_files(
        &self,
        file_paths: &[NormalisedPaths],
        commit_message: &str,
    ) -> Result<(), ApiError> {
        let repo = Repository::open(self.root())?;
        sha1_commit_files(&repo, file_paths, commit_message)
    }

    fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }
}

/// SHA-256 git backend using the git CLI.
///
/// `libgit2-sys` does not yet ship the `unstable-sha256` feature in a
/// published release, so this backend shells out to `git` (>= 2.42) for
/// staging and committing. It validates the repository uses SHA-256 via
/// `git rev-parse --show-object-format` before every commit.
pub struct Sha256GitBackend {
    root: PathBuf,
}

struct GitCommand;
impl GitCommand {
    /// Run a git command in the given repo directory. Returns stdout on
    /// success, or a `git2::Error` with combined stderr/stdout on failure.
    fn git(repo_path: &Path, args: &[&str]) -> Result<String, git2::Error> {
        let output = std::process::Command::new("git")
            .args(["-C", &repo_path.to_string_lossy()])
            .args(args)
            .output()
            .map_err(|e| git2::Error::from_str(&format!("Failed to run git: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(git2::Error::from_str(&format!(
                "git {:?} failed: {}",
                args,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}
impl Sha256GitBackend {
    /// Validate that the repository uses the SHA-256 object format.
    fn validate_sha256(repo_path: &Path) -> Result<(), git2::Error> {
        let format = GitCommand::git(repo_path, &["rev-parse", "--show-object-format"])?;
        if format != "sha256" {
            return Err(git2::Error::from_str(&format!(
                "Sha256GitBackend requires a SHA-256 repository, got '{}'",
                format
            )));
        }
        Ok(())
    }
}

impl GitBackend for Sha256GitBackend {
    fn commit_files(
        &self,
        file_paths: &[NormalisedPaths],
        commit_message: &str,
    ) -> Result<(), ApiError> {
        let repo_path = self.root();
        Self::validate_sha256(repo_path.as_path())?;

        let absolute_paths: Vec<PathBuf> = file_paths.iter().map(|p| p.absolute_path()).collect();
        let rel_paths = collect_relative_paths(repo_path.as_path(), &absolute_paths)?;

        if rel_paths.is_empty() {
            return Err(ApiError::GitOperationFailed(git2::Error::from_str(
                "No files to commit",
            )));
        }

        // Stage files one at a time via git add
        for rel_path in &rel_paths {
            GitCommand::git(
                repo_path.as_path(),
                &["add", "--", &rel_path.to_string_lossy()],
            )?;
        }

        let staged = GitCommand::git(repo_path.as_path(), &["status", "--porcelain"])?;
        if staged.is_empty() {
            return Err(ApiError::InvalidRequestBody(
                "No changes to commit".to_string(),
            ));
        }

        // Commit with configured author identity
        GitCommand::git(
            repo_path.as_path(),
            &[
                "-c",
                &format!("user.name={}", GIT_ACTOR_NAME),
                "-c",
                &format!("user.email={}", GIT_USER_EMAIL),
                "commit",
                "-m",
                commit_message,
            ],
        )?;

        Ok(())
    }

    fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn root(&self) -> &PathBuf {
        &self.root
    }
}

/// Dispatch enum for GitBackend implementations.
#[derive(Debug, Clone, Copy)]
pub enum GitBackendKind {
    Sha1,
    Sha256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Signature;
    use tempfile::TempDir;

    struct MockBackend {
        root: PathBuf,
        should_fail: bool,
    }

    impl GitBackend for MockBackend {
        fn commit_files(
            &self,
            _file_paths: &[NormalisedPaths],
            _commit_message: &str,
        ) -> Result<(), ApiError> {
            if self.should_fail {
                Err(ApiError::GitOperationFailed(git2::Error::from_str(
                    "mock failure",
                )))
            } else {
                Ok(())
            }
        }

        fn new<P: AsRef<Path>>(root: P) -> Self
        where
            Self: Sized,
        {
            Self {
                root: root.as_ref().to_path_buf(),
                should_fail: false,
            }
        }

        fn root(&self) -> &PathBuf {
            &self.root
        }
    }

    impl MockBackend {
        fn new_failing<P: AsRef<Path>>(root: P) -> Self {
            Self {
                root: root.as_ref().to_path_buf(),
                should_fail: true,
            }
        }
    }

    #[test]
    fn test_mock_backend_failure() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let target_path = repo_path.join("test").join("file.txt");
        let backend = MockBackend::new_failing(repo_path);
        let p = normalise_for_repo(repo_path, &target_path);
        let result = backend.commit_files(&[p], "test commit");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_path_recursively_skips_git_directory() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path).unwrap();
        let mut index = repo.index().unwrap();

        let test_file = repo_path.join("test.txt");
        std::fs::write(&test_file, "test content").unwrap();

        let test_dir = repo_path.join("subdir");
        std::fs::create_dir(&test_dir).unwrap();
        let test_file_in_dir = test_dir.join("nested.txt");
        std::fs::write(&test_file_in_dir, "nested content").unwrap();

        let root = normalise_for_repo(repo_path, repo_path);
        let result = add_path_recursively(&mut index, &root);
        assert!(result.is_ok(), "Should successfully add repo root");

        for entry in index.iter() {
            let path_str = String::from_utf8_lossy(&entry.path);
            assert!(
                !path_str.starts_with(".git/"),
                "File from .git directory found in index: {}",
                path_str
            );
        }
    }

    fn init_test_repo(path: &Path) -> Repository {
        let repo = Repository::init(path).unwrap();
        {
            let signature = Signature::now("Test", "test@test.com").unwrap();
            let tree_oid = repo.index().unwrap().write_tree().unwrap();
            let tree = repo.find_tree(tree_oid).unwrap();
            repo.commit(Some("HEAD"), &signature, &signature, "Initial", &tree, &[])
                .unwrap();
        }
        repo
    }

    fn normalise_for_repo(repo_path: &Path, file_path: &Path) -> NormalisedPaths {
        let relative_or_requested = file_path.strip_prefix(repo_path).unwrap_or(file_path);
        crate::path_validation::build_normalised_absolute_path(repo_path, relative_or_requested)
            .unwrap()
    }

    #[test]
    fn test_sha1_backend_commits_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let repo = init_test_repo(repo_path);

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        let result =
            backend.commit_files(&[normalise_for_repo(repo_path, &file_path)], "test commit");
        assert!(result.is_ok());

        let mut revwalk = repo.revwalk().unwrap();
        revwalk.push_head().unwrap();
        let commits: Vec<git2::Oid> = revwalk.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(commits.len(), 2);

        let latest = repo.find_commit(commits[0]).unwrap();
        assert_eq!(latest.message().unwrap(), "test commit");
        assert!(latest.tree().unwrap().get_name("test.txt").is_some());
    }

    #[test]
    fn test_sha1_backend_skips_git_directory() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let repo = init_test_repo(repo_path);

        std::fs::write(repo_path.join("real.txt"), "content").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        let result = backend.commit_files(&[normalise_for_repo(repo_path, repo_path)], "commit");
        assert!(result.is_ok());

        let head = repo.head().unwrap().peel_to_commit().unwrap();
        for entry in head.tree().unwrap().iter() {
            assert!(!entry.name().unwrap().starts_with(".git"));
        }
    }

    #[test]
    fn test_sha1_backend_commits_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let repo = init_test_repo(repo_path);

        std::fs::write(repo_path.join("a.txt"), "a").unwrap();
        std::fs::write(repo_path.join("b.txt"), "b").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[
                normalise_for_repo(repo_path, &repo_path.join("a.txt")),
                normalise_for_repo(repo_path, &repo_path.join("b.txt")),
            ],
            "multi",
        );
        assert!(result.is_ok());

        let tree = repo
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree()
            .unwrap();
        assert!(tree.get_name("a.txt").is_some());
        assert!(tree.get_name("b.txt").is_some());
    }

    #[test]
    fn test_sha1_backend_handles_initial_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let repo = Repository::init(repo_path).unwrap(); // No initial commit

        std::fs::write(repo_path.join("first.txt"), "first").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &repo_path.join("first.txt"))],
            "initial",
        );
        assert!(result.is_ok());
        assert_eq!(
            repo.head()
                .unwrap()
                .peel_to_commit()
                .unwrap()
                .message()
                .unwrap(),
            "initial"
        );
    }

    #[test]
    fn test_sha1_backend_rejects_empty_commit_when_file_is_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_test_repo(repo_path);

        let file = repo_path.join("same.txt");
        std::fs::write(&file, "same content").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        let first = backend.commit_files(&[normalise_for_repo(repo_path, &file)], "first");
        assert!(first.is_ok(), "First commit should succeed: {:?}", first);

        std::fs::write(&file, "same content").unwrap();
        let second = backend.commit_files(&[normalise_for_repo(repo_path, &file)], "second");
        match second {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("No changes to commit"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected rejection for unchanged tree commit"),
        }
    }

    /// Helper: init a repo, commit a source file, copy it to dest, commit the
    /// copy.  Returns (TempDir, backend, source path on disk, dest path on disk).
    /// The TempDir must be kept alive for the duration of the test.
    fn init_repo_with_copied_file(
        source_relative: &str,
        source_content: &str,
        dest_relative: &str,
    ) -> (TempDir, Sha1GitBackend, PathBuf, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_test_repo(repo_path);

        let source_file = repo_path.join(source_relative);
        if let Some(parent) = source_file.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&source_file, source_content).unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &source_file)],
                "add source file",
            )
            .unwrap();

        let dest_file = repo_path.join(dest_relative);
        if let Some(parent) = dest_file.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::copy(&source_file, &dest_file).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &dest_file)],
                "copy file to destination",
            )
            .unwrap();

        (temp_dir, backend, source_file, dest_file)
    }

    #[test]
    fn test_artifact_signers_source_finds_copy_source() {
        let (temp_dir, backend, _source, dest) = init_repo_with_copied_file(
            "signers.json",
            r#"{"signers": ["alice"]}"#,
            "artifacts/my_artifact.signers.json",
        );
        let repo_path = temp_dir.path();

        let signers_path = normalise_for_repo(repo_path, &dest);
        let result = backend.artifact_signers_source(signers_path);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        let source = result.unwrap();
        assert_eq!(
            source.path().relative_path(),
            Path::new("signers.json"),
            "Source path should be the original signers file"
        );
        assert_eq!(
            source.artifact_signers().relative_path(),
            Path::new("artifacts/my_artifact.signers.json"),
            "Artifact signers should be the copied file"
        );
        // commit should be a valid 40-char hex SHA-1
        assert_eq!(source.commit().len(), 40);
        assert!(source.commit().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_artifact_signers_source_errors_when_file_not_in_history() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_test_repo(repo_path);

        // File exists on disk but was never committed
        let file = repo_path.join("never_committed.json");
        std::fs::write(&file, "content").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        let signers_path = normalise_for_repo(repo_path, &file);
        let result = backend.artifact_signers_source(signers_path);

        match result {
            Err(ApiError::GitError(msg)) => {
                assert!(
                    msg.contains("No commit found"),
                    "Expected 'No commit found' error, got: {}",
                    msg
                );
            }
            other => panic!("Expected ApiError::GitError, got {:?}", other),
        }
    }

    #[test]
    fn test_artifact_signers_source_does_not_panic_for_non_copied_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_test_repo(repo_path);

        // Create and commit a brand new file (no copy source)
        let file = repo_path.join("original.json");
        std::fs::write(&file, "unique content that won't match anything").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        backend
            .commit_files(&[normalise_for_repo(repo_path, &file)], "add original file")
            .unwrap();

        let signers_path = normalise_for_repo(repo_path, &file);
        // Should not panic — may return Ok or Err depending on diff-tree output
        let _result = backend.artifact_signers_source(signers_path);
    }

    #[test]
    fn test_artifact_signers_source_nested_directories() {
        let (temp_dir, backend, _source, dest) = init_repo_with_copied_file(
            "config/signers.json",
            r#"{"threshold": 2, "signers": ["a","b","c"]}"#,
            "releases/v1/artifacts/binary.signers.json",
        );
        let repo_path = temp_dir.path();

        let signers_path = normalise_for_repo(repo_path, &dest);
        let result = backend.artifact_signers_source(signers_path);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        let source = result.unwrap();
        assert_eq!(
            source.path().relative_path(),
            Path::new("config/signers.json"),
        );
    }

    #[test]
    fn test_artifact_signers_source_returns_introducing_commit() {
        let (temp_dir, backend, _source, dest) = init_repo_with_copied_file(
            "signers.json",
            r#"{"signers": ["bob"]}"#,
            "artifact.signers.json",
        );
        let repo_path = temp_dir.path();

        let expected_commit = GitCommand::git(
            repo_path,
            &[
                "log",
                "--diff-filter=A",
                "--format=%H",
                "-1",
                "--",
                "artifact.signers.json",
            ],
        )
        .unwrap();

        let signers_path = normalise_for_repo(repo_path, &dest);
        let result = backend.artifact_signers_source(signers_path).unwrap();

        assert_eq!(result.commit(), expected_commit);
    }

    #[test]
    fn test_artifact_signers_source_has_commit_time() {
        let (temp_dir, backend, _source, dest) = init_repo_with_copied_file(
            "signers.json",
            r#"{"signers": ["alice"]}"#,
            "artifacts/my_artifact.signers.json",
        );
        let repo_path = temp_dir.path();

        let signers_path = normalise_for_repo(repo_path, &dest);
        let result = backend.artifact_signers_source(signers_path).unwrap();

        // commit_time should be a valid recent timestamp
        let commit_time = result.commit_time();
        let now = chrono::Utc::now();
        assert!(
            commit_time <= now,
            "Commit time should not be in the future"
        );
        assert!(
            (now - commit_time).num_seconds() < 60,
            "Commit time should be recent (within 60s)"
        );
    }

    #[test]
    fn test_file_content_at_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_test_repo(repo_path);

        let file_path = repo_path.join("data.json");
        std::fs::write(&file_path, r#"{"version": 1}"#).unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "add data.json",
            )
            .unwrap();

        let first_commit = GitCommand::git(repo_path, &["log", "--format=%H", "-1"]).unwrap();

        std::fs::write(&file_path, r#"{"version": 2}"#).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &file_path)],
                "update data.json",
            )
            .unwrap();

        let content = backend
            .file_content_at_commit(&first_commit, Path::new("data.json"))
            .unwrap();
        assert_eq!(content, r#"{"version": 1}"#);

        let current = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(current, r#"{"version": 2}"#);
    }

    #[test]
    fn test_file_content_at_commit_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_test_repo(repo_path);

        let file_path = repo_path.join("exists.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha1GitBackend::new(repo_path);
        backend
            .commit_files(&[normalise_for_repo(repo_path, &file_path)], "add file")
            .unwrap();

        let commit = GitCommand::git(repo_path, &["log", "--format=%H", "-1"]).unwrap();

        let result = backend.file_content_at_commit(&commit, Path::new("nonexistent.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_artifact_signers_source_with_successive_copies() {
        // Start with a basic repo + first copy (original → deep)
        let (temp_dir, backend, _original, deep_copy) = init_repo_with_copied_file(
            "signers.json",
            r#"{"threshold": 2, "signers": ["alice","bob","carol"]}"#,
            "sub/dir/subsub/signers.json",
        );
        let repo_path = temp_dir.path();

        // Record the commit that introduced the deep copy
        let deep_copy_commit = GitCommand::git(
            repo_path,
            &[
                "log",
                "--diff-filter=A",
                "--format=%H",
                "-1",
                "--",
                "sub/dir/subsub/signers.json",
            ],
        )
        .unwrap();

        // Second copy: deep → shallow
        let shallow_copy = repo_path.join("sub/dir/signers.json");
        std::fs::copy(&deep_copy, &shallow_copy).unwrap();
        backend
            .commit_files(
                &[normalise_for_repo(repo_path, &shallow_copy)],
                "copy signers to shallow path",
            )
            .unwrap();

        // Query the deep copy — should trace back to the original root file
        let deep_signers = normalise_for_repo(repo_path, &deep_copy);
        let result = backend.artifact_signers_source(deep_signers);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        let source = result.unwrap();
        assert_eq!(
            source.path().relative_path(),
            Path::new("signers.json"),
            "Deep copy should trace back to the original root file"
        );
        assert_eq!(
            source.artifact_signers().relative_path(),
            Path::new("sub/dir/subsub/signers.json"),
        );
        assert_eq!(
            source.commit(),
            deep_copy_commit,
            "Commit should be the one that introduced the deep copy"
        );
    }
}

#[cfg(test)]
mod sha256_tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// Create a SHA-256 git repository using the git CLI.
    ///
    /// `git2::RepositoryInitOptions` does not support `object-format` selection,
    /// so the CLI is the only way to create SHA-256 repos.
    fn init_sha256_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(path)
            .status()
            .expect("git CLI must be available for SHA-256 tests");
        assert!(status.success(), "git init --object-format=sha256 failed");

        let run_git = |args: &[&str]| {
            let s = Command::new("git")
                .args(["-C", &path.to_string_lossy()])
                .args(args)
                .status()
                .unwrap();
            assert!(s.success(), "git {:?} failed", args);
        };
        run_git(&["config", "user.name", "Test User"]);
        run_git(&["config", "user.email", "test@test.com"]);
        run_git(&["commit", "--allow-empty", "-m", "Initial"]);
    }

    fn normalise_for_repo(repo_path: &Path, file_path: &Path) -> NormalisedPaths {
        let relative_or_requested = file_path.strip_prefix(repo_path).unwrap_or(file_path);
        crate::path_validation::build_normalised_absolute_path(repo_path, relative_or_requested)
            .unwrap()
    }

    #[test]
    fn test_sha256_backend_commits_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "sha256 content").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &file_path)],
            "sha256 commit",
        );
        assert!(result.is_ok(), "SHA-256 commit failed: {:?}", result);

        // Verify via git log
        let log = GitCommand::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("sha256 commit"));
    }

    #[test]
    fn test_sha256_backend_rejects_sha1_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        git2::Repository::init(repo_path).unwrap(); // SHA-1 repo

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result =
            backend.commit_files(&[normalise_for_repo(repo_path, &file_path)], "should fail");
        match result {
            Err(ApiError::GitOperationFailed(e)) => {
                assert!(e.message().contains("SHA-256"));
            }
            Err(e) => panic!("Expected ApiError::GitOperationFailed but got {}", e),
            Ok(_) => panic!("Expected SHA-256 format rejection but commit succeeded"),
        }
    }

    #[test]
    fn test_sha256_backend_commits_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let f1 = repo_path.join("a.txt");
        let f2 = repo_path.join("b.txt");
        std::fs::write(&f1, "a").unwrap();
        std::fs::write(&f2, "b").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[
                normalise_for_repo(repo_path, &f1),
                normalise_for_repo(repo_path, &f2),
            ],
            "multi sha256",
        );
        assert!(result.is_ok());

        // Verify both files are committed
        let ls = GitCommand::git(repo_path, &["ls-tree", "--name-only", "HEAD"]).unwrap();
        assert!(ls.contains("a.txt"));
        assert!(ls.contains("b.txt"));
    }

    #[test]
    fn test_sha256_backend_handles_subdirectories() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let subdir = repo_path.join("nested/deep");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::write(subdir.join("file.txt"), "deep content").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &subdir.join("file.txt"))],
            "nested sha256",
        );
        assert!(result.is_ok());

        let ls = GitCommand::git(repo_path, &["ls-tree", "-r", "--name-only", "HEAD"]).unwrap();
        assert!(ls.contains("nested/deep/file.txt"));
    }

    #[test]
    fn test_sha256_backend_handles_initial_commit() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        // Create SHA-256 repo without initial commit
        let status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(repo_path)
            .status()
            .unwrap();
        assert!(status.success());

        std::fs::write(repo_path.join("first.txt"), "first").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[normalise_for_repo(repo_path, &repo_path.join("first.txt"))],
            "initial",
        );
        assert!(result.is_ok());

        let log = GitCommand::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("initial"));
    }

    #[test]
    fn test_sha256_backend_skips_git_directory() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        std::fs::write(repo_path.join("real.txt"), "content").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result = backend.commit_files(&[normalise_for_repo(repo_path, repo_path)], "commit");
        assert!(result.is_ok());

        let ls = GitCommand::git(repo_path, &["ls-tree", "-r", "--name-only", "HEAD"]).unwrap();
        assert!(!ls.contains(".git"));
        assert!(ls.contains("real.txt"));
    }

    #[test]
    fn test_sha256_backend_kind_dispatch() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        std::fs::write(repo_path.join("dispatch.txt"), "via enum").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let result = backend.commit_files(
            &[normalise_for_repo(
                repo_path,
                &repo_path.join("dispatch.txt"),
            )],
            "enum dispatch",
        );
        assert!(result.is_ok());

        let log = GitCommand::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("enum dispatch"));
    }

    #[test]
    fn test_sha256_backend_rejects_empty_commit_when_file_is_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file = repo_path.join("same.txt");
        std::fs::write(&file, "same content").unwrap();

        let backend = Sha256GitBackend::new(repo_path);
        let first = backend.commit_files(&[normalise_for_repo(repo_path, &file)], "first");
        assert!(first.is_ok(), "First commit should succeed: {:?}", first);

        // Rewriting identical content should reject commit because the tree is unchanged.
        std::fs::write(&file, "same content").unwrap();
        let second = backend.commit_files(&[normalise_for_repo(repo_path, &file)], "second");
        match second {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("No changes to commit"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected rejection for unchanged tree commit"),
        }
    }
}
