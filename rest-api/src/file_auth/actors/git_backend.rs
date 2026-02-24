use std::fs;
use std::path::{Path, PathBuf};

use git2::{Repository, Signature};

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
        repo_path: &Path,
        file_paths: &[PathBuf],
        commit_message: &str,
    ) -> Result<(), git2::Error>;
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
                    tracing::error!(
                        file_path = %current_path.display(),
                        "Encountered symlink in git repo!"
                    );
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
    repo_workdir: &Path,
    target_path: &Path,
) -> Result<(), git2::Error> {
    let rel_paths = collect_relative_paths(repo_workdir, &[target_path.to_path_buf()])?;
    for rel_path in &rel_paths {
        index.add_path(rel_path)?;
    }
    Ok(())
}

/// Shared commit logic for the git2-based Sha1GitBackend.
fn sha1_commit_files(
    repo: &Repository,
    repo_path: &Path,
    file_paths: &[PathBuf],
    commit_message: &str,
) -> Result<(), git2::Error> {
    let signature = Signature::now(GIT_ACTOR_NAME, GIT_USER_EMAIL)?;

    let mut index = repo.index()?;
    for file_path in file_paths {
        add_path_recursively(&mut index, repo_path, file_path)?;
    }

    let tree_oid = index.write_tree()?;
    index.write()?;
    let tree = repo.find_tree(tree_oid)?;

    let parent_commit = repo.head().and_then(|head| head.peel_to_commit()).ok();
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

pub struct Sha1GitBackend;

impl GitBackend for Sha1GitBackend {
    fn commit_files(
        &self,
        repo_path: &Path,
        file_paths: &[PathBuf],
        commit_message: &str,
    ) -> Result<(), git2::Error> {
        let repo = Repository::open(repo_path)?;
        sha1_commit_files(&repo, repo_path, file_paths, commit_message)
    }
}

/// SHA-256 git backend using the git CLI.
///
/// `libgit2-sys` does not yet ship the `unstable-sha256` feature in a
/// published release, so this backend shells out to `git` (>= 2.42) for
/// staging and committing. It validates the repository uses SHA-256 via
/// `git rev-parse --show-object-format` before every commit.
#[cfg(feature = "sha256")]
pub struct Sha256GitBackend;

#[cfg(feature = "sha256")]
impl Sha256GitBackend {
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

    /// Validate that the repository uses the SHA-256 object format.
    fn validate_sha256(repo_path: &Path) -> Result<(), git2::Error> {
        let format = Self::git(repo_path, &["rev-parse", "--show-object-format"])?;
        if format != "sha256" {
            return Err(git2::Error::from_str(&format!(
                "Sha256GitBackend requires a SHA-256 repository, got '{}'",
                format
            )));
        }
        Ok(())
    }
}

#[cfg(feature = "sha256")]
impl GitBackend for Sha256GitBackend {
    fn commit_files(
        &self,
        repo_path: &Path,
        file_paths: &[PathBuf],
        commit_message: &str,
    ) -> Result<(), git2::Error> {
        Self::validate_sha256(repo_path)?;

        let rel_paths = collect_relative_paths(repo_path, file_paths)?;

        if rel_paths.is_empty() {
            return Err(git2::Error::from_str("No files to commit"));
        }

        // Stage files one at a time via git add
        for rel_path in &rel_paths {
            Self::git(repo_path, &["add", "--", &rel_path.to_string_lossy()])?;
        }

        // Commit with configured author identity
        Self::git(
            repo_path,
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
}

/// Dispatch enum for GitBackend implementations.
///
/// Both backends are zero-size structs, so this enum is `Copy` and can be
/// moved into `spawn_blocking` closures without `Arc`.
#[derive(Debug, Clone, Copy)]
pub enum GitBackendKind {
    Sha1,
    #[cfg(feature = "sha256")]
    Sha256,
}

impl GitBackendKind {
    pub fn commit_files(
        &self,
        repo_path: &Path,
        file_paths: &[PathBuf],
        commit_message: &str,
    ) -> Result<(), git2::Error> {
        match self {
            GitBackendKind::Sha1 => {
                Sha1GitBackend.commit_files(repo_path, file_paths, commit_message)
            }
            #[cfg(feature = "sha256")]
            GitBackendKind::Sha256 => {
                Sha256GitBackend.commit_files(repo_path, file_paths, commit_message)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Signature;
    use tempfile::TempDir;

    struct MockBackend {
        should_fail: bool,
    }

    impl GitBackend for MockBackend {
        fn commit_files(
            &self,
            _repo_path: &Path,
            _file_paths: &[PathBuf],
            _commit_message: &str,
        ) -> Result<(), git2::Error> {
            if self.should_fail {
                Err(git2::Error::from_str("mock failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn test_trait_is_object_safe() {
        let backend: Box<dyn GitBackend> = Box::new(MockBackend { should_fail: false });
        let result = backend.commit_files(
            Path::new("/tmp/test"),
            &[PathBuf::from("/tmp/test/file.txt")],
            "test commit",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_backend_failure() {
        let backend: Box<dyn GitBackend> = Box::new(MockBackend { should_fail: true });
        let result = backend.commit_files(
            Path::new("/tmp/test"),
            &[PathBuf::from("/tmp/test/file.txt")],
            "test commit",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_add_path_recursively_rejects_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path).unwrap();
        let mut index = repo.index().unwrap();

        let target_file = repo_path.join("target.txt");
        std::fs::write(&target_file, "target content").unwrap();

        let symlink_path = repo_path.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target.txt", &symlink_path).unwrap();

        let result = add_path_recursively(&mut index, repo_path, &symlink_path);

        match result {
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("symlink"),
                    "Error message should mention symlink: {}",
                    error_msg
                );
                assert!(
                    error_msg.contains("link.txt"),
                    "Error message should mention path: {}",
                    error_msg
                );
            }
            Ok(_) => panic!("Expected error when encountering symlink but got Ok"),
        }
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

        let result = add_path_recursively(&mut index, repo_path, repo_path);
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

    #[test]
    fn test_sha1_backend_commits_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let repo = init_test_repo(repo_path);

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha1GitBackend;
        let result = backend.commit_files(repo_path, &[file_path], "test commit");
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
    fn test_sha1_backend_rejects_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let _repo = init_test_repo(repo_path);

        let target = repo_path.join("target.txt");
        std::fs::write(&target, "content").unwrap();
        let link = repo_path.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target.txt", &link).unwrap();

        let backend = Sha1GitBackend;
        let result = backend.commit_files(repo_path, &[link], "commit");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("symlink"));
    }

    #[test]
    fn test_sha1_backend_skips_git_directory() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        let repo = init_test_repo(repo_path);

        std::fs::write(repo_path.join("real.txt"), "content").unwrap();

        let backend = Sha1GitBackend;
        let result = backend.commit_files(repo_path, &[repo_path.to_path_buf()], "commit");
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

        let backend = Sha1GitBackend;
        let result = backend.commit_files(
            repo_path,
            &[repo_path.join("a.txt"), repo_path.join("b.txt")],
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

        let backend = Sha1GitBackend;
        let result = backend.commit_files(repo_path, &[repo_path.join("first.txt")], "initial");
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
}

#[cfg(all(test, feature = "sha256"))]
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

    #[test]
    fn test_sha256_backend_commits_file() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "sha256 content").unwrap();

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[file_path], "sha256 commit");
        assert!(result.is_ok(), "SHA-256 commit failed: {:?}", result);

        // Verify via git log
        let log = Sha256GitBackend::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("sha256 commit"));
    }

    #[test]
    fn test_sha256_backend_rejects_sha1_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        git2::Repository::init(repo_path).unwrap(); // SHA-1 repo

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[file_path], "should fail");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("SHA-256"));
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

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[f1, f2], "multi sha256");
        assert!(result.is_ok());

        // Verify both files are committed
        let ls = Sha256GitBackend::git(repo_path, &["ls-tree", "--name-only", "HEAD"]).unwrap();
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

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[subdir.join("file.txt")], "nested sha256");
        assert!(result.is_ok());

        let ls =
            Sha256GitBackend::git(repo_path, &["ls-tree", "-r", "--name-only", "HEAD"]).unwrap();
        assert!(ls.contains("nested/deep/file.txt"));
    }

    #[test]
    fn test_sha256_backend_rejects_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        let target = repo_path.join("target.txt");
        std::fs::write(&target, "content").unwrap();
        let link = repo_path.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target.txt", &link).unwrap();

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[link], "commit");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("symlink"));
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

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[repo_path.join("first.txt")], "initial");
        assert!(result.is_ok());

        let log = Sha256GitBackend::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("initial"));
    }

    #[test]
    fn test_sha256_backend_skips_git_directory() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        std::fs::write(repo_path.join("real.txt"), "content").unwrap();

        let backend = Sha256GitBackend;
        let result = backend.commit_files(repo_path, &[repo_path.to_path_buf()], "commit");
        assert!(result.is_ok());

        let ls =
            Sha256GitBackend::git(repo_path, &["ls-tree", "-r", "--name-only", "HEAD"]).unwrap();
        assert!(!ls.contains(".git"));
        assert!(ls.contains("real.txt"));
    }

    #[test]
    fn test_sha256_backend_kind_dispatch() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();
        init_sha256_repo(repo_path);

        std::fs::write(repo_path.join("dispatch.txt"), "via enum").unwrap();

        let backend = GitBackendKind::Sha256;
        let result = backend.commit_files(
            repo_path,
            &[repo_path.join("dispatch.txt")],
            "enum dispatch",
        );
        assert!(result.is_ok());

        let log = Sha256GitBackend::git(repo_path, &["log", "--oneline", "-1"]).unwrap();
        assert!(log.contains("enum dispatch"));
    }
}
