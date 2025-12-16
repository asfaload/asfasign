use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use log::{error, info};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct CommitFile {
    pub file_path: PathBuf,
    pub commit_message: String,
}

pub struct GitActor {
    repo_path: PathBuf,
}

impl GitActor {
    pub fn new(repo_path: PathBuf) -> Self {
        info!("GitActor created with repo path: {:?}", repo_path);
        Self { repo_path }
    }
    async fn commit_file(&self, file_path: &PathBuf, commit_message: &str) -> Result<(), String> {
        info!(
            "Attempting to commit file: {:?} with message: {}",
            file_path, commit_message
        );
        let repo_path = self.repo_path.clone();
        let file_path = file_path.clone();
        let commit_message = commit_message.to_string();

        tokio::task::spawn_blocking(move || {
            // Add the file
            let output = Command::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("add")
                .arg("--")
                .arg(&file_path)
                .output()
                .map_err(|e| format!("Failed to execute git add: {}", e))?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Git add failed: {}", error_msg);
                return Err(format!("Git add failed: {}", error_msg));
            }

            // Commit the changes
            let output = Command::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("commit")
                .arg("-m")
                .arg(commit_message)
                .output()
                .map_err(|e| format!("Failed to execute git commit: {}", e))?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Git commit failed: {}", error_msg);
                return Err(format!("Git commit failed: {}", error_msg));
            }

            info!("Successfully committed file: {:?}", file_path);
            Ok(())
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }
}
// GitActor implements Message<CommitFile> - the actor handles CommitFile messages
impl Message<CommitFile> for GitActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        msg: CommitFile,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        info!(
            "GitActor received commit request for file: {:?}",
            msg.file_path
        );
        info!("Commit message: {}", msg.commit_message);

        // Make the file path relative to the git repo
        let relative_path = msg
            .file_path
            .strip_prefix(&self.repo_path)
            .map_err(|e| format!("Failed to make path relative: {}", e))?;

        self.commit_file(&relative_path.to_path_buf(), &msg.commit_message)
            .await
    }
}

// Implement Actor trait with required associated types and methods
impl Actor for GitActor {
    type Args = PathBuf;
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        info!("GitActor starting with repo path: {:?}", args);
        Ok(Self::new(args))
    }
}
