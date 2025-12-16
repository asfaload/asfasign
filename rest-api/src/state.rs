use std::path::{Path, PathBuf};

use kameo::actor::{ActorRef, Spawn};

use crate::git_actor::GitActor;

#[derive(Clone)]
pub struct AppState {
    pub git_repo_path: PathBuf,
    pub git_actor: ActorRef<GitActor>,
}

pub fn init_state<P: AsRef<Path>>(git_repo_path_in: P) -> AppState {
    let git_repo_path = git_repo_path_in.as_ref().to_path_buf();
    let git_actor = GitActor::spawn(git_repo_path.clone());
    AppState {
        git_repo_path,
        git_actor,
    }
}
