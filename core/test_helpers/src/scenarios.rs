use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use common::fs::names::pending_signatures_path_for;
use constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
pub fn setup_asfald_project_registered<P: AsRef<Path>>(
    repo_path: P,
    signers_config_json: impl Into<String>,
) -> Result<PathBuf> {
    // Test the scenario where:
    // - There is a pending signers file at ./github.com/asfaload/asfald/asfaload.signers.pending/index.json
    // - There is NO asfaload.signers directory sibling or in parent directories
    // - Only asfaload.signers.history.json exists, which is not a signers directory
    let root = repo_path.as_ref();

    // Create the directory structure:
    // root/
    //   github.com/
    //     asfaload/
    //       asfald/
    //         asfaload.signers.history.json
    //         asfaload.signers.pending/
    //           index.json
    let github_dir = root.join("github.com");
    let asfaload_dir = github_dir.join("asfaload");
    let asfald_dir = asfaload_dir.join("asfald");
    fs::create_dir_all(&asfald_dir)?;

    // Create the history file (this is NOT a signers directory)
    let history_file = asfald_dir.join(SIGNERS_HISTORY_FILE);
    fs::write(&history_file, "{}")?;

    // Create the pending signers directory and file
    let pending_signers_dir = asfald_dir.join(PENDING_SIGNERS_DIR);
    fs::create_dir_all(&pending_signers_dir)?;
    let pending_index_file = pending_signers_dir.join(SIGNERS_FILE);
    fs::write(&pending_index_file, signers_config_json.into())?;
    let pending_signers_sig = pending_signatures_path_for(&pending_index_file)?;
    fs::write(&pending_signers_sig, "{}")?;
    Ok(pending_index_file)
}
