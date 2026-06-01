use super::ForgesPathMethods;

pub(super) struct FileServerForge;

impl ForgesPathMethods for FileServerForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        path.to_string()
    }
}
