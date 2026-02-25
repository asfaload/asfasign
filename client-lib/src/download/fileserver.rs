use super::ForgeTrait;

pub(super) struct FileServerForge;

impl ForgeTrait for FileServerForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        path.to_string()
    }
}
