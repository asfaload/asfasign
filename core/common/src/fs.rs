use std::path::Path;

pub mod names;

// Helper to safely create new files. The check of existence and the creation is atomic.
pub fn open_new_file<P: AsRef<Path>>(path_in: P) -> Result<std::fs::File, std::io::Error> {
    let path = path_in.as_ref();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}
