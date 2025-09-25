pub mod fs;

use sha2::{Digest, Sha512, digest::typenum};
use std::path::Path;

pub fn sha512_for_content(
    content: Vec<u8>,
) -> sha2::digest::generic_array::GenericArray<u8, typenum::consts::U64> {
    Sha512::digest(content)
}

pub fn sha512_for_file<P: AsRef<Path>>(
    path_in: P,
) -> Result<sha2::digest::generic_array::GenericArray<u8, typenum::consts::U64>, std::io::Error> {
    let file_content = std::fs::read(path_in.as_ref())?;
    Ok(sha512_for_content(file_content))
}
