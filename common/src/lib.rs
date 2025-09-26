pub mod fs;

use sha2::{Digest, Sha512, digest::typenum};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub enum AsfaloadHashes {
    Sha512(sha2::digest::generic_array::GenericArray<u8, typenum::consts::U64>),
}
pub fn sha512_for_content(content: Vec<u8>) -> AsfaloadHashes {
    AsfaloadHashes::Sha512(Sha512::digest(content))
}

pub fn sha512_for_file<P: AsRef<Path>>(path_in: P) -> Result<AsfaloadHashes, std::io::Error> {
    let file = File::open(path_in.as_ref())?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; 8192];
    let mut total_bytes_read = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of file
        }

        total_bytes_read += bytes_read;
        hasher.update(&buffer[..bytes_read]);
    }

    if total_bytes_read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ));
    }
    let result = hasher.finalize();
    Ok(AsfaloadHashes::Sha512(result))
}
