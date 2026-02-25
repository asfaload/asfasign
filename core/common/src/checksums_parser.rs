use crate::index_types::HashAlgorithm;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedChecksum {
    pub file_name: String,
    pub algo: HashAlgorithm,
    pub hash: String,
}

#[derive(Debug, Error, PartialEq)]
pub enum ChecksumParseError {
    #[error("Invalid line format: {0}")]
    InvalidLineFormat(String),
    #[error("Invalid hex characters in hash: {0}")]
    InvalidHex(String),
    #[error("Unsupported hash length: {0} hex characters")]
    UnsupportedHashLength(usize),
    #[error("Empty content: no checksums found")]
    EmptyContent,
}

/// Detect the hash algorithm based on the length of the hex string.
fn algo_from_hex_length(len: usize) -> Result<HashAlgorithm, ChecksumParseError> {
    match len {
        64 => Ok(HashAlgorithm::Sha256),
        128 => Ok(HashAlgorithm::Sha512),
        _ => Err(ChecksumParseError::UnsupportedHashLength(len)),
    }
}

/// Validate that a string contains only valid hexadecimal characters.
fn validate_hex(hash: &str) -> Result<(), ChecksumParseError> {
    if hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ChecksumParseError::InvalidHex(hash.to_string()))
    }
}

/// Parse the content of a checksums file (sha256sum/sha512sum output format).
///
/// Each non-empty line must match the format: `<hex_hash>  <filename>` or
/// `<hex_hash> *<filename>` (binary mode). The algorithm is detected by the
/// hex hash length: 64 chars = SHA256, 128 chars = SHA512.
///
/// Empty lines are skipped. Any non-matching line produces an error (strict parsing).
/// If the content is empty or contains only empty lines, returns `EmptyContent`.
pub fn parse_checksums(content: &str) -> Result<Vec<ParsedChecksum>, ChecksumParseError> {
    let results: Result<Vec<ParsedChecksum>, ChecksumParseError> = content
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_line)
        .collect();

    let checksums = results?;
    if checksums.is_empty() {
        return Err(ChecksumParseError::EmptyContent);
    }
    Ok(checksums)
}

/// Parse a single non-empty line from a checksums file.
///
/// Expects `<hex_hash><separator><filename>` where separator is either
/// two spaces ("  ") or a space followed by an asterisk (" *").
fn parse_line(line: &str) -> Result<ParsedChecksum, ChecksumParseError> {
    // Try the two valid separators: "  " (text mode) and " *" (binary mode)
    let (hash, file_name) = split_hash_and_filename(line)?;

    validate_hex(hash)?;
    let algo = algo_from_hex_length(hash.len())?;

    Ok(ParsedChecksum {
        file_name: file_name.to_string(),
        algo,
        hash: hash.to_string(),
    })
}

/// Split a checksum line into hash and filename parts.
///
/// The sha256sum/sha512sum format uses either "  " (two spaces) for text mode
/// or " *" (space + asterisk) for binary mode as separators.
fn split_hash_and_filename(line: &str) -> Result<(&str, &str), ChecksumParseError> {
    // Look for "  " (text mode) or " *" (binary mode) after the hash
    for separator in ["  ", " *"] {
        if let Some(pos) = line.find(separator) {
            let hash = &line[..pos];
            let file_name = &line[pos + separator.len()..];
            if !hash.is_empty() && !file_name.is_empty() {
                return Ok((hash, file_name));
            }
        }
    }
    Err(ChecksumParseError::InvalidLineFormat(line.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    const SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA512_HEX: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    #[test]
    fn test_sha256_single_file() -> Result<()> {
        let content = format!("{}  myfile.txt", SHA256_HEX);
        let result = parse_checksums(&content)?;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name, "myfile.txt");
        assert_eq!(result[0].algo, HashAlgorithm::Sha256);
        assert_eq!(result[0].hash, SHA256_HEX);
        Ok(())
    }

    #[test]
    fn test_sha512_single_file() -> Result<()> {
        let content = format!("{}  largefile.bin", SHA512_HEX);
        let result = parse_checksums(&content)?;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name, "largefile.bin");
        assert_eq!(result[0].algo, HashAlgorithm::Sha512);
        assert_eq!(result[0].hash, SHA512_HEX);
        Ok(())
    }

    #[test]
    fn test_multiple_files() -> Result<()> {
        let content = format!("{}  file1.txt\n{}  file2.txt", SHA256_HEX, SHA256_HEX);
        let result = parse_checksums(&content)?;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].file_name, "file1.txt");
        assert_eq!(result[1].file_name, "file2.txt");
        Ok(())
    }

    #[test]
    fn test_binary_mode_marker() -> Result<()> {
        let content = format!("{} *binary.bin", SHA256_HEX);
        let result = parse_checksums(&content)?;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name, "binary.bin");
        assert_eq!(result[0].algo, HashAlgorithm::Sha256);
        assert_eq!(result[0].hash, SHA256_HEX);
        Ok(())
    }

    #[test]
    fn test_empty_lines_skipped() -> Result<()> {
        let content = format!("\n{}  file.txt\n\n", SHA256_HEX);
        let result = parse_checksums(&content)?;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name, "file.txt");
        Ok(())
    }

    #[test]
    fn test_mixed_algorithms() -> Result<()> {
        let content = format!(
            "{}  sha256file.txt\n{}  sha512file.txt",
            SHA256_HEX, SHA512_HEX
        );
        let result = parse_checksums(&content)?;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].algo, HashAlgorithm::Sha256);
        assert_eq!(result[1].algo, HashAlgorithm::Sha512);
        Ok(())
    }

    #[test]
    fn test_invalid_hex_error() {
        let content = "zzzze44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  file.txt";
        match parse_checksums(content) {
            Err(ChecksumParseError::InvalidHex(bad_hex)) => {
                assert!(bad_hex.contains('z'));
            }
            Err(e) => panic!("Expected InvalidHex error, got: {}", e),
            Ok(_) => panic!("Expected InvalidHex error, got Ok"),
        }
    }

    #[test]
    fn test_unsupported_hash_length_error() {
        // 32 hex chars (too short for any supported algorithm)
        let content = "e3b0c44298fc1c149afbf4c8996fb924  file.txt";
        match parse_checksums(content) {
            Err(ChecksumParseError::UnsupportedHashLength(len)) => {
                assert_eq!(len, 32);
            }
            Err(e) => panic!("Expected UnsupportedHashLength error, got: {}", e),
            Ok(_) => panic!("Expected UnsupportedHashLength error, got Ok"),
        }
    }

    #[test]
    fn test_malformed_line_error() {
        let content = "not-a-valid-checksum-line";
        match parse_checksums(content) {
            Err(ChecksumParseError::InvalidLineFormat(line)) => {
                assert_eq!(line, "not-a-valid-checksum-line");
            }
            Err(e) => panic!("Expected InvalidLineFormat error, got: {}", e),
            Ok(_) => panic!("Expected InvalidLineFormat error, got Ok"),
        }
    }

    #[test]
    fn test_empty_content_error() {
        match parse_checksums("") {
            Err(ChecksumParseError::EmptyContent) => {}
            Err(e) => panic!("Expected EmptyContent error, got: {}", e),
            Ok(_) => panic!("Expected EmptyContent error, got Ok"),
        }
    }

    #[test]
    fn test_only_empty_lines_error() {
        match parse_checksums("\n\n\n") {
            Err(ChecksumParseError::EmptyContent) => {}
            Err(e) => panic!("Expected EmptyContent error, got: {}", e),
            Ok(_) => panic!("Expected EmptyContent error, got Ok"),
        }
    }
}
