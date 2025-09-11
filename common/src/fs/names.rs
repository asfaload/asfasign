use std::path::PathBuf;

// FIXME: we could improve this by reusing defined const in furture consts,
// but it seems too much of a burden at this time.
// We might want to look at https://crates.io/crates/constcat
pub const PENDING_SUFFIX: &str = "pending";

pub const SIGNATURES_SUFFIX: &str = "signatures.json";
pub const PENDING_SIGNATURES_SUFFIX: &str = "signatures.json.pending";
pub const SIGNERS_DIR: &str = "asfaload.signers";
pub const PENDING_SIGNERS_DIR: &str = "asfaload.signers.pending";
pub const SIGNERS_FILE: &str = "index.json";

pub fn signatures_path_for(file_path: PathBuf) -> Result<PathBuf, std::io::Error> {
    if !file_path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Input path is not a file",
        ));
    }

    // FIXME: how could this happen?
    let _file_name = file_path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Input path has no file name",
        )
    })?;

    let signatures_path = file_path.with_file_name(format!(
        "{}.{}",
        file_path.to_string_lossy(),
        SIGNATURES_SUFFIX
    ));
    Ok(signatures_path)
}

#[cfg(test)]
mod asfaload_index_tests {

    use std::str::FromStr;

    use anyhow::Result;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    #[test]
    fn test_signature_path_for() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "My data")?;
        let input_path = file.path().to_path_buf();
        let expected_str = format!(
            "{}.{}",
            input_path.clone().into_os_string().to_string_lossy(),
            SIGNATURES_SUFFIX
        );
        let expected_path = PathBuf::from_str(&expected_str)?;
        let signatures_path = signatures_path_for(input_path)?;
        assert_eq!(signatures_path, expected_path);

        let input_path = TempDir::new().unwrap().path().to_path_buf();
        let res = signatures_path_for(input_path);
        assert!(res.is_err());
        let error = res.err().unwrap();
        assert_eq!(error.to_string(), "Input path is not a file");

        Ok(())
    }
}
