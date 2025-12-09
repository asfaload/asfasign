use std::io::Read;
use std::path::Path;

use crate::error::{ClientCliError, Result};

/// Ensures a directory exists, creating it if necessary
pub fn ensure_dir_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(ClientCliError::Io)?;
    }
    Ok(())
}

/// Validates that a threshold is valid for the given number of keys
pub fn validate_threshold(threshold: u32, key_count: usize) -> Result<()> {
    if threshold == 0 {
        return Err(ClientCliError::InvalidInput(
            "Threshold cannot be zero".to_string(),
        ));
    }

    if threshold as usize > key_count {
        return Err(ClientCliError::InvalidInput(format!(
            "Threshold ({}) cannot be greater than the number of keys ({})",
            threshold, key_count
        )));
    }

    Ok(())
}

/// Reads password from a file
pub fn read_password_from_file(file_path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(file_path).map_err(ClientCliError::Io)?;
    let mut password = String::new();
    file.read_to_string(&mut password)
        .map_err(ClientCliError::Io)?;
    Ok(password.trim_end().to_string())
}

/// Gets password from various sources with the following priority:
/// 1. Direct password argument
/// 2. Password file argument
/// 3. Environment variable ASFALOAD_NEW_KEYS_PASSWORD
/// 4. Environment variable ASFALOAD_NEW_KEYS_PASSWORD_FILE
/// 5. Interactive prompt
pub fn get_password(
    password_arg: Option<String>,
    password_file_arg: Option<&Path>,
    env_var_password: &str,
    env_var_password_file: &str,
    prompt_message: &str,
) -> Result<String> {
    if let Some(password) = password_arg {
        return Ok(password);
    }

    if let Some(file_path) = password_file_arg {
        return read_password_from_file(file_path);
    }

    // Check environment variable for password
    if let Ok(password) = std::env::var(env_var_password) {
        return Ok(password);
    }

    // Check environment variable for password file
    if let Ok(file_path) = std::env::var(env_var_password_file) {
        return read_password_from_file(Path::new(&file_path));
    }

    // If none found, prompt the user
    eprint!("{}", prompt_message);
    let password = rpassword::read_password()
        .map_err(|e| ClientCliError::InvalidInput(format!("Failed to read password: {}", e)))?;

    if password.len() < 8 {
        return Err(ClientCliError::InvalidInput(
            "Password too short".to_string(),
        ));
    }

    eprint!("Confirmation:");
    let password_confirmation = rpassword::read_password()
        .map_err(|e| ClientCliError::InvalidInput(format!("Failed to read password: {}", e)))?;

    if password_confirmation == password {
        Ok(password)
    } else {
        Err(ClientCliError::PasswordConfirmationError)
    }
}
