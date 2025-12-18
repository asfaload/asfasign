use std::io::Read;
use std::path::Path;
use zxcvbn::{zxcvbn, Score};
use ClientCliError::PasswordStrengthError;

use crate::error::{ClientCliError, Result};
use features_lib::{SecretKey, SecretKeyTrait, SignatureTrait};
use reqwest::header::{HeaderMap, HeaderValue};
use rest_api_auth::AuthSignature;

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
fn get_unvalidated_password(
    password_arg: Option<String>,
    password_file_arg: Option<&Path>,
    env_var_password: &str,
    env_var_password_file: &str,
    password_confirmation: PasswordConfirmation,
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

    match password_confirmation {
        PasswordConfirmation::RequireConfirmation => {
            eprint!("Confirmation:");
            let password_confirmation = rpassword::read_password().map_err(|e| {
                ClientCliError::InvalidInput(format!("Failed to read password: {}", e))
            })?;

            if password_confirmation == password {
                Ok(password)
            } else {
                Err(ClientCliError::PasswordConfirmationError)
            }
        }
        PasswordConfirmation::WithoutConfirmation => Ok(password),
    }
}

fn validate_password(password: &str) -> Result<String> {
    let estimate = zxcvbn(password, &[]);

    // Check score
    match estimate.score() {
        Score::Zero | Score::One | Score::Two => {
            return Err(PasswordStrengthError("Password is too weak".to_string()))
        }
        // The enum is marked non-exhaustive, so we only match on the weaker ones, the rest is ok
        _ => {}
    }

    // Check warnings
    if let Some(feedback) = estimate.feedback() {
        if let Some(warning) = feedback.warning() {
            return Err(PasswordStrengthError(format!(
                "Password warning: {}",
                warning
            )));
        }
        if !feedback.suggestions().is_empty() {
            for suggestion in feedback.suggestions() {
                eprintln!("  • {}", suggestion);
            }
        }
    }

    Ok(password.to_string())
}
pub enum PasswordConfirmation {
    RequireConfirmation,
    WithoutConfirmation,
}
pub fn get_password(
    password_arg: Option<String>,
    password_file_arg: Option<&Path>,
    env_var_password: &str,
    env_var_password_file: &str,
    prompt_message: &str,
    password_confirmation: PasswordConfirmation,
    accept_weak_password: bool,
) -> Result<String> {
    let unvalidated_password = get_unvalidated_password(
        password_arg,
        password_file_arg,
        env_var_password,
        env_var_password_file,
        password_confirmation,
        prompt_message,
    )?;
    if accept_weak_password {
        Ok(unvalidated_password)
    } else {
        let validated_password = validate_password(unvalidated_password.as_str())?;
        Ok(validated_password)
    }
}

/// Creates authentication headers for REST API requests
///
/// # Arguments
///
/// * `payload` - The JSON payload as a string that will be sent in the request
/// * `secret_key` - The secret key used to sign the authentication data
///
/// # Returns
///
/// A HeaderMap containing the authentication headers:
/// - X-asfld-timestamp: RFC3339 timestamp
/// - X-asfld-nonce: UUID v4
/// - X-asfld-sig: Signature of the auth info
/// - X-asfld-pk: Public key in base64
pub fn create_auth_headers<MSK>(payload: &str, secret_key: SecretKey<MSK>) -> Result<HeaderMap>
where
    SecretKey<MSK>: SecretKeyTrait<SecretKey = MSK>,
    MSK: Clone,
{
    use rest_api_auth::AuthInfo;

    // Create authentication info
    let auth_info = AuthInfo::new(payload.to_string());

    // Create authentication signature
    // Now SecretKey implements SecretKeyTrait, so it should work directly
    // We need to specify the type parameters for AuthSignature
    let auth_signature = AuthSignature::new(auth_info, secret_key)
        .map_err(|e| ClientCliError::AuthError(e.to_string()))?;

    // Create headers
    let mut headers = HeaderMap::new();

    // Add timestamp header
    headers.insert(
        "X-asfld-timestamp",
        HeaderValue::from_str(&auth_signature.auth_info().timestamp().to_rfc3339())
            .map_err(|e| ClientCliError::AuthError(e.to_string()))?,
    );

    // Add nonce header
    headers.insert(
        "X-asfld-nonce",
        HeaderValue::from_str(&auth_signature.auth_info().nonce())
            .map_err(|e| ClientCliError::AuthError(e.to_string()))?,
    );

    // Add signature header
    headers.insert(
        "X-asfld-sig",
        HeaderValue::from_str(&auth_signature.signature().to_base64())
            .map_err(|e| ClientCliError::AuthError(e.to_string()))?,
    );

    // Add public key header
    headers.insert(
        "X-asfld-pk",
        HeaderValue::from_str(&auth_signature.public_key())
            .map_err(|e| ClientCliError::AuthError(e.to_string()))?,
    );

    Ok(headers)
}
