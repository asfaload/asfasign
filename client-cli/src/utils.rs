use ClientCliError::PasswordStrengthError;
use std::io::Read;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::Command;
use zxcvbn::{Score, zxcvbn};

use crate::error::{ClientCliError, Result};
use bishop::BishopArt;
use colored::Colorize;
use common::AsfaloadHashes;

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
    password_command_arg: Option<String>,
    env_var_password: &str,
    env_var_password_file: &str,
    password_confirmation: PasswordConfirmation,
    prompt_message: &str,
) -> Result<String> {
    if let Some(password) = password_arg {
        return Ok(password);
    }

    if let Some(command) = password_command_arg {
        return read_password_from_command(&command);
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
    let password = rpassword::prompt_password(prompt_message)
        .map_err(|e| ClientCliError::InvalidInput(format!("Failed to read password: {}", e)))?;

    match password_confirmation {
        PasswordConfirmation::RequireConfirmation => {
            let password_confirmation =
                rpassword::prompt_password("Confirmation:").map_err(|e| {
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
            return Err(PasswordStrengthError("Password is too weak".to_string()));
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
#[allow(clippy::too_many_arguments)]
pub fn get_password(
    password_arg: Option<String>,
    password_file_arg: Option<&Path>,
    password_command_arg: Option<String>,
    env_var_password: &str,
    env_var_password_file: &str,
    prompt_message: &str,
    password_confirmation: PasswordConfirmation,
    accept_weak_password: bool,
) -> Result<String> {
    let unvalidated_password = get_unvalidated_password(
        password_arg,
        password_file_arg,
        password_command_arg,
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

fn read_password_from_command(command_str: &str) -> Result<String> {
    // shell_words::split handles quotes and escapes properly
    let words = shell_words::split(command_str).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid shell quoting in command: {}", e),
        )
    })?;

    if words.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Command string is empty").into());
    }

    // args[0] is the executable, the rest are arguments
    let output = Command::new(&words[0]).args(&words[1..]).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!("Command failed: {}", stderr.trim())).into());
    }

    let password =
        String::from_utf8(output.stdout).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    Ok(password.trim_end_matches(['\r', '\n']).to_string())
}

pub fn bishop_art(hash: &AsfaloadHashes) -> String {
    let bytes = match hash {
        AsfaloadHashes::Sha512(d) => d.as_slice(),
    };

    // Horizontal and vertical block fractions interleaved by fill level (1/8 steps).
    // At each level horizontal comes first: ▏▁ ▎▂ ▍▃ ▌▄ ▋▅ ▊▆ then ▇█.
    let chars: Vec<char> = " ▏▁▎▂▍▃▌▄▋▅▊▆▇█SE".chars().collect();
    let chr_ln = chars.len();
    let chr_sub_ln = chr_ln as isize - 2;

    let result = BishopArt::new().chain(bytes).result();
    let (w, h) = (result.width(), result.height());
    let field = result.field();

    // Map a raw visit count to a colored string.
    // colored respects NO_COLOR and TTY detection automatically.
    let cell_str = |v: isize| -> String {
        let c = match v {
            -1 => chars[chr_ln - 2], // S
            -2 => chars[chr_ln - 1], // E
            v if v >= 0 && v < chr_sub_ln => chars[v as usize],
            _ => chars[(chr_sub_ln - 1) as usize], // saturated / chr_last
        }
        .to_string();
        // Colors cycle through 6 hue families so no two adjacent visit counts
        // share the same tint: red·blue·green·magenta·cyan·yellow (regular),
        // then the same cycle again in bright variants.
        match v {
            0 => c,
            -1 => c.bright_white().bold().to_string(),
            -2 => c.bright_white().bold().to_string(),
            1 => c.bright_black().to_string(),
            2 => c.red().to_string(),
            3 => c.blue().to_string(),
            4 => c.green().to_string(),
            5 => c.magenta().to_string(),
            6 => c.cyan().to_string(),
            7 => c.yellow().to_string(),
            8 => c.bright_red().to_string(),
            9 => c.bright_blue().to_string(),
            10 => c.bright_green().to_string(),
            11 => c.bright_magenta().to_string(),
            12 => c.bright_cyan().to_string(),
            13 => c.bright_yellow().to_string(),
            _ => c.white().bold().to_string(),
        }
    };

    // Replicate the bishop crate's frame rendering so the borders match exactly.
    let render_frame = |text: &str| -> String {
        let mut s = String::from("+");
        if text.is_empty() {
            s.extend(std::iter::repeat('-').take(w));
        } else {
            let text_ln = text.chars().count();
            let fill = w.saturating_sub(text_ln).saturating_sub(2);
            let dash = fill / 2;
            let pad = fill % 2;
            s.extend(std::iter::repeat('-').take(dash));
            s.push('[');
            s.push_str(text);
            s.push(']');
            s.extend(std::iter::repeat('-').take(dash + pad));
        }
        s.push_str("+\n");
        s
    };

    let mut out = render_frame("SHA512 64");
    for y in 0..h {
        out.push('|');
        for x in 0..w {
            out.push_str(&cell_str(*field.get(x, y)));
        }
        out.push_str("|\n");
    }
    out.push_str(&render_frame(""));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::AsfaloadHashes;
    use sha2::{Digest, Sha512};

    #[test]
    fn bishop_art_contains_framed_borders() {
        let bytes = Sha512::digest(b"deterministic test input");
        let hash = AsfaloadHashes::Sha512(bytes);
        let art = bishop_art(&hash);
        assert!(
            art.contains("+---[SHA512 64]---+"),
            "expected top border with label"
        );
        assert!(art.contains("+"), "expected bottom border");
    }

    #[test]
    fn bishop_art_is_deterministic() {
        let bytes = Sha512::digest(b"same input");
        let hash = AsfaloadHashes::Sha512(bytes);
        assert_eq!(bishop_art(&hash), bishop_art(&hash));
    }
}
