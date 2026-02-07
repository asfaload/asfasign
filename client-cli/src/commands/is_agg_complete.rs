use crate::error::Result;
use crate::output::IsAggCompleteOutput;

use features_lib::{
    SignedFileLoader,
    aggregate_signature_helpers::{check_groups, get_individual_signatures, load_signers_config},
    sha512_for_file,
};
use std::path::Path;

pub fn handle_is_agg_complete_command<P: AsRef<Path>>(
    signed_file: &P,
    signatures_file: &P,
    signers_file: &P,
    json: bool,
) -> Result<()> {
    // Load the signed file
    let signed_file_with_kind = SignedFileLoader::load(signed_file);

    // Check that we have an artifact file
    if signed_file_with_kind.kind() != features_lib::FileType::Artifact {
        return Err(crate::error::ClientCliError::InvalidInput(
            "This command only works with artifact files".to_string(),
        ));
    }

    // Compute the hash of the file
    let file_hash = sha512_for_file(signed_file)?;

    // Load the signatures
    let signatures = get_individual_signatures(signatures_file)?;

    // Load the signers config
    let signers_config = load_signers_config(signers_file.as_ref())?;

    // Check if the aggregate is complete
    let is_complete = check_groups(signers_config.artifact_signers(), &signatures, &file_hash);

    if json {
        // In JSON mode, always return Ok with the status in the output.
        // Callers check the is_complete field rather than the exit code.
        let output = IsAggCompleteOutput { is_complete };
        println!("{}", serde_json::to_string(&output)?);
        Ok(())
    } else if is_complete {
        println!("Aggregate signature is complete");
        Ok(())
    } else {
        println!("Aggregate signature is not complete");
        Err(crate::error::ClientCliError::AggregateSignatureIncompleteError)
    }
}
