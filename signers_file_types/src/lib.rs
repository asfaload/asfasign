pub mod revocation;
use std::collections::HashSet;

use chrono::{DateTime, Utc};
use common::errors::keys::KeyError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use signatures::keys::AsfaloadPublicKeyTrait;
pub use signatures::keys::KeyFormat;

pub mod errs {
    use common::errors::keys::KeyError;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum SignersConfigError {
        #[error("Key error")]
        IOError(#[from] KeyError),
        #[error("Invalid Signer group")]
        GroupError(String),
    }
}
use errs::SignersConfigError;

// We set a bound in the serde annotation. Here why, as explained by AI:
// Without this bound, we get the error `E0277` "the trait bound `P: _::_serde::Deserialize<'_>` is
// not satisfied" occurs because when `#[derive(Deserialize)]` is used on generic structs like
// `SignersConfig`, `SignerGroup`, and `Signer`, `serde` implicitly adds `P: Deserialize` and `P:
// Serialize` bounds to their generic parameter `P`.
// However, in this design, the actual deserialization and serialization of the generic `P` (which
// represents the public key) is handled manually within the `SignerData<APK>`'s custom `impl
// Serialize` and `impl Deserialize` blocks, which only require `P: AsfaloadPublicKeyTrait`. `P`
// itself does not need to implement `serde::Deserialize` or `serde::Serialize` directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "APK: AsfaloadPublicKeyTrait",
    deserialize = "APK: AsfaloadPublicKeyTrait"
))]
pub struct SignersConfig<APK: AsfaloadPublicKeyTrait> {
    version: u32,
    timestamp: DateTime<Utc>,
    artifact_signers: Vec<SignerGroup<APK>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_keys: Option<Vec<SignerGroup<APK>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    master_keys: Option<Vec<SignerGroup<APK>>>,
}

// Introduced to make fields of SignersConfig private while:
// - limiting changes: no need to edit field names, etc in code where
//   a SignersConfig was constructed
// - keeping the code clear: I first started to require the use of
//   SignersConfig::new with arguments (version, artifact, admin,master),
//   but in the end it was not very readable code because the function arguments don't make it
//   clear which argument is which SignersGroup.
// In the end, rewriting new to take this struct as argument seemed the best solution.
// Apart from requiing the use of accessor to private fields, this does not change much at this time
// but it enables us to add a validation step when building a SignersConfig.
#[derive(Clone)]
pub struct SignersConfigProposal<APK: AsfaloadPublicKeyTrait> {
    pub version: u32,
    pub timestamp: DateTime<Utc>,
    pub artifact_signers: Vec<SignerGroup<APK>>,
    pub admin_keys: Option<Vec<SignerGroup<APK>>>,
    pub master_keys: Option<Vec<SignerGroup<APK>>>,
}

impl<APK> SignersConfigProposal<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    // Implemented so we can call do SignersConfigProposal{...}.build()
    // without having to assign the proposal.
    pub fn build(&self) -> SignersConfig<APK> {
        SignersConfig::new(self.clone())
    }
}
impl<APK> SignersConfig<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    pub fn new(p: SignersConfigProposal<APK>) -> Self {
        Self {
            timestamp: p.timestamp,
            version: p.version,
            artifact_signers: p.artifact_signers,
            master_keys: p.master_keys,
            admin_keys: p.admin_keys,
        }
    }

    // Helper function to create a SignerGroup from pubkeys' string representation.
    fn create_group(
        pubkeys: Vec<APK>,
        threshold: u32,
    ) -> Result<SignerGroup<APK>, errs::SignersConfigError> {
        if pubkeys.is_empty() {
            return Err(errs::SignersConfigError::GroupError(
                "Empty groups cannot be built".to_string(),
            ));
        }
        let signers = pubkeys
            .iter()
            .map(Signer::from_key)
            .collect::<Result<Vec<Signer<APK>>, KeyError>>()?;
        Ok(SignerGroup { signers, threshold })
    }

    pub fn as_proposal(&self) -> SignersConfigProposal<APK> {
        SignersConfigProposal {
            timestamp: self.timestamp,
            version: self.version,
            artifact_signers: self.artifact_signers.clone(),
            master_keys: self.master_keys.clone(),
            admin_keys: self.admin_keys.clone(),
        }
    }

    // Create a SignersConfig with the given public keys as strings and threshold for different groups
    pub fn with_keys(
        version: u32,
        (artifact_signers, artifact_threshold): (Vec<APK>, u32),
        admin_keys: Option<(Vec<APK>, u32)>,
        master_keys: Option<(Vec<APK>, u32)>,
    ) -> Result<Self, SignersConfigError> {
        // Helper function to create a SignerGroup from a vector of public key strings
        // Create the artifact signers group
        let artifact_signers = if artifact_signers.is_empty() {
            vec![]
        } else {
            vec![Self::create_group(artifact_signers, artifact_threshold)?]
        };

        // Create the admin signers group
        let admin_keys = match admin_keys {
            Some((keys, _threshold)) if keys.is_empty() => None,
            Some((keys, threshold)) => Some(vec![Self::create_group(keys, threshold)?]),
            None => None,
        };

        // Create the master signers group
        let master_keys = match master_keys {
            Some((keys, _threshold)) if keys.is_empty() => None,
            Some((keys, threshold)) => Some(vec![Self::create_group(keys, threshold)?]),
            None => None,
        };

        Ok(Self::new(SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version,
            artifact_signers,
            admin_keys,
            master_keys,
        }))
    }

    pub fn with_artifact_signers_only(
        version: u32,
        artifact_signers_and_threshold: (Vec<APK>, u32),
    ) -> Result<Self, SignersConfigError> {
        Self::with_keys(version, artifact_signers_and_threshold, None, None)
    }

    pub fn artifact_signers(&self) -> &[SignerGroup<APK>] {
        &self.artifact_signers
    }
    pub fn admin_keys(&self) -> &[SignerGroup<APK>] {
        match &self.admin_keys {
            Some(v) if !v.is_empty() => v,
            _ => &self.artifact_signers,
        }
    }
    pub fn master_keys(&self) -> Option<Vec<SignerGroup<APK>>> {
        self.master_keys.clone()
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    // Get all signers keys present in the SignersConfig.
    pub fn all_signer_keys(&self) -> HashSet<APK> {
        self.admin_keys()
            .iter()
            .chain(self.master_keys().unwrap_or_default().iter())
            .chain(self.artifact_signers.iter())
            .flat_map(|group| {
                group
                    .signers
                    .iter()
                    .map(|signer| signer.data.pubkey.clone())
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitialVersion {
    pub permalink: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
}
impl Default for InitialVersion {
    fn default() -> Self {
        InitialVersion {
            permalink: "".to_string(),
            mirrors: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(
    serialize = "APK: AsfaloadPublicKeyTrait",
    deserialize = "APK: AsfaloadPublicKeyTrait"
))]
#[derive(Eq, PartialEq)]
pub struct SignerGroup<APK: AsfaloadPublicKeyTrait> {
    pub signers: Vec<Signer<APK>>,
    pub threshold: u32,
}

// Custom deserializer for SignerGroup that validates threshold <= signers.len()
impl<'de, APK> Deserialize<'de> for SignerGroup<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a helper struct that mirrors SignerGroup but without the custom Deserialize
        #[derive(Deserialize)]
        #[serde(bound(deserialize = "APK: AsfaloadPublicKeyTrait"))]
        struct SignerGroupHelper<APK: AsfaloadPublicKeyTrait> {
            signers: Vec<Signer<APK>>,
            threshold: u32,
        }

        // Deserialize into the helper struct
        let helper = SignerGroupHelper::deserialize(deserializer)?;

        // Validate that we have at least one signer
        if helper.signers.is_empty() {
            return Err(serde::de::Error::custom("Group size must be at least 1"));
        }
        // Validate that threshold > 0
        if helper.threshold == 0 {
            return Err(serde::de::Error::custom(format!(
                "Threshold ({}) must be strictly greater than 0",
                helper.threshold,
            )));
        }
        // Validate that threshold <= signers.len()
        if helper.threshold > helper.signers.len() as u32 {
            return Err(serde::de::Error::custom(format!(
                "Threshold ({}) cannot be greater than the number of signers ({})",
                helper.threshold,
                helper.signers.len()
            )));
        }

        // If validation passes, create the actual SignerGroup
        Ok(SignerGroup {
            signers: helper.signers,
            threshold: helper.threshold,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "APK: AsfaloadPublicKeyTrait",
    deserialize = "APK: AsfaloadPublicKeyTrait"
))]
#[derive(Eq, PartialEq)]
pub struct Signer<APK: AsfaloadPublicKeyTrait> {
    pub kind: SignerKind,
    pub data: SignerData<APK>,
}

impl<APK: AsfaloadPublicKeyTrait> Signer<APK> {
    pub fn from_key(pk: &APK) -> Result<Self, KeyError> {
        Ok(Self {
            kind: SignerKind::Key,
            data: SignerData {
                format: pk.key_format(),
                pubkey: pk.clone(),
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignerKind {
    Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerData<APK: AsfaloadPublicKeyTrait> {
    pub format: KeyFormat,
    pub pubkey: APK,
}

impl<APK> Serialize for SignerData<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SignerData", 2)?;
        state.serialize_field("format", &self.format)?;
        // Convert the public key to its string representation using the trait method
        state.serialize_field("pubkey", &self.pubkey.to_base64())?;
        state.end()
    }
}

impl<'de, APK> Deserialize<'de> for SignerData<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SignerDataHelper {
            format: KeyFormat,
            pubkey: String,
        }

        let helper = SignerDataHelper::deserialize(deserializer)?;
        // Parse the public key from string using the trait method
        let pubkey = APK::from_base64(helper.pubkey.clone()).map_err(|_e| {
            serde::de::Error::custom(format!("Problem parsing pubkey base64: {}", helper.pubkey))
        })?;
        Ok(SignerData {
            format: helper.format,
            pubkey,
        })
    }
}

pub fn parse_signers_config<APK: AsfaloadPublicKeyTrait>(
    json_str: &str,
) -> Result<SignersConfig<APK>, serde_json::Error> {
    serde_json::from_str(json_str)
}
