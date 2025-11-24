use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use signatures::keys::KeyFormat;
use signatures::keys::{
    AsfaloadPublicKeyTrait,
    errs::{self, KeyError},
};

// We set a bound in the serde annotation. Here why, as explained by AI:
// Without this bound, we get the error `E0277` "the trait bound `P: _::_serde::Deserialize<'_>` is
// not satisfied" occurs because when `#[derive(Deserialize)]` is used on generic structs like
// `SignersConfig`, `SignerGroup`, and `Signer`, `serde` implicitly adds `P: Deserialize` and `P:
// Serialize` bounds to their generic parameter `P`.
// However, in this design, the actual deserialization and serialization of the generic `P` (which
// represents the public key) is handled manually within the `SignerData<P>`'s custom `impl
// Serialize` and `impl Deserialize` blocks, which only require `P: AsfaloadPublicKeyTrait`. `P`
// itself does not need to implement `serde::Deserialize` or `serde::Serialize` directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct SignersConfig<P: AsfaloadPublicKeyTrait> {
    pub version: u32,
    pub initial_version: InitialVersion,
    pub artifact_signers: Vec<SignerGroup<P>>,
    pub master_keys: Vec<SignerGroup<P>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // FIXME: make private, but causes trouble in tests of aggregate signature definitions
    pub admin_keys: Option<Vec<SignerGroup<P>>>,
}

impl<APK> SignersConfig<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    // Create a new SignersConfig with the SignerGroup parameters
    pub fn new(
        version: u32,
        artifact_signers: Vec<SignerGroup<APK>>,
        master_keys: Vec<SignerGroup<APK>>,
        admin_keys: Option<Vec<SignerGroup<APK>>>,
    ) -> Self
    where
        APK: AsfaloadPublicKeyTrait,
    {
        Self {
            version,
            initial_version: InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers,
            master_keys,
            admin_keys,
        }
    }

    // Helper function to create a SignerGroup from pubkeys' string representation.
    fn create_group(pubkeys: Vec<APK>, threshold: u32) -> Result<SignerGroup<APK>, KeyError>
    where
        APK: AsfaloadPublicKeyTrait,
    {
        if pubkeys.is_empty() {
            return Ok(SignerGroup {
                signers: vec![],
                threshold: 0, // Default threshold when no signers
            });
        }
        let signers = pubkeys
            .iter()
            .map(Signer::from_key)
            .collect::<Result<Vec<Signer<APK>>, KeyError>>()?;
        Ok(SignerGroup { signers, threshold })
    }

    // Create a SignersConfig with the given public keys as strings and threshold for different groups
    pub fn with_keys(
        version: u32,
        (artifact_signers, artifact_threshold): (Vec<APK>, u32),
        (master_keys, master_threshold): (Vec<APK>, u32),
        admin_keys: Option<(Vec<APK>, u32)>,
    ) -> Result<Self, KeyError>
    where
        APK: AsfaloadPublicKeyTrait,
    {
        // Helper function to create a SignerGroup from a vector of public key strings
        // Create the artifact signers group
        let artifact_signers = if artifact_signers.is_empty() {
            vec![]
        } else {
            vec![Self::create_group(artifact_signers, artifact_threshold)?]
        };

        // Create the master signers group
        let master_keys = if master_keys.is_empty() {
            vec![]
        } else {
            vec![Self::create_group(master_keys, master_threshold)?]
        };

        // Create the admin signers group
        let admin_keys = match admin_keys {
            Some((keys, _threshold)) if keys.is_empty() => None,
            Some((keys, threshold)) => Some(vec![Self::create_group(keys, threshold)?]),
            None => None,
        };

        Ok(Self::new(
            version,
            artifact_signers,
            master_keys,
            admin_keys,
        ))
    }

    pub fn admin_keys(&self) -> &Vec<SignerGroup<APK>> {
        match &self.admin_keys {
            Some(v) if !v.is_empty() => v,
            _ => &self.artifact_signers,
        }
    }
    pub fn master_keys(&self) -> &Vec<SignerGroup<APK>> {
        &self.master_keys
    }
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    // Get all signers keys present in the SignersConfig.
    pub fn all_signer_keys(&self) -> HashSet<APK> {
        self.admin_keys()
            .iter()
            .chain(self.master_keys().iter())
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
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
#[derive(Eq, PartialEq)]
pub struct SignerGroup<P: AsfaloadPublicKeyTrait> {
    pub signers: Vec<Signer<P>>,
    pub threshold: u32,
}

// Custom deserializer for SignerGroup that validates threshold <= signers.len()
impl<'de, P> Deserialize<'de> for SignerGroup<P>
where
    P: AsfaloadPublicKeyTrait,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a helper struct that mirrors SignerGroup but without the custom Deserialize
        #[derive(Deserialize)]
        #[serde(bound(deserialize = "P: AsfaloadPublicKeyTrait"))]
        struct SignerGroupHelper<P: AsfaloadPublicKeyTrait> {
            signers: Vec<Signer<P>>,
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
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
#[derive(Eq, PartialEq)]
pub struct Signer<P: AsfaloadPublicKeyTrait> {
    pub kind: SignerKind,
    pub data: SignerData<P>, // Specify the concrete type here
}

impl<P: AsfaloadPublicKeyTrait> Signer<P> {
    pub fn from_key(pk: &P) -> Result<Self, errs::KeyError> {
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
pub struct SignerData<P: AsfaloadPublicKeyTrait> {
    pub format: KeyFormat,
    pub pubkey: P,
}

impl<P> Serialize for SignerData<P>
where
    P: AsfaloadPublicKeyTrait,
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

impl<'de, P> Deserialize<'de> for SignerData<P>
where
    P: AsfaloadPublicKeyTrait,
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
        let pubkey = P::from_base64(helper.pubkey.clone()).map_err(|_e| {
            serde::de::Error::custom(format!("Problem parsing pubkey base64: {}", helper.pubkey))
        })?;
        Ok(SignerData {
            format: helper.format,
            pubkey,
        })
    }
}

pub fn parse_signers_config<P: AsfaloadPublicKeyTrait>(
    json_str: &str,
) -> Result<SignersConfig<P>, serde_json::Error> {
    serde_json::from_str(json_str)
}
