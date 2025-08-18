use minisign;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use signatures::keys::{AsfaloadPublicKey, AsfaloadPublicKeyTrait};
use std::fmt; // Required for minisign::PublicKey::from_base64 and its Error type

// We set a bound in the serde annotation. Here why, as explained by AI:
// Without this bound, we get the error `E0277` "the trait bound `P: _::_serde::Deserialize<'_>` is
// not satisfied" occurs because when `#[derive(Deserialize)]` is used on generic structs like
// `SignersConfig`, `SignerGroup`, and `Signer`, `serde` implicitly adds `P: Deserialize` and `P:
// Serialize` bounds to their generic parameter `P`.
// However, in this design, the actual deserialization and serialization of the generic `P` (which
// represents the public key) is handled manually within the `SignerData<P>`'s custom `impl
// Serialize` and `impl Deserialize` blocks, which only require `P: AsfaloadPublicKeyTrait`. `P`
// itself does not need to implement `serde::Deserialize` or `serde::Serialize` directly.

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub admin_keys: Option<Vec<SignerGroup<P>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialVersion {
    pub permalink: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct SignerGroup<P: AsfaloadPublicKeyTrait> {
    pub signers: Vec<Signer<P>>,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct Signer<P: AsfaloadPublicKeyTrait> {
    pub kind: SignerKind,
    pub data: SignerData<P>, // Specify the concrete type here
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
        let pubkey = P::from_base64(helper.pubkey)
            .map_err(|_e| serde::de::Error::custom(format!("Problem parsing base64")))?;

        Ok(SignerData {
            format: helper.format,
            pubkey,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyFormat {
    Minisign,
}

pub fn parse_signers_config<P: AsfaloadPublicKeyTrait>(
    json_str: &str,
) -> Result<SignersConfig<P>, serde_json::Error> {
    serde_json::from_str(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        let json_str = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTsbRMhBdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyv"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWSNbF6ZeLYJLBOKm8a2QbbSb3U+K4ag1YJENgvRXfKEC6RqICqYF+NE"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "R4DM1NJ1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "R4DM1NL285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "R4DM1NN3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;

        let config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(json_str).expect("Failed to parse JSON");
        assert_eq!(config.version, 1);
        assert_eq!(
            config.initial_version.permalink,
            "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json"
        );
        assert_eq!(config.artifact_signers.len(), 1);
        assert_eq!(config.artifact_signers[0].threshold, 2);
        assert_eq!(config.artifact_signers[0].signers[0].kind, SignerKind::Key);
        assert_eq!(
            config.artifact_signers[0].signers[0].data.format,
            KeyFormat::Minisign
        );

        assert_eq!(config.master_keys.len(), 1);
        assert_eq!(config.master_keys[0].threshold, 2);
        assert_eq!(config.master_keys[0].signers[0].kind, SignerKind::Key);

        assert!(config.admin_keys.is_some());
        assert_eq!(
            config
                .admin_keys
                .as_ref()
                .expect("Should be some as checked earlier")[0]
                .threshold,
            2
        );
        assert_eq!(
            config
                .admin_keys
                .as_ref()
                .expect("Should be some as checked earlier")[0]
                .signers[0]
                .kind,
            SignerKind::Key
        );
    }
}
