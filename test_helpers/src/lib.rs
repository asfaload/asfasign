use signatures::keys::AsfaloadKeyPair;
use signatures::keys::AsfaloadKeyPairTrait;
use signatures::keys::AsfaloadPublicKey;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::keys::AsfaloadSecretKey;
pub struct TestKeys {
    key_pairs: Vec<AsfaloadKeyPair<minisign::KeyPair>>,
    pub_keys: Vec<AsfaloadPublicKey<minisign::PublicKey>>,
    sec_keys: Vec<AsfaloadSecretKey<minisign::SecretKey>>,
}

impl TestKeys {
    pub fn new(n: i8) -> Self {
        let mut r = TestKeys {
            key_pairs: vec![],
            pub_keys: vec![],
            sec_keys: vec![],
        };
        for _ in 1..(n + 1) {
            let key_pair = AsfaloadKeyPair::new("password").unwrap();
            let pub_key = key_pair.public_key();
            let sec_key = key_pair.secret_key("password").unwrap();
            r.key_pairs.push(key_pair);
            r.sec_keys.push(sec_key);
            r.pub_keys.push(pub_key);
        }

        r
    }

    pub fn pub_key(&self, n: usize) -> Option<&AsfaloadPublicKey<minisign::PublicKey>> {
        self.pub_keys.get(n)
    }
    pub fn sec_key(&self, n: usize) -> Option<&AsfaloadSecretKey<minisign::SecretKey>> {
        self.sec_keys.get(n)
    }
    pub fn key_pair(&self, n: usize) -> Option<&AsfaloadKeyPair<minisign::KeyPair>> {
        self.key_pairs.get(n)
    }

    pub fn substitute_keys(&self, tpl: String) -> String {
        self.pub_keys.iter().enumerate().fold(tpl, |t, (i, k)| {
            t.replace(
                format!("PUBKEY{}_PLACEHOLDER", i).as_str(),
                k.to_base64().as_str(),
            )
        })
    }
}
