use signatures::keys::AsfaloadKeyPairTrait;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::types::AsfaloadKeyPairs;
use signatures::types::AsfaloadPublicKeys;
use signatures::types::AsfaloadSecretKeys;
pub struct TestKeys {
    key_pairs: Vec<AsfaloadKeyPairs>,
    pub_keys: Vec<AsfaloadPublicKeys>,
    sec_keys: Vec<AsfaloadSecretKeys>,
}

impl TestKeys {
    pub fn new(n: usize) -> Self {
        let mut r = TestKeys {
            key_pairs: Vec::with_capacity(n),
            pub_keys: Vec::with_capacity(n),
            sec_keys: Vec::with_capacity(n),
        };
        for _ in 0..n {
            let key_pair = AsfaloadKeyPairs::new("password").unwrap();
            let pub_key = key_pair.public_key();
            let sec_key = key_pair.secret_key("password").unwrap();
            r.key_pairs.push(key_pair);
            r.sec_keys.push(sec_key);
            r.pub_keys.push(pub_key);
        }

        r
    }

    pub fn pub_key(&self, n: usize) -> Option<&AsfaloadPublicKeys> {
        self.pub_keys.get(n)
    }
    pub fn sec_key(&self, n: usize) -> Option<&AsfaloadSecretKeys> {
        self.sec_keys.get(n)
    }
    pub fn key_pair(&self, n: usize) -> Option<&AsfaloadKeyPairs> {
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

pub fn pause() {
    let mut s = "".to_string();
    println!("Pausing test, press enter when done");
    let _ = std::io::stdin().read_line(&mut s);
}
