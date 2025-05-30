use crate::transport::Transport;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::rc::Rc;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Session {
    raw: Box<dyn Transport>,
    keypair: Rc<KeyPair>,
}

struct clientHello {
    public: [u8; PUBLIC_KEY_LENGTH],
}

impl Session {
    pub async fn client_handshake(
        stream: Box<dyn Transport>,
        keypair: Rc<KeyPair>,
    ) -> anyhow::Result<Self> {
        let ephemeral_private = EphemeralSecret::random();
        let ephemeral_public = PublicKey::from(&ephemeral_private);
        let mut hasher = Sha256::new();
        hasher.update(ephemeral_public);

        Ok(Session {
            raw: stream,
            keypair: keypair,
        })
    }
    pub async fn server_handshake(stream: Box<dyn Transport>) -> anyhow::Result<Self> {
        Ok(Session { raw: stream })
    }
}

pub struct KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
impl KeyPair {
    pub fn print(&self) {
        print!(
            "PublicKey: {}\nPrivateKey: {}",
            self.private_key(),
            self.public_key(),
        )
    }
    pub fn private_key(&self) -> String {
        base64.encode(self.private)
    }
    pub fn public_key(&self) -> String {
        base64.encode(self.public)
    }

    pub fn from_string(public_key: &str, private_key: &str) -> anyhow::Result<KeyPair> {
        let public_vec = base64.decode(public_key)?;
        let private_vec = base64.decode(private_key)?;
        let public = vec_to_array::<PUBLIC_KEY_LENGTH>(public_vec)?;
        let private = vec_to_array::<SECRET_KEY_LENGTH>(private_vec)?;
        Ok(KeyPair { private, public })
    }
}

fn vec_to_array<const N: usize>(v: Vec<u8>) -> anyhow::Result<[u8; N]> {
    let r = v.try_into();
    match r {
        Ok(a) => Ok(a),
        Err(e) => Err(anyhow::anyhow!(
            "key length is mismatch: expect {} got {}",
            N,
            e.len()
        )),
    }
}

pub fn generate_secret() -> KeyPair {
    let mut rng = OsRng;
    let private_key = SigningKey::generate(&mut rng);
    let public_key = VerifyingKey::from(&private_key);

    KeyPair {
        private: private_key.to_bytes(),
        public: public_key.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generate() {
        let secret = generate_secret();
        secret.print();
        assert_eq!(32, secret.private.len());
        assert_eq!(32, secret.public.len());
        let parsed = KeyPair::from_string(&secret.public_key(), &secret.private_key()).unwrap();
        assert_eq!(secret.private, parsed.private);
        assert_eq!(secret.public, parsed.public);
    }
}
