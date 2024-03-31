use error::HandleShakeError;
use rsa::{rand_core::CryptoRngCore, RsaPrivateKey, RsaPublicKey};

mod cipher_suites;
pub mod error;
mod key_exchange;
mod msg;
mod tcp_stream;

const VERSION_SSL30: u16 = 0x0300;
const VERSION_SSL10: u16 = 0x0301;
const VERSION_SSL11: u16 = 0x0302;
const VERSION_SSL12: u16 = 0x0303;

enum PrivateKey {
    RsaPrivateKey(RsaPrivateKey),
}

enum PublicKey {
    RsaPublicKey(RsaPublicKey),
}

impl PrivateKey {
    fn decrypt<Rng>(
        &self,
        rng: Option<&mut Rng>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HandleShakeError>
    where
        Rng: CryptoRngCore + Sized,
    {
        match self {
            PrivateKey::RsaPrivateKey(ref rsa_pk) => rsa_pk
                .decrypt(rsa::Pkcs1v15Encrypt, ciphertext)
                .map_err(|_| HandleShakeError::PrivateKeyDecodeError),
        }
    }
}

impl PublicKey {
    pub fn encrypt<Rng>(&self, rng: &mut Rng, text: &[u8]) -> Result<Vec<u8>, HandleShakeError>
    where
        Rng: CryptoRngCore + Sized,
    {
        match self {
            PublicKey::RsaPublicKey(ref rsa_pk) => rsa_pk
                .encrypt(rng, rsa::Pkcs1v15Encrypt, text)
                .map_err(|_| HandleShakeError::PublicKeyEncodeError),
        }
    }
}

pub struct Certificate {
    pub(crate) private_key: PrivateKey,
    pub(crate) public_key: PublicKey,
    // ocspstaple contain an optional ocsp response which will served to
    // clients that request it.
    ocsp_staple: Vec<u8>,

    //signed_certificate_timestamps have the optional list of timestamps
    //which will served to clients that request it.
    signed_certificate_timestamps: Vec<Vec<u8>>,
}

impl Certificate {}

#[cfg(test)]
mod test {
    use rsa::{self, RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_rsa_certificate() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 128).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let ciphertext = public_key
            .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, b"test")
            .unwrap();
        let raw_text = private_key
            .decrypt(rsa::Pkcs1v15Encrypt, &ciphertext[..])
            .unwrap();
        assert_eq!(raw_text, b"test");
    }
}
