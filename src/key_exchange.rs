use bytes::{BufMut, BytesMut};
use rand::rngs::OsRng;

use super::error::HandleShakeError;
use super::msg;
use crate::cipher_suites::KeyAgreement;
use crate::{Certificate, VERSION_SSL30};

struct RsaKeyAgreement;

impl KeyAgreement for RsaKeyAgreement {
    fn gen_server_key_exchange(
        cert: &Certificate,
        client_msg: &msg::ClientHelloMsg,
        server_msg: &msg::ServerHelloMsg,
    ) -> Result<Option<msg::ServerHelloMsg>, HandleShakeError> {
        Ok(None)
    }

    fn do_client_key_exchange(
        cert: &Certificate,
        ckx: &msg::ClientKeyExchangeMsg,
        version: u16,
    ) -> Result<Vec<u8>, HandleShakeError> {
        if ckx.ciphertext.len() < 2 {
            return Err(HandleShakeError::ClientKeyExchangeMsgError);
        }
        let mut ciphertext = &ckx.ciphertext[..];
        // when ssl version is 30, the ciphertext contain the length.
        // real ciphertext must remove the length.
        if version == VERSION_SSL30 {
            let ciphertext_len = (ckx.ciphertext[0] as usize) << 8 | ckx.ciphertext[1] as usize;
            if ciphertext_len != ckx.ciphertext.len() - 2 {
                return Err(HandleShakeError::ClientKeyExchangeMsgError);
            }
            ciphertext = &ckx.ciphertext[2..];
        }
        let pre_master_secret = cert.private_key.decrypt(None::<&mut OsRng>, ciphertext)?;
        return Ok(pre_master_secret);
    }

    /// generate client key exchange message
    /// rng is generate the random data.
    fn gen_client_key_exchange<Rng>(
        rng: &mut Rng,
        client_msg: &msg::ClientHelloMsg,
        cert: &Certificate,
    ) -> Result<Option<msg::ClientKeyExchangeMsg>, HandleShakeError>
    where
        Rng: rand_core::CryptoRngCore + Sized,
    {
        let mut pre_master_secret = bytes::BytesMut::new();
        let mut ran = [0u8; 46];
        pre_master_secret.put_u8((client_msg.version >> 8) as u8);
        pre_master_secret.put_u8(client_msg.version as u8);
        rng.try_fill_bytes(&mut ran)
            .map_err(|_| HandleShakeError::UnexpectedError("random fill bytes error"))?;
        pre_master_secret.put_slice(&ran);
        let ciphertext = cert.public_key.encrypt(rng, &ran)?;
        let mut buf = Vec::with_capacity(ciphertext.len() + 2);
        buf.put_u16_ne(ciphertext.len() as u16);
        buf.put(&ciphertext[..]);
        let buf: Vec<_> = buf.into();
        Ok(Some(msg::ClientKeyExchangeMsg { ciphertext: buf }))
    }

    fn do_server_key_exchange(
        cert: &Certificate,
        client_msg: &msg::ClientKeyExchangeMsg,
        version: u16,
    ) -> Result<Vec<u8>, HandleShakeError> {
        Err(HandleShakeError::UnexpectedServerExchangeError)
    }
}
