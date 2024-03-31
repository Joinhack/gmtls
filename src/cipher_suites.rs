use crate::{
    error::HandleShakeError,
    msg::{ClientHelloMsg, ClientKeyExchangeMsg, ServerHelloMsg},
    Certificate,
};

const TLS_RSA_WITH_RC4_128_SHA: u16 = 0x0005;
const TLS_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x000a;
const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: u16 = 0xc007;
const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
const TLS_ECDHE_RSA_WITH_RC4_128_SHA: u16 = 0xc011;
const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc012;
const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305: u16 = 0xcca8;
const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: u16 = 0xcca9;

// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
// that the client is doing version fallback. See
// https://tools.ietf.org/html/rfc7507.
const TLS_FALLBACK_SCSV: u16 = 0x5600;

struct CipherSuite {
    id: u16,
    key_len: u32,
    mac_len: u32,
    iv_len: u32,
}

pub trait KeyAgreement {
    fn gen_server_key_exchange(
        cert: &Certificate,
        client_msg: &ClientHelloMsg,
        server_msg: &ServerHelloMsg,
    ) -> Result<Option<ServerHelloMsg>, HandleShakeError>;
    fn do_client_key_exchange(
        cert: &Certificate,
        client_msg: &ClientKeyExchangeMsg,
        version: u16,
    ) -> Result<Vec<u8>, HandleShakeError>;
    fn gen_client_key_exchange<Rng: rand_core::CryptoRngCore + Sized>(
        rng: &mut Rng,
        client_msg: &ClientHelloMsg,
        cert: &Certificate,
    ) -> Result<Option<ClientKeyExchangeMsg>, HandleShakeError>;
    fn do_server_key_exchange(
        cert: &Certificate,
        client_msg: &ClientKeyExchangeMsg,
        version: u16,
    ) -> Result<Vec<u8>, HandleShakeError>;
}

const CIPHER_SUITES: &[CipherSuite] = &[CipherSuite {
    id: TLS_RSA_WITH_RC4_128_SHA,
    key_len: 16,
    mac_len: 20,
    iv_len: 0,
}];
