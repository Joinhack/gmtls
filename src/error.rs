use thiserror::Error;

#[derive(Error, Debug)]
pub enum HandleShakeError {
    #[error("parse error")]
    ParserError,

    #[error("generator server key msg error")]
    GenServerKeyMsgError,

    #[error("client key exchange message error")]
    ClientKeyExchangeMsgError,

    #[error("private key decode error")]
    PrivateKeyDecodeError,

    #[error("public key encode error")]
    PublicKeyEncodeError,

    #[error("unexpected server exchange error")]
    UnexpectedServerExchangeError,

    #[error("unexpected error {0}")]
    UnexpectedError(&'static str),
}
