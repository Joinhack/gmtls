mod client_hello_msg;
use client_hello_msg::*;

mod server_hello_msg;
use crate::error::HandleShakeError;
use server_hello_msg::*;

const EXT_TYPE_SVR_NAME: u16 = 0x0;
const EXT_TYPE_STATUS_REQUEST: u16 = 0x5;
const EXT_TYPE_SUPPORTED_CURVES: u16 = 0x0A;
const EXT_TYPE_SUPPORTED_POINTS: u16 = 0x0B;
const EXT_TYPE_SIGNATURE_ALGORITHMS: u16 = 0x0C;
const EXT_TYPE_ALPN: u16 = 0x10;
const EXT_TYPE_SCT: u16 = 0x12;
const EXT_TYPE_SESSION_TICKET: u16 = 0x23;
const EXT_TYPE_NEXT_PROTO_NEG: u16 = 0x3374;
const EXT_TYPE_RENEGOTIATION_INFO: u16 = 0xFF01;

/// rfc3546
const STATUS_TYPE_OCSP: u8 = 1;

struct PosReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

macro_rules! buf_get {
    ($buf: ident, $typ:tt::$conv:tt, true) => {{
        const TYPE_SIZE: usize = std::mem::size_of::<$typ>();
        let mut bs = [0u8; TYPE_SIZE];
        $buf.copy_to_slice(&mut bs);
        $typ::$conv(bs)
    }};
    ($buf: ident, $typ:tt::$conv:tt, false) => {{
        const TYPE_SIZE: usize = std::mem::size_of::<$typ>();
        let mut bs = [0u8; TYPE_SIZE];
        $buf.fill_to_slice(&mut bs);
        $typ::$conv(bs)
    }};
}

impl<'a> PosReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline(always)]
    fn advance(&mut self, pos: usize) {
        self.pos += pos
    }

    #[inline(always)]
    fn remaining(&self) -> usize {
        if self.buf.len() > self.pos {
            self.buf.len() - self.pos
        } else {
            0
        }
    }

    /// copy to slice will copy the buf data to slice with advance the position.
    #[inline(always)]
    pub fn copy_to_slice(&mut self, buf: &mut [u8]) {
        self.fill_to_slice(buf);
        self.advance(buf.len());
    }

    /// fill to slice will copy the buf data to slice without advance the position.
    #[inline(always)]
    fn fill_to_slice(&self, buf: &mut [u8]) {
        let s_idx = self.pos;
        assert!(self.remaining() > buf.len());
        buf.copy_from_slice(&self.buf[s_idx..s_idx + buf.len()]);
    }

    #[inline(always)]
    pub fn get_u8(&mut self) -> u8 {
        let rs = self.buf[self.pos];
        self.advance(1);
        rs
    }

    #[inline(always)]
    pub fn first_u8(&mut self) -> u8 {
        self.buf[self.pos]
    }

    /// get_u16 will read the 2 bytes and advance 2 bytes.
    #[inline(always)]
    pub fn get_u16(&mut self) -> u16 {
        buf_get!(self, u16::from_be_bytes, true)
    }

    pub fn first_u16(&self) -> u16 {
        buf_get!(self, u16::from_be_bytes, false)
    }
}

impl<'a> Clone for PosReader<'a> {
    fn clone(&self) -> Self {
        Self {
            buf: &*self.buf,
            pos: self.pos,
        }
    }
}

pub struct SignatureHash {
    pub hash: u8,
    pub signature: u8,
}

trait HandleShakeDecoder {
    fn decode(buf: &[u8]) -> Result<Self, HandleShakeError>
    where
        Self: Sized;
}

pub struct ServerHelloMsg {}

pub struct ClientHelloMsg {
    pub version: u16,
}

pub struct CertificateMsg {}

pub struct ServerKeyExchangeMsg {}

pub struct ClientKeyExchangeMsg {
    pub ciphertext: Vec<u8>,
}

struct CertificateRequestMsg {}

struct ServerHelloDoneMsg {}

struct ClientHelloDoneMsg {}

struct NewSessionTicketMsg {}

struct ChangeCipherSpecMsg {}

enum HandleShakeMsg {
    ClientHello(ClientHelloMsg),
    ServerHello(ServerHelloMsg),
    CertificateMsg(CertificateMsg),
    ServerKeyExchangeMsg(ServerKeyExchangeMsg),
    ClientKeyExchangeMsg(ClientKeyExchangeMsg),
    ServerHelloDoneMsg(ServerHelloDoneMsg),
    ClientHelloDoneMsg(ClientHelloDoneMsg),
    NewSessionTicketMsg(NewSessionTicketMsg),
    ChangeCipherSpecMsg(ChangeCipherSpecMsg),
}
