use std::{
    collections::HashSet, mem
};
use thiserror::Error;

const EXT_SVR_NAME_TYPE: u16 = 0x0;

#[derive(Error, Debug)]
enum HandleShakeError {
    #[error("parse error")]
    ParserError
}

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
        Self {
            buf,
            pos: 0
        }
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
        buf.copy_from_slice(&self.buf[s_idx..s_idx+buf.len()]);
    }

    #[inline(always)]
    pub fn get_u8(&mut self) -> u8 {
        let rs = self.buf[self.pos];
        self.advance(1);
        rs
    }

    /// get_u16 will read the 2 bytes and advance 2 bytes.
    #[inline(always)]
    pub fn get_u16(&mut self) -> u16 {
        buf_get!(self, u16::from_be_bytes, true)
    }

    pub fn first_u16(&self) -> u16 {
        buf_get!(self, u16::from_be_bytes, false)
    }

    pub fn split(&self) -> (&[u8],&[u8]) {
        if self.pos >= self.buf.len() {
            (&self.buf, &[])
        } else {
            (&self.buf[0..self.pos], &self.buf[self.pos..])
        }
    }
}

trait HandleShakeDecoder {
    fn decode(buf: &[u8]) -> Result<Self, HandleShakeError> where Self: Sized;
}

enum Extension {
    ServerName(String),
}

struct ExtensionParser<'a, 'b> {
    pos_reader: &'b mut PosReader<'a>,
    extensions_len: u16,
}

impl<'a, 'b> ExtensionParser<'a, 'b> {
    fn new(pos_reader: &'b mut PosReader<'a>, extensions_len: u16) -> Self {
        Self {
            pos_reader,
            extensions_len,
        }
    }
    fn parse_server_name(self) -> Result<Option<String>, HandleShakeError> {
        let ext_len = self.extensions_len;
        let name_list_len = self.pos_reader.get_u16();
        if name_list_len + 2 != ext_len {
            return Err(HandleShakeError::ParserError); 
        }
        let mut idx = 0;
        while idx < name_list_len {
            let name_type = self.pos_reader.get_u8();
            let name_len = self.pos_reader.get_u16();
            if name_list_len != 3 + name_len {
                return Err(HandleShakeError::ParserError); 
            }
            idx += 3;
            idx += name_len;
            if name_type == 0 {
                let mut name = vec![0; name_len as _];
                self.pos_reader.copy_to_slice(&mut name);
                let name = unsafe {String::from_utf8_unchecked(name)};
                return Ok(Some(name));
            } else {
                self.pos_reader.advance(name_len as _);
            }
        }
        if idx < name_list_len {
            self.pos_reader.advance((name_list_len - idx) as _);
        }
        return Ok(None);
    }

}

pub struct ClientHelloMsg {
    version: u16,
    random: [u8; 32],
    session_len: u8,
    session_id: Vec<u8>,
    compress_methods: Vec<u8>,
    exensions: Extensions,
}

struct Extensions(Vec<Extension>);

impl Extensions {
    fn new() -> Self {
        Self(Vec::new())
    }
}

struct ExtensionsParser<'a, 'b> {
    pos_reader: &'b mut PosReader<'a>,
}

impl<'a, 'b> ExtensionsParser<'a, 'b> {
    fn new(pos_reader: &'b mut PosReader<'a>) -> Self {
        Self {
            pos_reader
        }
    }

    fn parser(&self) -> Result<Extensions, HandleShakeError> {
        let mut exts = Vec::new();
        let pos_reader = self.pos_reader;
        while pos_reader.remaining() > 0 {
            // the min size of extension is 4, which without data.
            if pos_reader.remaining() < 4 {
                return Err(HandleShakeError::ParserError);
            }
            let ext_type = pos_reader.get_u16();
            let ext_len = pos_reader.get_u16();
            match ext_type {
                EXT_SVR_NAME_TYPE => {
                    let parser = ExtensionParser::new(pos_reader, ext_len);
                    if let Some(svr_name) = parser.parse_server_name()? {
                        exts.push(svr_name);
                    }
                }
                
                _=> {

                }
            }
        }
        todo!();
    }
}

impl ClientHelloMsg {
   
}

impl HandleShakeDecoder for ClientHelloMsg {
    /// parse the client hello package
    fn decode(buf: &[u8]) -> Result<ClientHelloMsg, HandleShakeError> {
        // client hello protocol package min size is 42.
        if buf.len() < 42 {
            return Err(HandleShakeError::ParserError);
        }
        let mut pos_reader = PosReader::new(buf);
        let version = pos_reader.get_u16();
        let mut random = [0u8; 32];
        pos_reader.copy_to_slice(&mut random);
        pos_reader.advance(mem::size_of_val(&random));
        let session_id_len = pos_reader.get_u8() as usize;
        let mut session = vec![0u8; session_id_len];
        pos_reader.copy_to_slice(&mut session);
        if pos_reader.remaining() < 2 {
            return Err(HandleShakeError::ParserError);
        }
        // next 2 bytes is cipher length, if have no data remain, parse fail.
        let cipher_len = pos_reader.get_u16();
        if cipher_len %2 == 1 || cipher_len + 2 > pos_reader.remaining() as _ {
            return Err(HandleShakeError::ParserError);
        }
        let mut ciphers = HashSet::new();
        for _ in 0..cipher_len/2 {
            let cipher = pos_reader.get_u16();
            ciphers.insert(cipher);
        }
        // next 1 bytes is compress methods length, if have no data remain, parse fail.
        if pos_reader.remaining() == 0 {
            return Err(HandleShakeError::ParserError);
        }
        let compress_len = pos_reader.get_u8();
        if compress_len + 1 < pos_reader.remaining() as _ {
            return Err(HandleShakeError::ParserError);
        }
        let mut compresss = vec![0; compress_len as _];
        pos_reader.copy_to_slice(&mut compresss);
        // next 2 bytes is extends length, if have no data remain, parse fail.
        if pos_reader.remaining() < 2 {
            return Err(HandleShakeError::ParserError);
        }
        let exts_len = pos_reader.get_u16();
        if exts_len != pos_reader.remaining() as _ {
            return Err(HandleShakeError::ParserError);
        }
        let exts_parser = ExtensionsParser::new(&mut pos_reader);
        let extensions = exts_parser.parser()?;
        todo!()
    }

}



struct ServerHelloMsg {
}

struct CertificateMsg {
}

struct ServerKeyExchangeMsg {
}

struct ClientKeyExchangeMsg {
}

struct CertificateRequestMsg {
}

struct ServerHelloDoneMsg {
}

struct ClientHelloDoneMsg {
}

struct NewSessionTicketMsg {
}

struct ChangeCipherSpecMsg {
}

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