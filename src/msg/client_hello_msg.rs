use std::collections::HashSet;

use super::{
    HandleShakeError, PosReader, SignatureHash, STATUS_TYPE_OCSP,
    EXT_TYPE_SVR_NAME, EXT_TYPE_STATUS_REQUEST,EXT_TYPE_SUPPORTED_CURVES,
    EXT_TYPE_SUPPORTED_POINTS, EXT_TYPE_SIGNATURE_ALGORITHMS, EXT_TYPE_ALPN,
    EXT_TYPE_SCT,EXT_TYPE_SESSION_TICKET, EXT_TYPE_NEXT_PROTO_NEG, EXT_TYPE_RENEGOTIATION_INFO
};

pub struct ClientHelloMsg {
    version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    compress_methods: Vec<u8>,
    extensions: ClientHelloExtensions,
}

type CurveIdType = u16;

#[derive(Default)]
struct ClientHelloExtensions {
    server_name: Option<String>,
    next_proto_neg: bool,
    ocsp_stapling: bool,
    supported_curves: Option<Vec<CurveIdType>>,
    supported_points: Option<Vec<u8>>,
    session_ticket: Option<Vec<u8>>,
    signature_algorithms: Option<Vec<SignatureHash>>,
    alpn: Option<Vec<u8>>,
    secure_renegotiation: Option<Vec<u8>>,
    scts: bool,
}


struct ExtParser<'a, 'b> {
    pos_reader: &'b mut PosReader<'a>,
    extension_len: u16,
}

impl<'a, 'b> ExtParser<'a, 'b> {
    fn new(pos_reader: &'b mut PosReader<'a>, extension_len: u16) -> Self {
        Self {
            pos_reader,
            extension_len,
        }
    }

    fn parse_server_name(self) -> Result<Option<String>, HandleShakeError> {
        let ext_len = self.extension_len;
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

    /// http://tools.ietf.org/html/rfc4492#section-5.1.1
    fn parse_supported_curves(self) -> Result<Vec<CurveIdType>, HandleShakeError> {
        if self.extension_len < 2 {
            return Err(HandleShakeError::ParserError);
        }
        let len = self.pos_reader.get_u16();
        if len % 2 == 1 || self.extension_len != len + 2 {
            return Err(HandleShakeError::ParserError);
        }
        Ok((0..(len / 2))
            .map(|_| self.pos_reader.get_u16())
            .collect::<Vec<_>>())
    }

    /// http://tools.ietf.org/html/rfc4492#section-5.1.2
    fn parse_supported_points(self) -> Result<Vec<u8>, HandleShakeError> {
        if self.extension_len < 2 {
            return Err(HandleShakeError::ParserError);
        }
        let len = self.pos_reader.get_u16();
        if len + 2 != self.extension_len {
            return Err(HandleShakeError::ParserError);
        }
        let mut points = vec![0u8; len as _];
        self.pos_reader.copy_to_slice(&mut points);
        Ok(points)
    }

    fn parse_renegotiation_info(self) -> Result<Vec<u8>, HandleShakeError> {
        if self.extension_len == 0 {
            return Err(HandleShakeError::ParserError); 
        }
        let len = self.pos_reader.get_u8();
        if len + 1 != self.extension_len as _ {
            return Err(HandleShakeError::ParserError); 
        }
        let mut data = vec![0u8; len as _];
        self.pos_reader.copy_to_slice(&mut data[..]);
        Ok(data)
    }


    fn parse_signature_algorithms(self) -> Result<Vec<SignatureHash>, HandleShakeError> {
        if self.extension_len < 2 {
            return Err(HandleShakeError::ParserError);
        }
        let len = self.pos_reader.get_u16();
        if len + 2 != self.extension_len || len % 2 != 0 {
            return Err(HandleShakeError::ParserError);
        }
        let n = len / 2;
        Ok((0..n).map(|_| SignatureHash {
            hash: self.pos_reader.get_u8(),
            signature: self.pos_reader.get_u8(),
        }).collect::<Vec<_>>())
    }

    /// https://datatracker.ietf.org/doc/html/rfc7301#page-3
    fn parse_alpn(self) -> Result<Vec<u8>, HandleShakeError> {
        if self.extension_len < 2 {
            return Err(HandleShakeError::ParserError);
        }
        let len = self.pos_reader.get_u16();
        if len + 2 != self.extension_len {
            return Err(HandleShakeError::ParserError);
        }
        let mut pos = 0;
        let mut alpn = vec![];
        let mut buf = [0u8; 256];
        while pos < len {
            pos += 1;
            let str_len = self.pos_reader.get_u8() as usize;
            if str_len > self.pos_reader.remaining() {
                return Err(HandleShakeError::ParserError);   
            }
            let b = &mut buf[0..str_len];
            self.pos_reader.copy_to_slice(b);
            alpn.extend_from_slice(b);
        }
        Ok(alpn)
    }

}

struct ClientHelloExtensionsParser<'a, 'b> {
    pos_reader: &'b mut PosReader<'a>,
}

impl<'a, 'b> ClientHelloExtensionsParser<'a, 'b> {
    fn new(pos_reader: &'b mut PosReader<'a>) -> Self {
        Self {
            pos_reader,
        }
    }

    fn parser(&mut self) -> Result<ClientHelloExtensions, HandleShakeError> {
        let mut client_hello_ext = ClientHelloExtensions::default();
        loop {
            let remaining = self.pos_reader.remaining();
            if remaining == 0 {
                break;
            }
            // the min size of extension is 4, which without data.
            if remaining < 4 {
                return Err(HandleShakeError::ParserError);
            }
            let ext_type = self.pos_reader.get_u16();
            let ext_len = self.pos_reader.get_u16();
            macro_rules! parse_extension {
                ($ex: tt) => {{
                    let parser = ExtParser::new(&mut self.pos_reader, ext_len);
                    Some(parser.$ex()?)
                }};
            }
            match ext_type {
                EXT_TYPE_SVR_NAME => {
                    let parser = ExtParser::new(&mut self.pos_reader, ext_len);
                    if let Some(svr_name) = parser.parse_server_name()? {
                        client_hello_ext.server_name = Some(svr_name);
                    }
                }
                EXT_TYPE_NEXT_PROTO_NEG => {
                    if ext_len > 0 {
                        return Err(HandleShakeError::ParserError); 
                    }
                    client_hello_ext.next_proto_neg = true;
                }
                EXT_TYPE_STATUS_REQUEST => {
                    client_hello_ext.ocsp_stapling = if ext_len > 0 {
                        self.pos_reader.first_u8() == STATUS_TYPE_OCSP
                    } else {
                        false
                    };
                    self.pos_reader.advance(ext_len as _);
                }
                EXT_TYPE_SESSION_TICKET => {
                    //https://datatracker.ietf.org/doc/html/rfc5077#section-3.2
                    let mut ticket = vec![0;ext_len as _];
                    self.pos_reader.copy_to_slice(&mut ticket);
                    client_hello_ext.session_ticket = Some(ticket);
                }
                EXT_TYPE_SUPPORTED_CURVES => {
                    client_hello_ext.supported_curves = parse_extension!(parse_supported_curves);
                }
                EXT_TYPE_SUPPORTED_POINTS => {
                    client_hello_ext.supported_points = parse_extension!(parse_supported_points);
                }
                EXT_TYPE_SIGNATURE_ALGORITHMS => {
                    client_hello_ext.signature_algorithms = parse_extension!(parse_signature_algorithms);
                }
                EXT_TYPE_ALPN => {
                    client_hello_ext.alpn = parse_extension!(parse_alpn);
                }
                EXT_TYPE_RENEGOTIATION_INFO => {
                    client_hello_ext.secure_renegotiation = parse_extension!(parse_renegotiation_info);
                }
                EXT_TYPE_SCT => {
                    if ext_len != 0 {
                        return Err(HandleShakeError::ParserError); 
                    }
                    client_hello_ext.scts = true;
                }
                
                _=> {
                    self.pos_reader.advance(ext_len as _)
                }
            }
        }
        Ok(client_hello_ext)
    }
}

struct ClientHelloMsgParser<'a, 'b> {
    pos_reader: &'b mut PosReader<'a>
}

impl<'a, 'b> ClientHelloMsgParser<'a, 'b> {

    pub fn new(pos_reader: &'b mut PosReader<'a>) -> Self {
        Self {
            pos_reader
        }
    }

    /// parse the client hello package
    pub fn parse(self) -> Result<ClientHelloMsg, HandleShakeError> {
        // client hello protocol package min size is 42.
        if self.pos_reader.remaining() < 42 {
            return Err(HandleShakeError::ParserError);
        }
        let pos_reader = self.pos_reader;
        let version = pos_reader.get_u16();
        let mut random = [0u8; 32];
        pos_reader.copy_to_slice(&mut random);
        let session_id_len = pos_reader.get_u8() as usize;
        let mut session_id = vec![0u8; session_id_len];
        pos_reader.copy_to_slice(&mut session_id);
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
        if compress_len + 1 > pos_reader.remaining() as _ {
            return Err(HandleShakeError::ParserError);
        }
        let mut compress_methods = vec![0; compress_len as _];
        pos_reader.copy_to_slice(&mut compress_methods);
        // next 2 bytes is extends length, if have no data remain, parse fail.
        if pos_reader.remaining() < 2 {
            return Err(HandleShakeError::ParserError);
        }
        let exts_len = pos_reader.get_u16();
        if exts_len != pos_reader.remaining() as _ {
            return Err(HandleShakeError::ParserError);
        }
        let mut exts_parser = ClientHelloExtensionsParser::new(pos_reader);
        let extensions = exts_parser.parser()?;
        Ok(ClientHelloMsg {
            version,
            random,
            session_id,
            compress_methods,
            extensions,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_client_hello_parse() {
        const packet: &[u8] = &[
            0x03, 0x03, 0xe4, 0x93, 0x51, 0x02, 0x7a,
            0x33, 0x16, 0xcb, 0x67, 0x6c, 0x6a, 0xb8, 0x43,
            0x48, 0x99, 0xb7, 0x0a, 0xd1, 0xc1, 0x5d, 0xfe,
            0x71, 0x7f, 0xa7, 0x3d, 0x3b, 0xe5, 0x85, 0x00,
            0x5d, 0x98, 0x35, 0x20, 0x04, 0xbd, 0xc5, 0x90,
            0x90, 0x1b, 0x04, 0xac, 0x38, 0x07, 0x7e, 0x6e,
            0xa3, 0x1b, 0x21, 0x21, 0x5f, 0x7e, 0x24, 0x1d,
            0x2c, 0xa4, 0x3f, 0xde, 0xe7, 0xe0, 0x1e, 0xe5,
            0xaa, 0x12, 0xe5, 0x89, 0x00, 0x20, 0x8a, 0x8a,
            0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b,
            0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9,
            0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c,
            0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00,
            0x01, 0xe2, 0xea, 0xea, 0x00, 0x00, 0x00, 0x17,
            0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
            0xaa, 0xaa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
            0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03,
            0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
            0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x00, 0x33,
            0x00, 0x2b, 0x00, 0x29, 0xaa, 0xaa, 0x00, 0x01,
            0x00, 0x00, 0x1d, 0x00, 0x20, 0xcc, 0xc9, 0xc4,
            0xa9, 0xd4, 0xf6, 0xcf, 0x0f, 0x6a, 0xb0, 0x23,
            0x16, 0xc8, 0x08, 0x80, 0x67, 0x08, 0x23, 0xe5,
            0xdd, 0x72, 0xa6, 0x48, 0xec, 0x72, 0x83, 0xae,
            0xac, 0x82, 0x24, 0xea, 0x69, 0x00, 0x00, 0x00,
            0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c, 0x73, 0x73,
            0x6f, 0x2e, 0x6b, 0x6f, 0x61, 0x6c, 0x2e, 0x63,
            0x6f, 0x6d, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00,
            0x02, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x2b, 0x00, 0x07, 0x06, 0xea,
            0xea, 0x03, 0x04, 0x03, 0x03, 0x00, 0x10, 0x00,
            0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68,
            0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00,
            0x12, 0x00, 0x00, 0x44, 0x69, 0x00, 0x05, 0x00,
            0x03, 0x02, 0x68, 0x32, 0xfe, 0x0d, 0x01, 0x1a,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x5e, 0x00, 0x20,
            0xa2, 0xd7, 0x11, 0x6a, 0xe6, 0xeb, 0xdc, 0x7c,
            0x0c, 0x5d, 0xff, 0x01, 0x46, 0xad, 0x3e, 0x89,
            0xa7, 0xe0, 0x3a, 0x76, 0x73, 0xcb, 0x62, 0x5d,
            0xaf, 0x04, 0xab, 0x6b, 0x6c, 0xd3, 0x06, 0x7c,
            0x00, 0xf0, 0x7f, 0x8d, 0x56, 0x76, 0xa9, 0xe5,
            0xeb, 0xa2, 0xca, 0x61, 0x33, 0x43, 0xb2, 0xdb,
            0x72, 0xdc, 0xea, 0xf7, 0xc3, 0x88, 0x08, 0x73,
            0xdc, 0xa0, 0xe5, 0xd9, 0x6f, 0x29, 0xf0, 0x2a,
            0x2f, 0x3e, 0x47, 0xc9, 0x95, 0x68, 0xd3, 0x60,
            0x98, 0xf0, 0xde, 0xeb, 0x6c, 0x47, 0x32, 0xdf,
            0xce, 0xc7, 0x94, 0x02, 0x14, 0x07, 0xbc, 0x7f,
            0x15, 0x41, 0x35, 0x9d, 0x7c, 0x97, 0xdc, 0xb8,
            0x1b, 0xe2, 0x2f, 0x15, 0x57, 0x7f, 0xf7, 0xc1,
            0x2b, 0x2e, 0x5d, 0x0b, 0x33, 0x21, 0x38, 0xc0,
            0xfd, 0x38, 0xb3, 0x61, 0x07, 0xb8, 0xbe, 0x4a,
            0x24, 0x83, 0xa9, 0x61, 0x4d, 0x3a, 0x46, 0x30,
            0x29, 0x78, 0x16, 0x01, 0x29, 0x5c, 0x95, 0x1a,
            0x9b, 0xab, 0x32, 0xae, 0xc3, 0xdb, 0x5d, 0x82,
            0xf9, 0xa2, 0x45, 0x40, 0x63, 0x89, 0x55, 0xc0,
            0x78, 0x6e, 0x75, 0x48, 0x7d, 0xbb, 0x72, 0x73,
            0xbb, 0x1e, 0x50, 0x5a, 0x76, 0x64, 0xcc, 0x70,
            0x7f, 0xf9, 0x65, 0xd4, 0xe1, 0x20, 0x0b, 0xd9,
            0x12, 0x54, 0x25, 0xaf, 0xc0, 0x7a, 0xec, 0x6b,
            0x9e, 0xa6, 0x61, 0xc3, 0x47, 0xa7, 0x1e, 0x69,
            0x18, 0x59, 0xe1, 0x0e, 0x52, 0x8f, 0xc0, 0xd8,
            0x72, 0x3a, 0xc9, 0xc0, 0x21, 0xc1, 0xb0, 0x19,
            0xee, 0x23, 0x97, 0xb2, 0x23, 0x78, 0x12, 0x3a,
            0x1e, 0x6d, 0xf2, 0xac, 0x8a, 0xf9, 0xc5, 0x73,
            0xa6, 0x94, 0x8d, 0x4f, 0x11, 0xba, 0x86, 0xc5,
            0x72, 0x29, 0x1f, 0x59, 0xff, 0x46, 0xf5, 0xd7,
            0xcd, 0x63, 0xf3, 0xc5, 0x23, 0x4f, 0xcd, 0xd0,
            0x4a, 0xd7, 0x3d, 0xb6, 0x83, 0xf8, 0x48, 0x76,
            0x99, 0x6f, 0xa0, 0xa1, 0x27, 0xfb, 0x37, 0x08,
            0x82, 0xfc, 0x80, 0xc0, 0xe5, 0xbb, 0xf5, 0x55,
            0x71, 0x4c, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x23, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0xaa,
            0xaa, 0x00, 0x01, 0x00
        ];
        let mut pos_reader = PosReader::new(packet);
        let parser = ClientHelloMsgParser::new(&mut pos_reader);
        assert!(parser.parse().is_ok());
    }

    
}