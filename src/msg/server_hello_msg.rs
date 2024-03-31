struct ServerHelloExtension {
    server_name: Option<String>,
    session_ticket: Option<String>,
    alpn: Option<String>,
    secure_renegotiation: Option<Vec<u8>>,
    ticket_suppoted: bool,
    scts: Vec<Vec<u8>>,
    ocsp_stapling: bool,
    next_protos: Option<Vec<String>>,
}

struct ServerHelloMsg {
    version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suite: u16,
    compress_methods: u8,
    extensions: ServerHelloExtension,
}
