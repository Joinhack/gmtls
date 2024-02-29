use tokio::net::TcpListener;

///
fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:8081").await.expect("the port is already bind.");
        while let Ok((mut stream, _addr)) = listener.accept().await  {
            
        }
    });
    
}
