use std::net::{TcpListener, TcpStream};
use openssl::ssl::{SslAcceptor, SslMethod, SslFiletype, SslStream};
use std::sync::Arc;
use std::error::Error;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;

pub struct Server {
    ipaddr: String,

}

impl Server {
    pub fn new(ipaddr: &str) -> Self {
        Self {
            ipaddr: String::from(ipaddr),
        }
    }
}

pub fn run(server: &Server) {
    let listener = TcpListener::bind(server.ipaddr.as_str()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file("test/server_key.pem", SslFiletype::PEM).unwrap();
    acceptor.set_certificate_chain_file("test/server_cert.pem").unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    loop {
        let (socket, _) = listener.accept().unwrap();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let stream = acceptor.accept(socket).unwrap();
            process(stream);
        });
    }
}

fn process(mut stream: SslStream<TcpStream>) {
    let buffer_size = 1024;
    let mut request_buffer: Vec<u8> = vec![];
    let mut request_len = 0usize;
    let mut tcp_stream = stream.get_mut();
    loop {
        let mut buffer: Vec<u8> = vec![0; buffer_size];
        match tcp_stream.read(&mut buffer){
            Ok(n) => {
                if n == 0 {
                    sleep(Duration::from_millis(100));
                    continue;
                }else{
                    request_len += n;
                }
            }
            _ => {}
        }
        // print data
        println!("data: {:?}", buffer);
    }
}
