use std::net::{TcpListener, TcpStream};
use openssl::ssl::{SslAcceptor, SslMethod, SslFiletype, SslStream};
use std::sync::Arc;
use std::error::Error;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;
use std::thread;
use crate::utils;
use crate::channel;

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
        thread::spawn(move || {
            let stream = acceptor.accept(socket).unwrap();
            process(stream);
        });
    }
}

fn process(mut stream: SslStream<TcpStream>) {
    let buffer_size = 1024;
    let mut content: Vec<u8> = vec![];
    let mut request_len = 0usize;
    let mut tcp_stream = stream.get_mut();
    let sockaddr = tcp_stream.peer_addr().unwrap();
    loop {
        let mut buffer: Vec<u8> = vec![0; buffer_size];
        match stream.ssl_read(&mut buffer) {
            Ok(n) => {
                if n == 0 {
                    continue;
                } else {
                    request_len += n;
                    // 将数据拷贝到content，继续读
                    content.append(&mut buffer[0..n].to_vec());
                }
            }
            _ => {
                println!("ssl_read error");
                break;
            }
        }
        // split package 62+content
        if content.len() == 0 {
            continue;
        }
        // 如果不是f0开头，则找到下一个f0开头的值，并清除之前的垃圾数据
        if content[0] != 0xF0 {
            content = find_next_f0(&content);
            if content.len() == 0 {
                continue;
            }
        }
        let data_length = utils::u8_array_to_u32(&content[9..13]);
        if content.len() < data_length as usize {
            continue;
        }
        if content[(61 + data_length) as usize] == 0xFE {
            stream.ssl_write(channel::tunnel_process(sockaddr, &content).as_slice());
        }
    }
}

/*
    找到包头
 */
fn find_next_f0(data: &Vec<u8>) -> Vec<u8> {
    let mut offset = 0;
    for element in data.iter() {
        if *element == 0xF0 {
            break;
        }
        offset += 1;
    }

    data[offset..].to_owned()
}