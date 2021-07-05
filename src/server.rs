use crate::channel;
use crate::utils;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use std::borrow::Borrow;
use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

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

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key"))
}

pub async fn run(server: &Server) -> io::Result<()> {
    let mut config = ServerConfig::new(NoClientAuth::new());
    let certs = load_certs(Path::new("test/server_cert.pem"))?;
    let mut keys = load_keys(Path::new("test/server_key.pem"))?;
    config
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(server.ipaddr.as_str()).await?;
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = async move {
            let mut stream = acceptor.accept(stream).await?;
            let (mut reader, mut writer) = split(stream);
            let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
            read(tx, reader, peer_addr);
            write(rx, writer);
            Ok(()) as io::Result<()>
        };
        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}

fn read(
    tx: Sender<Vec<u8>>,
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    peer_addr: SocketAddr,
) -> JoinHandle<tokio::io::Result<()>> {
    tokio::spawn(async move {
        let mut content = vec![];
        let mut content_len = 0usize;
        loop {
            println!("read...");
            let mut buffer: Vec<u8> = vec![0; 1024];
            let n = match reader.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => break,
            };
            content.append(&mut buffer[0..n].to_vec());
            // split package 62+content
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
                let tx = tx.clone();
                let content = content.clone();
                tokio::spawn(async move {
                    let response = channel::tunnel_process(&peer_addr, content);
                    tx.send(response).unwrap();
                    Ok(()) as io::Result<()>
                });
            }
        }
        drop(tx);
        Ok(()) as io::Result<()>
    })
}

fn write(
    rx: Receiver<Vec<u8>>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
) -> JoinHandle<tokio::io::Result<()>> {
    tokio::spawn(async move {
        loop {
            println!("write....");
            let data: Vec<u8> = match rx.recv() {
                Ok(data) => data,
                Err(_) => break,
            };
            // TODO if rx equals zero
            if data.is_empty() {
                sleep(Duration::from_millis(100));
                continue;
            }
            println!("data: {:?}", data);
            writer.write(data.as_slice()).await;
        }
        drop(rx);
        Ok(()) as io::Result<()>
    })
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
