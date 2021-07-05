mod channel;
mod db;
mod error;
mod server;
mod sm;
mod utils;

// use tokio::net::{TcpListener, TcpStream};
use crate::server::Server;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use std::borrow::Borrow;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let server = Server::new("0.0.0.0:443");
    server::run(&server).await;
}
