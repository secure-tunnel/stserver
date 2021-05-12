mod channel;
mod db;
mod error;
mod utils;
mod server;

// use tokio::net::{TcpListener, TcpStream};
use openssl::ssl::{SslAcceptor, SslMethod, SslFiletype, SslStream};
use std::sync::Arc;
use std::borrow::Borrow;
use std::net::{TcpListener, TcpStream};
use crate::server::Server;

#[tokio::main]
async fn main() {
    let server = Server::new("0.0.0.0:443");
    server::run(&server);
}