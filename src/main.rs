mod channel;
mod db;
mod error;
mod utils;

use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::borrow::Borrow;
use std::convert::Infallible;
use std::net::SocketAddr;


#[tokio::main]
async fn main() {
    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let make_svc = make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move | req: Request<Body>| data_process(remote_addr, req)))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn data_process(
    socket: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    if req.method().eq(&Method::POST) {
        for (key, value) in req.headers().iter() {
            println!("{:?}: {:?}", key, value);
        }

        println!("uri: {}", req.uri());

        let b = hyper::body::to_bytes(req).await;
        let b = Vec::from(b.unwrap().as_ref());
        let resp = channel::tunnel_process(socket,&b);
        Ok(Response::new(Body::from(resp)))
    } else {
        let mut response = Response::new("illegal request".into());
        *response.status_mut() = StatusCode::NOT_ACCEPTABLE;
        Ok(response)
    }
}