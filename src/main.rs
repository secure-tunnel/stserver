mod mixed;

use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use std::borrow::Borrow;


async fn data_process(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if req.method().eq(&Method::POST) {
        for (key, value) in req.headers().iter() {
            println!("{:?}: {:?}", key, value);
        }

        println!("uri: {}", req.uri());

        let b = hyper::body::to_bytes(req).await;
        let b = Vec::from(b.unwrap().as_ref());

        println!("request body len: {}", b.len());
        println!("request body len[0]: {}", b[0]);
    }
    let mut response = Response::new("illegal request".into());
    *response.status_mut() = StatusCode::NOT_ACCEPTABLE;
    Ok(response)
}

#[tokio::main]
async fn main() {
    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    // A `Service` is needed for every connection, so this
    // creates one from our `hello_world` function.
    let make_svc = make_service_fn(|_conn| async {
        // service_fn converts our function into a `Service`
        Ok::<_, Infallible>(service_fn(data_process))
    });

    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}