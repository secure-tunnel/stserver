mod security;
mod tunnel;

use security::datapack;
use std::net::SocketAddr;

/*
   主处理流程
*/
pub fn tunnel_process(addr: SocketAddr, data: &Vec<u8>) -> Vec<u8> {
    println!("{:#?}", addr);
    let dataEntry = datapack::common_unpack(data).unwrap();

    if dataEntry.data_type == 1 {
        tunnel::tunnel_first(&dataEntry.content)
    }else if dataEntry.data_type == 2 {
        // check dataEntry.token()
        let decrypt_data = dataEntry.decrypt();
    }else {
        // check dataEntry.token()
        let decrypt_data = dataEntry.decrypt();
    }

    unimplemented!()
}

