mod security;
pub mod tunnel;

use security::datapack;
use std::net::SocketAddr;

/*
   主处理流程
*/
pub fn tunnel_process(addr: SocketAddr, data: &Vec<u8>) -> Vec<u8> {
    println!("{:#?}", addr);
    datapack::common_unpack(data);

    // security::common_pack(data, )
    unimplemented!()
}
