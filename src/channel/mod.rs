mod security;
mod tunnel;

use security::datapack;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use crate::channel::security::datapack::common_pack;

/*
   主处理流程
*/
pub fn tunnel_process(addr: &SocketAddr, data: Vec<u8>) -> Vec<u8> {
    println!("{:#?}", addr);
    let dataEntry = match datapack::common_unpack(&data) {
        Ok(dataEntry) => dataEntry,
        Err(msg) => {
            println!("data unpack error: {:?}", msg);
            return vec![];
        }
    };
    println!("decrypt success!");
    if dataEntry.data_type == 1 {
        tunnel::tunnel_first(&dataEntry.content);
    } else if dataEntry.data_type == 2 {
        // check dataEntry.token()
        let decrypt_data = dataEntry.decrypt();
    } else {
        // check dataEntry.token()
        let decrypt_data = dataEntry.decrypt();
    }

    vec![]
}
