mod security;
mod tunnel;

use crate::channel::security::datapack::common_pack;
use security::datapack;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;

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
    let mut token = vec![];
    let mut data_result = vec![];
    if dataEntry.data_type == 1 {
        let (data_result, token_t) = tunnel::tunnel_first(&dataEntry.content);
        token = token_t;
    } else if dataEntry.data_type == 2 {
        token = dataEntry.token.clone();
        // check dataEntry.token()
        let decrypt_data = dataEntry.decrypt();
    } else {
        token = dataEntry.token.clone();
        // check dataEntry.token()
        let decrypt_data = dataEntry.decrypt();
    }

    match datapack::common_pack(
        &data_result,
        &dataEntry.aes_key,
        dataEntry.data_type,
        &token,
    ) {
        Ok(_data) => _data,
        Err(err) => err.to_string().as_bytes().to_vec(),
    }
}
