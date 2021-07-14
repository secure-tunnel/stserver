mod security;
mod tunnel;

use crate::channel::security::datapack::common_pack;
use crate::error;
use security::datapack;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::vec;

use self::security::datapack::DataEntry;

/*
   主处理流程
*/
pub fn tunnel_process(addr: &SocketAddr, data: Vec<u8>) -> Vec<u8> {
    println!("{:#?}", addr);
    let data_entry = match datapack::common_unpack(&data) {
        Ok(data_entry) => data_entry,
        Err(msg) => {
            println!("data unpack error: {:?}", msg);
            return vec![];
        }
    };
    println!("decrypt success!");

    match process(&data_entry) {
        Ok((data, token)) => {
            match datapack::common_pack(
                &data,
                &data_entry.symmetric_key,
                data_entry.data_type,
                &token,
            ) {
                Ok(_data) => _data,
                Err(err) => vec![10],
            }
        },
        Err(err) => {
            match datapack::common_pack(
                &err.to_vec(),
                &data_entry.symmetric_key,
                0,
                &data_entry.token,
            ) {
                Ok(_data) => _data,
                Err(err) => vec![11],
            }
        }
    }
    
    
}

fn process(data_entry: &DataEntry) -> error::Result<(Vec<u8>, Vec<u8>)> {
    if data_entry.data_type == 1 {
        return tunnel::tunnel_first(&data_entry.content);
    }
    Ok((vec![], vec![]))
    // } else if data_entry.data_type == 2 {
    //     token = data_entry.token.clone();
    //     // check dataEntry.token()
    //     let decrypt_data = data_entry.decrypt();
    // } else {
    //     token = data_entry.token.clone();
    //     // check dataEntry.token()
    //     let decrypt_data = data_entry.decrypt();
    // }

}