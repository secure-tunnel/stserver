/*
   主要实现加密信道两次交互数据处理
   包括以下：
   1 从mysql或者redis读取伪值唯一标识对应的私钥
     先从redis读，如果没有从mysql读，并回写到redis中
   2 生成TOKEN写入redis
       关联预值D
   3
*/

use std::vec;

use crate::{sm::SM2, store::db::AppClientKey, utils};

/*
   处理协商第一个请求
*/
pub fn tunnel_first(data: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let unique_id = data[0..32].to_vec();
    // todo 根据唯一标识查询私钥KEY
    let id = match String::from_utf8(unique_id) {
        Ok(id) => id,
        Err(err) => String::from(""),
    };
    let private_key: Vec<u8> = match AppClientKey::get_with_app_client(id.as_str()) {
        Ok(Some(app_client_key)) => Vec::from(app_client_key.prikey),
        Ok(None) => return (vec![], vec![]),
        Err(_) => return (vec![], vec![]),
    };
    let dec_data = SM2::decrypt(&data[32..].to_vec(), &private_key).unwrap();
    // 生成TOKEN
    let token = vec![];
    // todo randomA Mac存入缓存
    let random_a = dec_data[0..32].to_vec();
    let mac = dec_data[32..].to_vec();
    // todo create random B
    let random_b: Vec<u8> = vec![0];
    // todo 查询一个证书
    let cert: Vec<u8> = vec![];
    let mut no_sign_data = Vec::new();
    no_sign_data.extend(&random_b);
    no_sign_data.extend(&cert);
    let mut sign_data = SM2::sign(&no_sign_data, &private_key).unwrap();
    sign_data.extend(&random_b);
    sign_data.extend(&cert);
    (sign_data, token)
}

/*
   处理协商第二个请求
*/
pub fn tunnel_second() {}
