/*
   主要实现加密信道两次交互数据处理
   包括以下：
   1 从mysql或者redis读取伪值唯一标识对应的私钥
     先从redis读，如果没有从mysql读，并回写到redis中
   2 生成TOKEN写入redis
       关联预值D
   3
*/

use crate::utils;

/*
   处理协商第一个请求
*/
pub(crate) fn tunnel_first(data: &Vec<u8>) -> Vec<u8> {
    let unique_id = data[0..32].to_vec();
    // todo 根据唯一标识查询私钥KEY
    let private_key = vec![0];
    let dec_data = utils::rsa_privatekey_decrypt(&data[32..].to_vec(), &private_key).unwrap();
    let random_a = dec_data[0..32].to_vec();
    let mac = dec_data[32..].to_vec();
    // todo create random B
    let random_b = vec![0];
    Vec::new()
}

/*
   处理协商第二个请求
*/
pub fn tunnel_second() {}
