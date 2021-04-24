use super::models;
use openssl::symm::{Cipher, Mode, Crypter};
use std::ptr::null;

/*
    公共报文加密
    data 要混淆的数据
    key 公钥或者对称密钥
 */
pub fn common_pack(data: Vec<u8>, key: Vec<u8>, data_type: u8) -> Vec<u8> {
    // 产生model x and y
    let model_x = models::model_rand_choice();
    let mut model_y = model_x;
    let mut flag = true;
    while model_x == model_y {
        model_y = models::model_rand_choice();
    }

    if data_type == 1 || data_type == 2 {
        // 协商第一步
        let total_len = 1+4+4+1+1+1+7+data.len();
        let mut res = vec![0; total_len];
        res[0] = 0xF0;
        res[1] = 0x01;

        res[total_len -1] = 0xFE;

        res
    }else if data_type == 3 {
        // 业务数据 对称密钥
        let mut key_r = key.clone();
        key_r[0] = model_x as u8;
        key_r[key.len()] = model_y as u8;
        let mut encrypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, &key_r[0..24], Some(&key_r[24..])).unwrap();
        let block_size = Cipher::aes_256_gcm().block_size();
        let mut ciphertext = vec![0; data.len() + block_size];
        let mut count = encrypter.update(data.as_slice(), &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);
        ciphertext
    }else {
        Vec::new()
    }
}

/*
    公共报文解密
    data 要解混淆的数据
    key 私钥或者对称密钥
 */
pub fn common_unpack(data: Vec<u8>, key: Vec<u8>, data_type: u8) -> Vec<u8> {
    if data_type == 1 || data_type == 2 {

    }else if data_type == 3 {
        let mut encrypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, &key[0..24], Some(&key[24..])).unwrap();
        let block_size = Cipher::aes_256_gcm().block_size();
        let mut ciphertext = vec![0; data.len() + block_size];
        let mut count = encrypter.update(data.as_slice(), &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);

        // ciphertext
    }
    unimplemented!()
}

#[cfg(test)]
mod test {
    use crate::mixed::security;
    use crate::mixed::models;

    #[test]
    fn rand() {
        let model_x = models::model_rand_choice();
        let mut model_y = model_x;
        let mut flag = true;
        while model_x == model_y {
            model_y = models::model_rand_choice();
        }
        println!("{}, {}", model_x, model_y);
    }
}