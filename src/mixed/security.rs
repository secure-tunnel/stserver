use super::models;
use openssl::symm::{Cipher, Mode, Crypter};
use std::ptr::null;
use crate::error::{Error, ErrorKind};

/*
    报文中4字节存储数值采用大端序处理
 */

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
    key 私钥或者对称密钥 key24 + iv16
 */
pub fn common_unpack(data: Vec<u8>, key: Vec<u8>, data_type: u8) -> Result<Vec<u8>, Error> {
    if data.is_empty() || data[0] != 0xF0 || data[data.len() - 1] != 0xFE {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data check failed!"));
    }
    let mut offset: usize = 1;
    let module_x = data[offset];
    let module_y = data[offset];
    let x = data[0..4].to_u32();

    if data_type == 1 || data_type == 2 {

    }else if data_type == 3 {
        let mut mixed_data = data.clone();
        models::model_decrypt(&mut mixed_data, module_y as u32);
        models::model_decrypt(&mut mixed_data, module_x as u32);

        let mut encrypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, &key[0..24], Some(&key[24..])).unwrap();
        let block_size = Cipher::aes_256_gcm().block_size();
        let mut ciphertext = vec![0; mixed_data.len() + block_size];
        let mut count = encrypter.update(mixed_data.as_slice(), &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);

        // ciphertext
    }
    unimplemented!()
}

trait BytesConvert {
    fn to_u32(&self) -> u32;
}

impl BytesConvert for [u8] {
    fn to_u32(&self) -> u32 {
        u32::from(self[0]) << 24
            | u32::from(self[1]) << 16
            | u32::from(self[2]) << 8
            | u32::from(self[3])
    }
}

trait U32Convert {
    fn to_vector(&self) -> Vec<u8>;
}

impl U32Convert for u32 {
    fn to_vector(&self) -> Vec<u8> {
        let mut t: Vec<u8> = vec![0;4];
        t[0] = (self >> 24) as u8;
        t[1] = ((self & 0xff0000) >> 16) as u8;
        t[2] = ((self & 0xff00) >> 8) as u8;
        t[3] = (self & 0xff) as u8;
        t
    }
}

#[cfg(test)]
mod test {
    use crate::mixed::security;
    use crate::mixed::models;
    use crate::mixed::security::{BytesConvert, U32Convert};

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

    #[test]
    fn bytes_convert() {
        let v : Vec<u8> = vec![1,2,3,4];
        assert_eq!(v[0..4].to_u32(), 0b00000001000000100000001100000100);
        let t: u32 = 0b00000001000000100000001100000100;
        assert_eq!(t.to_vector(), v);
    }
}