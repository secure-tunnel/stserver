use super::models;
use openssl::symm::{Cipher, Mode, Crypter};
use std::ptr::null;
use crate::error::{Error, ErrorKind};
use mysql_async::chrono::{Local, Datelike, Timelike};
use hyper::Response;

/*
    报文中4字节存储数值采用大端序处理

    报文头|版本号|时间戳|混淆模式X|混淆模式Y|数据段混淆后长度|数据段混淆前长度|数据类型|数据|报文尾
 */

pub struct RespData {
    pub datatype: u8,
    pub data: Vec<u8>,
}

impl RespData {
    fn new_null() -> RespData{
        RespData{
            datatype: 0,
            data: vec![]
        }
    }

    fn new(data_type: u8, data: Vec<u8>) -> RespData {
        RespData{
            datatype: data_type,
            data: data,
        }
    }
}

fn common_pack_core(data: Vec<u8>, model_x: u8, model_y: u8, data_type: u8) -> Vec<u8> {
    let mut encrypted_data = data.clone();
    models::model_encrypt(&mut encrypted_data, model_x as u32);
    models::model_encrypt(&mut encrypted_data, model_y as u32);

    let total_len = 1+1+7+1+1+4+4+1+encrypted_data.len()+1;
    let mut res = vec![0; total_len];
    res[0] = 0xF0;
    res[1] = 0x01;
    res[2..9].copy_from_slice(current_timestamp().as_slice());
    res[9] = model_x as u8;
    res[10] = model_y as u8;
    res[11..15].copy_from_slice((encrypted_data.len() as u32).to_vector().as_slice());
    res[15..19].copy_from_slice((data.len() as u32).to_vector().as_slice());
    res[19] = data_type;
    res[20..total_len-1].copy_from_slice(encrypted_data.as_slice());
    res[total_len -1] = 0xFE;
    res
}

/*
    公共报文加密
    data 要混淆的数据
    key 公钥或者对称密钥
 */
pub fn common_pack(data: Vec<u8>, key: Vec<u8>, data_type: u8) -> Result<Vec<u8>, Error> {
    // 产生model x and y
    let model_x = models::model_rand_choice();
    let mut model_y = model_x;
    let mut flag = true;
    while model_x == model_y {
        model_y = models::model_rand_choice();
    }

    // 协商第二步返回已经可以通过动态对称密钥加密了
    if data_type == 1 {
        let res = common_pack_core(data, model_x as u8, model_y as u8, data_type);
        Ok(res)
    }else if data_type == 2 || data_type == 3 {
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

        let res = common_pack_core(ciphertext, model_x as u8, model_y as u8, data_type);
        Ok(res)
    }else {
        Err(Error::new(ErrorKind::DATATYPE, "data type not matched!"))
    }
}

/*
    公共报文解密
    data 要解混淆的数据
    key 私钥或者对称密钥 key24 + iv16
 */
pub fn common_unpack(data: Vec<u8>, key: Vec<u8>) -> Result<RespData, Error> {
    if data.is_empty() || data[0] != 0xF0 || data[1] != 0x01 || data[data.len() - 1] != 0xFE || data.len() <= 21 {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data check failed!"));
    }

    let model_x = data[9];
    let model_y = data[10];
    let enc_data_len = data[11..15].to_u32();
    let data_len = data[15..19].to_u32();
    let data_type = data[19];
    if(enc_data_len + 21 != data.len() as u32) {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data len not matched!"));
    }

    let enc_data = data[20..data.len()-1].to_vec();
    let mut mixed_data = enc_data.clone();
    models::model_decrypt(&mut mixed_data, model_y as u32);
    models::model_decrypt(&mut mixed_data, model_x as u32);

    if data_type == 1 || data_type == 2 {
        Ok(RespData::new(data_type, mixed_data))
    }else if data_type == 3 {
        let mut encrypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, &key[0..24], Some(&key[24..])).unwrap();
        let block_size = Cipher::aes_256_gcm().block_size();
        let mut ciphertext = vec![0; mixed_data.len() + block_size];
        let mut count = encrypter.update(mixed_data.as_slice(), &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);

        Ok(RespData::new(data_type, ciphertext))
    }else{
        Err(Error::new(ErrorKind::DATATYPE, "data type not matched!"))
    }
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

fn current_timestamp() -> Vec<u8> {
    let mut v : Vec<u8> = vec![0;7];
    let now = Local::now();
    v[0] = (now.year()/100) as u8;
    v[1] = (now.year()%100) as u8;
    v[2] = now.month() as u8;
    v[3] = now.day() as u8;
    v[4] = now.hour() as u8;
    v[5] = now.minute() as u8;
    v[6] = now.second() as u8;
    v
}

fn timestamp_to_string(v: Vec<u8>) -> String {
    todo!()
}

#[cfg(test)]
mod test {
    use crate::mixed::security;
    use crate::mixed::models;
    use crate::mixed::security::{BytesConvert, U32Convert, RespData};
    use std::ptr::null;

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

    #[test]
    fn current_timestamp() {
        let v = security::current_timestamp();
        println!("{:#?}", v);
    }

    #[test]
    fn pack() {
        let v = vec![1,2,3,4,5,6];
        let v1 = security::common_pack(v.clone(), Vec::new(), 1).unwrap_or(Vec::new());
        match security::common_unpack(v1, Vec::new()) {
            Ok(data) =>
                assert_eq!(v, data.data),
            Err(message) =>
                println!("{}", message)
        }
    }
}