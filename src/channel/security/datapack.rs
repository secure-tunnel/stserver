use super::models;
use crate::error::{Error, ErrorKind};
use hyper::Response;
use mysql_async::chrono::{Datelike, Local, Timelike};
use openssl::symm::{Cipher, Crypter, Mode};
use std::ptr::null;

/*
   报文中4字节存储数值采用大端序处理

   报文头|版本号|时间戳|混淆模式X|混淆模式Y|数据段混淆后长度|数据段混淆前长度|数据类型|TOKEN|数据|报文尾

   AES:  KEY 32bit, IV 16bit
   TOEKN 40bytes
*/

pub struct DataEntry {
    model_x: u8,
    model_y: u8,
    token: Vec<u8>,
    aes_key: Vec<u8>,
    data_type: u8,
    content: Vec<u8>,
}

impl DataEntry {
    fn new() -> DataEntry {
        DataEntry {
            model_x: 0,
            model_y: 0,
            token: vec![],
            aes_key: vec![],
            data_type: 0,
            content: vec![],
        }
    }
}

fn common_pack_core(
    data: &Vec<u8>,
    model_x: u8,
    model_y: u8,
    data_type: u8,
    token: &str,
) -> Vec<u8> {
    let mut encrypted_data = data.clone();
    models::model_encrypt(&mut encrypted_data, model_x as u32);
    models::model_encrypt(&mut encrypted_data, model_y as u32);

    let total_len = 1 + 1 + 7 + 1 + 1 + 4 + 4 + 1 + 40 + encrypted_data.len() + 1;
    let mut res = vec![0; total_len];
    res[0] = 0xF0;
    res[1] = 0x01;
    res[2..9].copy_from_slice(current_timestamp().as_slice());
    res[9] = model_x as u8;
    res[10] = model_y as u8;
    res[11..15].copy_from_slice((encrypted_data.len() as u32).to_vector().as_slice());
    res[15..19].copy_from_slice((data.len() as u32).to_vector().as_slice());
    res[19] = data_type;
    res[20..60].copy_from_slice(token.as_bytes());
    res[60..total_len - 1].copy_from_slice(encrypted_data.as_slice());
    res[total_len - 1] = 0xFE;
    res
}

/*
   公共报文加密
   data 要混淆的数据
   key 公钥或者对称密钥
*/
pub fn common_pack(
    data: &Vec<u8>,
    key: &Vec<u8>,
    data_type: u8,
    token: &str,
) -> Result<Vec<u8>, Error> {
    // 产生model x and y
    let model_x = models::model_rand_choice();
    let mut model_y = model_x;
    let mut flag = true;
    while model_x == model_y {
        model_y = models::model_rand_choice();
    }

    // 协商第二步返回已经可以通过动态对称密钥加密了
    if data_type == 1 {
        let res = common_pack_core(data, model_x as u8, model_y as u8, data_type, token);
        Ok(res)
    } else if data_type == 2 || data_type == 3 {
        // 业务数据 对称密钥
        let mut key_r = key.clone();
        key_r[0] = model_x as u8;
        key_r[key.len() - 1] = model_y as u8;
        let ciphertext = aes_256_cbc(&data, &key_r, Mode::Encrypt).unwrap();
        let res = common_pack_core(&ciphertext, model_x as u8, model_y as u8, data_type, token);
        Ok(res)
    } else {
        Err(Error::new(ErrorKind::DATATYPE, "data type not matched!"))
    }
}

/*
   公共报文解密
   data 要解混淆的数据
   key 私钥或者对称密钥 key32 + iv16
*/
pub fn common_unpack(data: &Vec<u8>) -> Result<DataEntry, Error> {
    if data.is_empty()
        || data[0] != 0xF0
        || data[1] != 0x01
        || data[data.len() - 1] != 0xFE
        || data.len() <= 61
    {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data check failed!"));
    }

    let model_x = data[9];
    let model_y = data[10];
    let enc_data_len = data[11..15].to_u32();
    let data_len = data[15..19].to_u32();
    let data_type = data[19];
    if (enc_data_len + 61 != data.len() as u32) {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data len not matched!"));
    }
    let token = String::from_utf8(data[20..60].to_vec()).unwrap();
    let enc_data = data[60..data.len() - 1].to_vec();
    let mut mixed_data = enc_data.clone();
    models::model_decrypt(&mut mixed_data, model_y as u32);
    models::model_decrypt(&mut mixed_data, model_x as u32);

    if (data_len != mixed_data.len() as u32) {
        return Err(Error::new(
            ErrorKind::DATA_UNPACK_OLDDATA_NOMATCH,
            "old data len not matched!",
        ));
    }

    if data_type == 1 {
        Ok(DataEntry::new())
    } else if data_type == 2 {
        todo!()
        // 校验TOKEN
    } else if data_type == 3 {
        // 校验TOKEN
        // AES解密
        // 通过TOKEN找到对称密钥
        let key = vec![];
        let mut key_r = key.clone();
        key_r[0] = model_x as u8;
        key_r[key.len() - 1] = model_y as u8;
        let ciphertext = aes_256_cbc(&mixed_data, &key_r, Mode::Decrypt).unwrap();
        Ok(DataEntry::new())
    } else {
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
        let mut t: Vec<u8> = vec![0; 4];
        t[0] = (self >> 24) as u8;
        t[1] = ((self & 0xff0000) >> 16) as u8;
        t[2] = ((self & 0xff00) >> 8) as u8;
        t[3] = (self & 0xff) as u8;
        t
    }
}

fn current_timestamp() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0; 7];
    let now = Local::now();
    v[0] = (now.year() / 100) as u8;
    v[1] = (now.year() % 100) as u8;
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

fn aes_256_cbc(data: &Vec<u8>, key: &Vec<u8>, mode: Mode) -> Result<Vec<u8>, Error> {
    let mut encrypter =
        Crypter::new(Cipher::aes_256_cbc(), mode, &key[0..32], Some(&key[32..])).unwrap();
    let block_size = Cipher::aes_256_cbc().block_size();
    let mut ciphertext = vec![0; data.len() + block_size];
    let mut count = encrypter.update(data.as_slice(), &mut ciphertext).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    Ok(ciphertext)
}

#[cfg(test)]
mod test {
    use super::*;
    use openssl::symm::{Cipher, Crypter, Mode};
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
        let v: Vec<u8> = vec![1, 2, 3, 4];
        assert_eq!(v[0..4].to_u32(), 0b00000001000000100000001100000100);
        let t: u32 = 0b00000001000000100000001100000100;
        assert_eq!(t.to_vector(), v);
    }

    #[test]
    fn current_timestamp1() {
        let v = current_timestamp();
        println!("{:#?}", v);
    }

    #[test]
    fn pack() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let key = vec![20; 48];
        let token = vec![0; 40];
        let v1 = common_pack(&data, &key, 1, String::from_utf8(token).unwrap().as_str())
            .unwrap_or(Vec::new());
        match common_unpack(&v1) {
            Ok(data1) => assert_eq!(data, data1.data),
            Err(message) => println!("{}", message),
        }
    }
}
