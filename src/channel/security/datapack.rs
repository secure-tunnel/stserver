use super::models;
use crate::error::{Error, ErrorKind};
use crate::utils;
use openssl::symm::{Cipher, Crypter, Mode};
use std::ptr::null;

/*
   报文中4字节存储数值采用大端序处理

   报文头|版本号|时间戳|数据段混淆后长度|数据段混淆前长度|混淆模式X|混淆模式Y|数据类型|TOKEN|混淆是否启用|数据|报文尾

   AES:  KEY 32bit, IV 16bit
   TOEKN 40bytes
*/

pub struct DataEntry {
    model_x: u8,
    model_y: u8,
    pub token: Vec<u8>,
    pub aes_key: Vec<u8>,
    pub data_type: u8,
    pub content: Vec<u8>,
}

impl DataEntry {
    pub fn new(
        model_x: u8,
        model_y: u8,
        token: &Vec<u8>,
        data_type: u8,
        data: &Vec<u8>,
    ) -> DataEntry {
        DataEntry {
            model_x: model_x,
            model_y: model_y,
            token: token.clone(),
            aes_key: vec![],
            data_type: data_type,
            content: data.clone(),
        }
    }

    pub fn decrypt(&self) -> Vec<u8> {
        let mut key = self.aes_key.clone();
        key[0] = self.model_x as u8;
        key[self.aes_key.len() - 1] = self.model_y as u8;
        utils::aes_256_cbc(&self.content, &key, Mode::Decrypt).unwrap()
    }
}

fn common_pack_core(
    data: &Vec<u8>,
    model_x: u8,
    model_y: u8,
    data_type: u8,
    token: &Vec<u8>,
) -> Vec<u8> {
    // todo 从配置server读取是否启用混淆. 数据依据toekn找到关联的项目配置信息 \
    //   混淆数据的粒度控制：项目 or API接口
    let mixed_flag = 0x0;
    let mut encrypted_data = data.clone();
    models::model_encrypt(&mut encrypted_data, model_x as u32);
    models::model_encrypt(&mut encrypted_data, model_y as u32);

    let total_len = 1 + 1 + 7 + 1 + 1 + 4 + 4 + 1 + 40 + 1 + encrypted_data.len() + 1;
    let mut res = vec![0; total_len];
    res[0] = 0xF0;
    res[1] = 0x00;
    res[2..9].copy_from_slice(utils::current_timestamp().as_slice());
    res[9..13].copy_from_slice(utils::u32_to_vector(encrypted_data.len() as u32).as_slice());
    res[13..17].copy_from_slice(utils::u32_to_vector(data.len() as u32).as_slice());
    res[17] = model_x as u8;
    res[18] = model_y as u8;
    res[19] = data_type;
    res[20..60].copy_from_slice(token.as_slice());
    res[60] = mixed_flag;
    res[61..total_len - 1].copy_from_slice(encrypted_data.as_slice());
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
    token: &Vec<u8>,
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
        let ciphertext = utils::aes_256_cbc(&data, &key_r, Mode::Encrypt).unwrap();
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
        || data[1] != 0x00
        || data[data.len() - 1] != 0xFE
        || data.len() <= 62
    {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data check failed!"));
    }

    let enc_data_len = utils::u8_array_to_u32(&data[9..13]);
    let data_len = utils::u8_array_to_u32(&data[13..17]);
    let model_x = data[17];
    let model_y = data[18];
    let data_type = data[19];
    if (enc_data_len + 62 != data.len() as u32) {
        return Err(Error::new(ErrorKind::DATA_INVALID, "data len not matched!"));
    }
    let token = data[20..60].to_vec();
    let mixed_flag = data[60];
    let enc_data = data[61..data.len() - 1].to_vec();
    if mixed_flag == 0x0 {
        Ok(DataEntry::new(
            model_x, model_y, &token, data_type, &enc_data,
        ))
    } else {
        let mut mixed_data = enc_data.clone();
        models::model_decrypt(&mut mixed_data, model_y as u32);
        models::model_decrypt(&mut mixed_data, model_x as u32);

        if (data_len != mixed_data.len() as u32) {
            return Err(Error::new(
                ErrorKind::DATA_UNPACK_OLDDATA_NOMATCH,
                "old data len not matched!",
            ));
        }

        Ok(DataEntry::new(
            model_x,
            model_y,
            &token,
            data_type,
            &mixed_data,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils;
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
    fn pack() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let key = vec![20; 48];
        let token = vec![0; 40];
        let v1 = common_pack(&data, &key, 1, &token);
        // match common_unpack(&v1) {
        //     Ok(data1) => assert_eq!(data, data1.content),
        //     Err(message) => println!("{}", message),
        // }
    }
}
