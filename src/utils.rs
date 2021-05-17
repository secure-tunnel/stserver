use crate::error::Error;
use mysql_async::chrono::{Datelike, Local, Timelike};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl_sys::{EVP_sm3, EVP_MD_CTX, EVP_MD_CTX_new, EVP_DigestInit_ex, EVP_md_null, EVP_DigestUpdate, ENGINE, EVP_DigestFinal_ex, EVP_MD_CTX_free};
use std::os::raw::{c_uint, c_uchar, c_ulong};

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

pub fn u8_array_to_u32(vec: &[u8]) -> u32 {
    vec.to_u32()
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

pub fn u32_to_vector(v: u32) -> Vec<u8> {
    v.to_vector()
}

pub fn current_timestamp() -> Vec<u8> {
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

pub fn timestamp_to_string(v: Vec<u8>) -> String {
    todo!()
}

pub fn aes_256_cbc(data: &Vec<u8>, key: &Vec<u8>, mode: Mode) -> Result<Vec<u8>, Error> {
    let mut encrypter =
        Crypter::new(Cipher::aes_256_cbc(), mode, &key[0..32], Some(&key[32..])).unwrap();
    let block_size = Cipher::aes_256_cbc().block_size();
    let mut ciphertext = vec![0; data.len() + block_size];
    let mut count = encrypter.update(data.as_slice(), &mut ciphertext).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    Ok(ciphertext)
}

pub fn rsa_publickey_encrypt(data: &Vec<u8>, publickey: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let rsa = Rsa::public_key_from_pem(publickey).unwrap();
    let mut encrypted_data: Vec<u8> = vec![0; data.len()];
    let len = rsa
        .public_encrypt(data, encrypted_data.as_mut_slice(), Padding::PKCS1)
        .unwrap();
    encrypted_data.truncate(len);
    Ok(encrypted_data)
}

pub fn rsa_privatekey_decrypt(data: &Vec<u8>, privatekey: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let rsa = Rsa::private_key_from_pem(privatekey).unwrap();
    let mut encrypted_data: Vec<u8> = vec![0; data.len()];
    let len = rsa
        .private_decrypt(data, encrypted_data.as_mut_slice(), Padding::PKCS1)
        .unwrap();
    encrypted_data.truncate(len);
    Ok(encrypted_data)
}

pub struct SM3{}

impl SM3 {
    pub fn hash(data: &Vec<u8>) -> Vec<u8> {
        let mut res = vec![0, 64].into_boxed_slice();
        let mut res_len: u32 = 0;
        unsafe {
            let md = EVP_sm3();
            let mut md_ctx = EVP_MD_CTX_new();
            let mut engine = ENGINE{};
            EVP_DigestInit_ex(md_ctx, md, *engine);
            EVP_DigestUpdate(md_ctx, data.as_ptr(), data.len());
            EVP_DigestFinal_ex(md_ctx, res.as_mut_ptr(), *res_len);
            EVP_MD_CTX_free(md_ctx);
        }
        res.to_vec()
    }
}

pub struct SM4 {}

impl SM4 {
    pub fn encrypt(data: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
        vec![]
    }

    pub fn decrypt(data: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
        unimplemented!()
    }
}

pub struct SM2{}

impl SM2 {
    pub fn encrypt(data: &Vec<u8>, pubKey: &Vec<u8>) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }

    pub fn decrypt(data: &Vec<u8>, priKey: &Vec<u8>) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }

    pub fn sign(data: &Vec<u8>, priKey: &Vec<u8>) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }

    pub fn verify(data: &Vec<u8>, oldData: &Vec<u8>, pubKey: &Vec<u8>) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }
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
