use serde_derive::Deserialize;
use std::error::Error;
use std::{
    fs::File,
    io::{Read, Result},
};

use crate::store::mem;

#[derive(Deserialize)]
pub struct Config {
    pub app: Option<App>,
    pub redis: Option<Redis>,
    pub mysql: Option<Mysql>,
}

#[derive(Deserialize)]
pub struct App {
    pub tls_cert: String,
    pub tls_key: String,
}

#[derive(Deserialize)]
pub struct Redis {
    pub host: Vec<String>,
    pub auth_passwd: String,
}

#[derive(Deserialize)]
pub struct Mysql {
    pub host: String,
    pub port: i32,
    pub user: String,
    pub passwd: String,
}

impl Config {
    pub fn default() -> Config {
        Config {
            app: None,
            redis: None,
            mysql: None,
        }
    }
}

pub fn parse_config(path: &str) -> anyhow::Result<(), anyhow::Error> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut buffer: Vec<u8> = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut buffer)?;
    let config: Config = toml::from_slice(buffer.as_slice())?;
    match mem::CONFIG.lock() {
        Ok(mut config_value) => {
            *config_value = config;
            Ok(())
        }
        Err(err) => Err(anyhow::Error::msg(err.to_string())),
    }
}
