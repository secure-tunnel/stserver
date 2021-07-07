
use std::{fs::File, io::{Read, Result}};
use serde_derive::Deserialize;
use std::error::Error;

use crate::store::mem;

#[derive(Deserialize)]
pub struct Config {
    app: Option<App>,
    redis: Option<Redis>,
    mysql: Option<Mysql>,

}

#[derive(Deserialize)]
pub struct App {
    tls_cert: String,
    tls_key: String,
}

#[derive(Deserialize)]
pub struct Redis {
    host: Vec<String>,
}

#[derive(Deserialize)]
pub struct Mysql {
    host: String,
    port: i32,
    user: String,
    passwd: String,
}

impl Config {
    pub fn default() -> Config {
        Config{
            app: None,
            redis: None,
            mysql: None,
        }
    }
}

pub fn parse_config(path: &str) -> Result<()> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut buffer: Vec<u8> = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut buffer)?;
    let config: Config = toml::from_slice(buffer.as_slice())?;
    if let Ok(mut config_value) = mem::CONFIG.lock() {
        *config_value = config;
    }else{
        
    }
    
    Ok(())
}