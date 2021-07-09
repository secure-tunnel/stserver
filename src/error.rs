use std::{fmt::{Debug, Display, Formatter}, string::FromUtf8Error};

use clap::Format;

use crate::config::Config;

pub struct Error {
    code: ErrorKind,
    msg: String,
}

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub fn new(kind: ErrorKind, msg: &str) -> Error {
        Error {
            code: kind,
            msg: String::from(msg),
        }
    }

    pub fn mysql_convert(err: mysql::Error) -> Error {
        Error {
            code: ErrorKind::MYSQL,
            msg: err.to_string(),
        }
    }

    // 转为字节流
    pub fn to_vec(&self) -> Vec<u8> {
        todo!()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)?;

        Ok(())
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    DATA_INVALID,
    DATA_PACK,
    DATA_TYPE,
    DATA_UNPACK_OLDDATA_NOMATCH,
    DATA_IO,
    MYSQL,
    SM2_EVP_PKEY,
    TOML_DESERIALIZE,
    OS_POISONERROR,
    OS_FromUtf8Error,
    MYSQL_NO_DATA,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error {
            code: ErrorKind::DATA_IO,
            msg: String::from(err.to_string()),
        }
    }
}

impl From<mysql::Error> for Error {
    fn from(err: mysql::Error) -> Self {
        Error {
            code: ErrorKind::MYSQL,
            msg: err.to_string(),
        }
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error {
            code: ErrorKind::TOML_DESERIALIZE,
            msg: err.to_string(),
        }
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, Config>>> for Error {
    fn from(err: std::sync::PoisonError<std::sync::MutexGuard<'_, Config>>) -> Self {
        Error {
            code: ErrorKind::OS_POISONERROR,
            msg: err.to_string(),
        }
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Error{
            code: ErrorKind::OS_FromUtf8Error,
            msg: err.to_string(),
        }
    }
}