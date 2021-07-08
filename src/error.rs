use std::fmt::{Debug, Display, Formatter};

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

pub enum ErrorKind {
    DATA_INVALID,
    DATA_PACK,
    DATA_TYPE,
    DATA_UNPACK_OLDDATA_NOMATCH,
    DATA_IO,
    MYSQL,
    SM2_EVP_PKEY,
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
