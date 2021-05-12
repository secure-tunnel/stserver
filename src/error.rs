use std::fmt;
use std::fmt::{Debug, Display, Formatter};

pub struct Error {
    code: ErrorKind,
    msg: String,
}

impl Error {
    pub fn new(kind: ErrorKind, msg: &str) -> Error {
        Error {
            code: kind,
            msg: String::from(msg),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)?;

        Ok(())
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)?;
        Ok(())
    }
}

pub enum ErrorKind {
    DATAPACK,
    DATA_INVALID,
    DATATYPE,
    DATA_UNPACK_OLDDATA_NOMATCH,
}
