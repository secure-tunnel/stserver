use std::fmt::{Display, Formatter};
use std::fmt;

pub struct Error {
    code: ErrorKind,
    msg: String,
}

impl Error {
    pub fn new(kind: ErrorKind, msg: &str) -> Error {
        Error{
            code: kind,
            msg: String::from(msg)
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)?;

        Ok(())
    }
}

pub enum ErrorKind {
    DATAPACK,
    DATA_INVALID,
    DATATYPE,
}