
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

pub enum ErrorKind {
    DATA_INVALID,
}