use mysql::{params, prelude::Queryable, Opts, Pool};

use crate::error::{self, Error};

use super::mem;

pub struct AppClientKey {
    pub app_id: usize,
    pub client_type: usize,
    pub serialid: String,
    pub pubkey: String,
    pub prikey: String,
}

fn db_global_init() -> Pool {
    let config = &*mem::CONFIG.lock().unwrap();
    let mysql_name = &config.mysql.as_ref().unwrap().user;
    let mysql_passwd = &config.mysql.as_ref().unwrap().passwd;
    let mysql_host = &config.mysql.as_ref().unwrap().host;
    let mysql_port = &config.mysql.as_ref().unwrap().port;
    let url = format!(
        "mysql://{}:{}@{}:{}/stserver",
        mysql_name, mysql_passwd, mysql_host, mysql_port
    );
    let pool = Pool::new(Opts::from_url(url.as_str()).unwrap()).unwrap();
    pool
}

impl AppClientKey {
    pub fn get_with_app_client(serialid: &str) -> error::Result<Option<AppClientKey>> {
        let pool = db_global_init();
        let mut conn = pool.get_conn()?;
        let res = conn
            .exec_first(
                "select * from app_client_key where serialid=:serialid",
                params! {
                    "serialid" => serialid,
                },
            )
            .map(|row| {
                row.map(
                    |(app_id, client_type, serialid, pubkey, prikey)| AppClientKey {
                        app_id: app_id,
                        client_type: client_type,
                        serialid: serialid,
                        pubkey: pubkey,
                        prikey: prikey,
                    },
                )
            });

        Ok(res?)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        config,
        store::db::{self, AppClientKey},
    };

    #[test]
    fn test_get_with_app_client() {
        config::parse_config("test/config.toml");
        match AppClientKey::get_with_app_client("123456").unwrap() {
            Some(app_client_key) => {
                println!("pubkey: {}", app_client_key.pubkey);
            }
            None => println!("not found data"),
        }
    }
}
