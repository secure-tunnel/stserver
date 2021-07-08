use std::fmt::format;

use mysql::{params, prelude::Queryable, Opts, Pool};

use super::mem;

pub struct AppClientKey {
    app_id: usize,
    client_type: usize,
    pubkey: String,
    prikey: String,
}

fn db_global_init() -> Pool {
    let config = &*mem::CONFIG.lock().unwrap();
    let mysql_name = &config.mysql.as_ref().unwrap().user;
    let mysql_passwd = &config.mysql.as_ref().unwrap().passwd;
    let mysql_host = &config.mysql.as_ref().unwrap().host;
    let mysql_port = &config.mysql.as_ref().unwrap().port;
    let url = format!("mysql://{}:{}@{}:{}/stserver", mysql_name, mysql_passwd, mysql_host, mysql_port);
    let pool = Pool::new(Opts::from_url(url.as_str()).unwrap()).unwrap();
    pool
}

pub fn get_with_app_client(
    app_id: usize,
    client_type: usize,
) -> anyhow::Result<Option<AppClientKey>> {
    let pool = db_global_init();
    let mut conn = pool.get_conn()?;
    let res = conn
        .exec_first(
            "select * from app_client_key where app_id= :appid and client_type=:clienttype",
            params! {
                "appid" => app_id,
                "clienttype" => client_type,
            },
        )
        .map(|row| {
            row.map(|(app_id, client_type, pubkey, prikey)| AppClientKey {
                app_id: app_id,
                client_type: client_type,
                pubkey: pubkey,
                prikey: prikey,
            })
        });

    match res {
        Ok(app_client_key) => Ok(app_client_key),
        Err(err) => Err(anyhow::Error::msg(err.to_string())),
    }
}

#[cfg(test)]
mod test {
    use crate::{config, store::db};

    #[test]
    fn test_get_with_app_client() {
        config::parse_config("test/config.toml");
        match db::get_with_app_client(1, 1).unwrap() {
            Some(app_client_key) => {
                println!("pubkey: {}", app_client_key.pubkey);
            }
            None => println!("not found data"),
        }
    }
}
