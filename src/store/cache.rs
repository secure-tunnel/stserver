use redis::{FromRedisValue, ToRedisArgs, Value};

pub struct Session {
    token: Vec<u8>,
    random_a: Vec<u8>,
    client_mac: Vec<u8>,
    random_b: Vec<u8>,
    pre_master_key: Vec<u8>,
    random_d: Vec<u8>,
    security_key: Vec<u8>,
}

impl FromRedisValue for Session {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let t = v.as_sequence().ok_or_else(|| "").unwrap();
        
        Ok(Session{
            token: Vec::from_redis_value(t.get(0).unwrap())?,
            random_a: Vec::from_redis_value(t.get(1).unwrap())?,
            client_mac: Vec::from_redis_value(t.get(2).unwrap())?,
            random_b: Vec::from_redis_value(t.get(3).unwrap())?,
            pre_master_key: Vec::from_redis_value(t.get(4).unwrap())?,
            random_d: Vec::from_redis_value(t.get(5).unwrap())?,
            security_key: Vec::from_redis_value(t.get(6).unwrap())?,
        })
    }
}

impl ToRedisArgs for Session {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + redis::RedisWrite {
        self.token.write_redis_args(out);
        self.random_a.write_redis_args(out);
        self.random_b.write_redis_args(out);
        self.random_d.write_redis_args(out);
        self.client_mac.write_redis_args(out);
        self.pre_master_key.write_redis_args(out);
        self.security_key.write_redis_args(out);
    }
}




#[cfg(test)]
mod test {
    use redis::{Commands, cluster::ClusterClient};

    #[test]
    fn test_conn() {
        // async {
        let nodes = vec!["redis://:secure_tunnel123@dev.liuweihua.cn:5601/", 
        "redis://:secure_tunnel123@dev.liuweihua.cn:5602/","redis://:secure_tunnel123@dev.liuweihua.cn:5603/", 
        "redis://:secure_tunnel123@dev.liuweihua.cn:5604/","redis://:secure_tunnel123@dev.liuweihua.cn:5605/", 
        "redis://:secure_tunnel123@dev.liuweihua.cn:5606/"];
        let client = ClusterClient::open(nodes).unwrap();
        let mut con = client.get_connection().unwrap();
        

        // con.set("key1", b"foo").unwrap();
        let x: String = redis::cmd("SET")
            .arg("key1")
            .arg("foo")
            .query(&mut con)
            .unwrap();
        let y: Vec<u8> = redis::cmd("SET")
            .arg(&["key2", "bar"])
            .query(&mut con)
            .unwrap();

        let result = redis::cmd("MGET").arg(&["key1", "key2"]).query(&mut con);
        assert_eq!(result, Ok(("foo".to_string(), b"bar".to_vec())));
        // }
    }
}
