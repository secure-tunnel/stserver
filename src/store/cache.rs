#[cfg(test)]
mod test {
    use redis::Commands;

    #[test]
    fn test_conn() {
        // async {
        let client = redis::Client::open("redis://192.168.31.10/").unwrap();
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
