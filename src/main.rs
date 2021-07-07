mod channel;
mod store;
mod error;
mod server;
mod sm;
mod utils;
mod config;

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use crate::server::Server;
use clap::{App, Arg};
use daemonize::Daemonize;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = App::new("Secure Tunnel Server")
        .version("0.1")
        .author("auhiewuil@gmail.com")
        .about("")
        .arg(
            Arg::from_usage("-c, --config=[FILE] 'Sets a custom config file'")
                .takes_value(true)
                .required(true)
                .short("c"),
        )
        .arg(Arg::from_usage("-d, --daemon 'Set process backgroud run'").short("d"))
        .get_matches();

    if let Some(c) = matches.value_of("config") {
        println!("Value of config： {}", c);
        // todo 解析配置文件
        config::parse_config(c).unwrap();
    }

    if let Some(daemon_idx) = matches.index_of("daemon") {
        if daemon_idx > 0 {
            println!("daemon is open");
            // todo 开启后网络不能listen socket
            let stdout = File::create("/tmp/stserver.out").unwrap();
            let stderr = File::create("/tmp/stserver.err").unwrap();

            let daemonize = Daemonize::new()
                .pid_file("/tmp/stserver.pid") // Every method except `new` and `start`
                .chown_pid_file(true) // is optional, see `Daemonize` documentation
                .working_directory(".") // for default behaviour.
                .user("nobody")
                .group("daemon") // Group name
                .umask(0o777) // Set umask, `0o027` by default.
                .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
                .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
                .chroot(".")
                .exit_action(|| println!("Executed before master process exits"))
                .privileged_action(|| {
                    println!("Executed before drop privileges");
                });

            match daemonize.start() {
                Ok(_) => println!("Success, daemonized"),
                Err(e) => eprintln!("Error, {}", e),
            }
        }
    }

    println!("stserver start......");

    let server = Server::new("0.0.0.0:3443");
    server::run(&server).await?;
    Ok(())
}
