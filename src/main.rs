#[macro_use]
extern crate log;
extern crate jemallocator;

mod decryption;
mod encryption;
mod local_server;
mod remote_server;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::{crate_version, App, AppSettings, Arg, SubCommand};
use local_server::LocalServer;
use remote_server::RemoteServer;
use std::process::exit;

fn main() {
    env_logger::init();
    let matcher = App::new("proxy-rs")
        .version(crate_version!())
        .author("Arthur Yu yuya008@aliyun.com")
        .about("fuck GFW")
        .subcommand(
            SubCommand::with_name("local")
                .about("Local server")
                .arg(
                    Arg::with_name("listen")
                        .short("l")
                        .long("listen")
                        .default_value("127.0.0.1:6355")
                        .required(true)
                        .help("Listen on address"),
                )
                .arg(
                    Arg::with_name("remote-addr")
                        .short("r")
                        .long("remote-addr")
                        .default_value("0.0.0.0:8171")
                        .required(true)
                        .help("remote server addr"),
                )
                .arg(
                    Arg::with_name("first-key")
                        .short("k")
                        .long("first-key")
                        .default_value("")
                        .required(true)
                        .help("first key"),
                ),
        )
        .subcommand(
            SubCommand::with_name("remote")
                .about("Remote server")
                .arg(
                    Arg::with_name("listen")
                        .short("l")
                        .long("listen")
                        .default_value("0.0.0.0:8171")
                        .required(true)
                        .help("Listen on address"),
                )
                .arg(
                    Arg::with_name("first-key")
                        .short("k")
                        .long("first-key")
                        .default_value("")
                        .required(true)
                        .help("first key"),
                ),
        )
        .setting(AppSettings::SubcommandRequired)
        .get_matches();
    match matcher.subcommand() {
        ("local", Some(arg_matcher)) => {
            let listen = arg_matcher.value_of("listen").unwrap();
            let remote_addr = arg_matcher.value_of("remote-addr").unwrap();
            let first_key = arg_matcher.value_of("first-key").unwrap();

            LocalServer::new(
                first_key.to_string(),
                listen.to_string(),
                remote_addr.to_string(),
            )
            .start()
            .unwrap_or_else(|e| {
                eprintln!("{}", e);
                exit(1);
            });
        }
        ("remote", Some(arg_matcher)) => {
            let listen = arg_matcher.value_of("listen").unwrap();
            let first_key = arg_matcher.value_of("first-key").unwrap();

            RemoteServer::new(first_key.to_string(), listen.to_string())
                .start()
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    exit(1);
                });
        }
        _ => panic!(),
    }
}
