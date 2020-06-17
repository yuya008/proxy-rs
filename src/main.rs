#[macro_use]
extern crate log;

#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

mod config;
mod decryption;
mod encryption;
mod local_server;
mod remote_server;

use crate::config::Config;
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
                    Arg::with_name("key")
                        .short("k")
                        .long("key")
                        .default_value("")
                        .required(true)
                        .help("key"),
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
                    Arg::with_name("key")
                        .short("k")
                        .long("key")
                        .default_value("")
                        .required(true)
                        .help("key"),
                ),
        )
        .setting(AppSettings::SubcommandRequired)
        .get_matches();
    match matcher.subcommand() {
        ("local", Some(arg_matcher)) => {
            let listen = arg_matcher.value_of("listen").unwrap();
            let remote_addr = arg_matcher.value_of("remote-addr").unwrap();
            let key = arg_matcher.value_of("key").unwrap();

            let config = Config::new_local_server(listen, remote_addr, key);

            LocalServer::new(config)
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    exit(1);
                })
                .start()
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    exit(1);
                });
        }
        ("remote", Some(arg_matcher)) => {
            let listen = arg_matcher.value_of("listen").unwrap();
            let key = arg_matcher.value_of("key").unwrap();

            let config = Config::new_remote_server(listen, key);

            RemoteServer::new(config)
                .unwrap_or_else(|e| {
                    error!("{:?}", e);
                    exit(1);
                })
                .start()
                .unwrap_or_else(|e| {
                    error!("{:?}", e);
                    exit(1);
                });
        }
        _ => unreachable!(),
    }
}
