use openssl::symm::Cipher;
use std::error::Error;
use std::net::ToSocketAddrs;

pub struct Config<'a> {
    pub mode: &'a str,
    pub listen: &'a str,
    pub remote_addr: &'a str,
    pub key: &'a str,
}

impl<'a> Config<'a> {
    pub fn new_local_server(listen: &'a str, remote_addr: &'a str, key: &'a str) -> Config<'a> {
        Config {
            mode: "local",
            listen,
            remote_addr,
            key,
        }
    }
    pub fn new_remote_server(listen: &'a str, key: &'a str) -> Config<'a> {
        Config {
            mode: "remote",
            listen,
            remote_addr: "",
            key,
        }
    }

    pub fn verification(&self) -> Result<(), Box<dyn Error>> {
        let cipher = Cipher::aes_256_gcm();

        match self.mode {
            "local" => {
                if self.key.len() != cipher.key_len() {
                    return Err(format!("`key` len != {}", cipher.key_len()).into());
                }
                if let Err(err) = self.listen.to_socket_addrs() {
                    return Err(format!("`listen` parameter error {}", err).into());
                }
                if let Err(err) = self.remote_addr.to_socket_addrs() {
                    return Err(format!("`remote-addr` parameter error {}", err).into());
                }
                Ok(())
            }
            "remote" => {
                if self.key.len() != cipher.key_len() {
                    return Err(format!("`key` len != {}", cipher.key_len()).into());
                }
                if let Err(err) = self.listen.to_socket_addrs() {
                    return Err(format!("`listen` parameter error {}", err).into());
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }
}
