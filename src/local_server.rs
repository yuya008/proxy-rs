use crate::decryption::Decryption;
use crate::encryption::Encryption;
use std::error::Error;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::spawn;

pub struct LocalServer {
    listen: String,
    remote_addr: String,
    key: String,
}

impl LocalServer {
    pub fn new(key: String, listen: String, remote_addr: String) -> LocalServer {
        LocalServer {
            listen,
            remote_addr,
            key,
        }
    }

    pub fn start(&mut self) -> Result<(), Box<dyn Error>> {
        info!("start local server");
        Runtime::new().unwrap().block_on(self.run())
    }
}

impl LocalServer {
    async fn proc0(key: String, r: OwnedReadHalf, mut w: OwnedWriteHalf) {
        let mut de = Decryption::new(key, r);
        loop {
            match de.decryption_read().await {
                Err(err) => {
                    debug!("de.decryption_read {:?}", err);
                    return;
                }
                Ok(data) => {
                    if let Err(err) = w.write_all(&data).await {
                        debug!("w.write_all {:?}", err);
                        return;
                    }
                }
            }
        }
    }
    async fn proc1(key: String, mut r: OwnedReadHalf, w: OwnedWriteHalf) {
        let mut buffer = [0_u8; 2048];
        let mut en = Encryption::new(key, w);
        loop {
            match r.read(&mut buffer).await {
                Err(err) => {
                    debug!("r.read {:?}", err);
                    return;
                }
                Ok(n) => {
                    if n <= 0 {
                        debug!("r.read eof");
                        return;
                    }
                    match en.encryption_write(&buffer[..n]).await {
                        Err(err) => {
                            debug!("en.encryption_write {:?}", err);
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    async fn process(s0: TcpStream, key: String, remote_addr: String) {
        match TcpStream::connect(&remote_addr).await {
            Ok(s1) => {
                let (r0, w0) = s0.into_split();
                let (r1, w1) = s1.into_split();
                let (k0, k1) = (key.clone(), key.clone());
                spawn(Self::proc0(k0, r1, w0));
                spawn(Self::proc1(k1, r0, w1));
            }
            Err(err) => {
                warn!(
                    "Unable to connect to remote server {:?} {:?}",
                    &remote_addr, err
                );
                return;
            }
        }
    }

    async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let mut listenner = TcpListener::bind(&self.listen).await?;
        loop {
            let (s0, _) = listenner.accept().await?;

            debug!("client {:?}", &s0);

            let remote_addr = self.remote_addr.clone();
            let key = self.key.clone();
            spawn(Self::process(s0, key, remote_addr));
        }
    }
}
