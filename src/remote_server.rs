use crate::decryption::Decryption;
use crate::encryption::Encryption;
use bytes::Buf;
use std::error::Error;
use std::net::Ipv4Addr;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::spawn;

pub struct RemoteServer {
    listen: String,
    first_key: String,
}

impl RemoteServer {
    pub fn new(first_key: String, listen: String) -> RemoteServer {
        RemoteServer { listen, first_key }
    }

    pub fn start(&mut self) -> Result<(), Box<dyn Error>> {
        info!("start remote server");
        Runtime::new().unwrap().block_on(self.run())
    }
}

impl RemoteServer {
    async fn client_socks5_handshake(first_key: String, client: TcpStream) {
        let (r0, w0) = client.into_split();

        let mut client_en = Encryption::new(first_key.clone(), w0);
        let mut client_de = Decryption::new(first_key.clone(), r0);

        // step 1
        match client_de.decryption_read().await {
            Err(err) => {
                warn!("client_socks5_handshake step 1-1 {:?}", err);
                return;
            }
            Ok(data) => {
                if data.len() != 3 {
                    warn!("client_socks5_handshake step 1-2 {:?}", data);
                    return;
                } else if data[0] != 0x05 || data[1] != 0x01 || data[2] != 0x00 {
                    warn!("client_socks5_handshake step 1-3 {:?}", data);
                    return;
                }
            }
        }

        // step 2
        if let Err(err) = client_en.encryption_write(&[0x05_u8, 0x00_u8]).await {
            warn!("client_socks5_handshake step 2 {:?}", err);
            return;
        }

        let mut target_addr = String::new();

        // step 3
        match client_de.decryption_read().await {
            Err(err) => {
                warn!("client_socks5_handshake step 3-1 {:?}", err);
                return;
            }
            Ok(data) => {
                if data.len() < 3 {
                    warn!("client_socks5_handshake step 3-2 {:?}", data);
                    return;
                } else if data[0] != 0x05 || data[1] != 0x01 || data[2] != 0x00 {
                    warn!("client_socks5_handshake step 3-3 {:?}", data);
                    return;
                }

                if data[3] == 0x03 {
                    // host
                    let host_len = (&data[4..5]).get_u64() as usize;
                    match std::str::from_utf8(&data[5..5 + host_len]) {
                        Err(err) => {
                            warn!("client_socks5_handshake step 3-4 {:?}", err);
                            return;
                        }
                        Ok(host) => {
                            let port = (&data[5 + host_len..5 + host_len + 2]).get_u16();
                            target_addr.push_str(format!("{}:{}", host, port).as_str());
                            warn!("client_socks5_handshake step 3-5 {:?}", &target_addr);
                        }
                    }
                } else if data[3] == 0x01 {
                    // ip
                    let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                    let port = (&data[8..10]).get_u16();
                    target_addr.push_str(format!("{}:{}", ip, port).as_str());
                } else {
                    warn!("client_socks5_handshake step 3-4");
                    return;
                }
            }
        }
        // step 4
        let resp: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        if let Err(err) = client_en.encryption_write(&resp).await {
            warn!("client_socks5_handshake step 4 {:?}", err);
            return;
        }

        info!("connect to {}", target_addr);

        match TcpStream::connect(&target_addr).await {
            Err(err) => {
                warn!(
                    "TcpStream::connect(&target_addr) {:?} {:?}",
                    &target_addr, err
                );
                return;
            }
            Ok(s1) => {
                let (r1, w1) = s1.into_split();
                spawn(Self::proc0(client_de, w1));
                spawn(Self::proc1(client_en, r1));
            }
        }
    }

    async fn proc0(mut client_de: Decryption, mut target_writer: OwnedWriteHalf) {
        loop {
            match client_de.decryption_read().await {
                Err(err) => {
                    debug!("client_de.decryption_read {:?}", err);
                    return;
                }
                Ok(data) => {
                    if let Err(err) = target_writer.write_all(&data).await {
                        debug!("target_writer.write_all {:?}", err);
                        return;
                    }
                }
            }
        }
    }

    async fn proc1(mut client_en: Encryption, mut target_reader: OwnedReadHalf) {
        let mut buffer = [0_u8; 2048];
        loop {
            match target_reader.read(&mut buffer).await {
                Err(err) => {
                    debug!("target_reader.read {:?}", err);
                    return;
                }
                Ok(n) => {
                    if n <= 0 {
                        debug!("target_reader.read eof");
                        return;
                    }
                    match client_en.encryption_write(&buffer[..n]).await {
                        Err(err) => {
                            debug!("client_en.encryption_write {:?}", err);
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let mut listenner = TcpListener::bind(&self.listen).await?;
        loop {
            let (client, _) = listenner.accept().await?;
            let first_key = self.first_key.clone();
            spawn(Self::client_socks5_handshake(first_key, client));
        }
    }
}
