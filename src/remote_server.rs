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
    async fn parse_socks5_host_addr(client_de: &mut Decryption) -> io::Result<String> {
        let mut host_len_buf = [0_u8, 1];
        client_de.decryption_read_exact(&mut host_len_buf).await?;

        let host_len = (&host_len_buf[..]).get_u64() as usize;

        // host
        let mut host = vec![0_u8; host_len];
        client_de.decryption_read_exact(&mut host).await?;

        // port
        let mut port_buf = [0_u8; 2];
        client_de.decryption_read_exact(&mut port_buf).await?;

        let port = (&port_buf[..]).get_u16();

        match std::str::from_utf8(&host[..]) {
            Err(err) => io::Result::Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            Ok(host) => io::Result::Ok(format!("{}:{}", host, port)),
        }
    }

    async fn parse_socks5_ip_addr(client_de: &mut Decryption) -> io::Result<String> {
        // ip
        let mut ip_buf = [0_u8, 6];
        client_de.decryption_read_exact(&mut ip_buf).await?;

        let port = (&ip_buf[4..]).get_u16();

        let ip = Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);

        io::Result::Ok(format!("{}:{}", ip, port))
    }

    async fn client_socks5_handshake(first_key: String, client: TcpStream) {
        let (r0, w0) = client.into_split();

        let mut client_en = Encryption::new(first_key.clone(), w0);
        let mut client_de = Decryption::new(first_key.clone(), r0);

        let mut data = [0_u8, 3];
        // step 1
        match client_de.decryption_read_exact(&mut data).await {
            Err(err) => {
                warn!("client_socks5_handshake step 1-1 {:?}", err);
                return;
            }
            Ok(read_n) => {
                if read_n != 3 {
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
            warn!("client_socks5_handshake step 2-1 {:?}", err);
            return;
        }

        let target_addr: String;
        let mut data = [0_u8, 4];

        // step 3
        match client_de.decryption_read_exact(&mut data).await {
            Err(err) => {
                warn!("client_socks5_handshake step 3-1 {:?}", err);
                return;
            }
            Ok(read_n) => {
                if read_n != 4 {
                    warn!("client_socks5_handshake step 3-2 {:?}", data);
                    return;
                } else if data[0] != 0x05 || data[1] != 0x01 || data[2] != 0x00 {
                    warn!("client_socks5_handshake step 3-3 {:?}", data);
                    return;
                }
            }
        }

        if data[3] == 0x03 {
            match Self::parse_socks5_host_addr(&mut client_de).await {
                Err(err) => {
                    warn!("client_socks5_handshake step 3-4 {:?}", err);
                    return;
                }
                Ok(s) => target_addr = s,
            };
        } else if data[3] == 0x01 {
            match Self::parse_socks5_ip_addr(&mut client_de).await {
                Err(err) => {
                    warn!("client_socks5_handshake step 3-5 {:?}", err);
                    return;
                }
                Ok(s) => target_addr = s,
            };
        } else {
            warn!("client_socks5_handshake step 3-4");
            return;
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
