use bytes::BufMut;
use openssl::rand::rand_bytes;
use openssl::symm::{encrypt_aead, Cipher};
use std::io;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::prelude::*;

pub struct Encryption {
    cur_key: Vec<u8>,
    alg: Cipher,
    writer: OwnedWriteHalf,
}

impl Encryption {
    pub fn new(first_key: String, writer: OwnedWriteHalf) -> Encryption {
        Encryption {
            cur_key: first_key.into_bytes(),
            alg: Cipher::aes_256_gcm(),
            writer,
        }
    }

    fn gen_vi(&mut self) -> Vec<u8> {
        let iv_len = self.alg.iv_len().unwrap();
        let mut vi = vec![0_u8; iv_len];
        rand_bytes(&mut vi[..]).unwrap();
        vi
    }

    fn gen_aad(&mut self) -> Vec<u8> {
        let mut aad = vec![0_u8; 16];
        rand_bytes(&mut aad[..]).unwrap();
        aad
    }

    fn en(&mut self, data: &[u8]) -> Vec<u8> {
        let iv = self.gen_vi();
        let aad = self.gen_aad();

        let mut tag = [0_u8; 16];

        let ct = encrypt_aead(self.alg, &self.cur_key, Some(&iv), &aad, &data, &mut tag).unwrap();

        let mut buffer = vec![];
        io::Write::write(&mut buffer, &iv).unwrap();
        dbg!(&iv);
        io::Write::write(&mut buffer, &tag).unwrap();
        dbg!(&tag);
        io::Write::write(&mut buffer, &aad).unwrap();
        dbg!(&aad);
        buffer.put_u64(ct.len() as u64);
        dbg!(&ct, ct.len());
        dbg!(&self.cur_key);
        io::Write::write(&mut buffer, &ct).unwrap();
        buffer
    }

    pub async fn encryption_write(&mut self, buf: &[u8]) -> io::Result<()> {
        let data = self.en(buf);
        io::Result::Ok(self.writer.write_all(&data).await?)
    }
}
