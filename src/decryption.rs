use bytes::Buf;
use openssl::symm::{decrypt_aead, Cipher};
use std::io;
use std::io::{Error, ErrorKind, Write};
use tokio::net::tcp::OwnedReadHalf;
use tokio::prelude::*;

pub struct Decryption {
    cur_key: Vec<u8>,
    alg: Cipher,
    reader: OwnedReadHalf,
}

impl Decryption {
    pub fn new(first_key: String, reader: OwnedReadHalf) -> Decryption {
        Decryption {
            cur_key: first_key.into_bytes(),
            alg: Cipher::aes_256_gcm(),
            reader,
        }
    }

    pub async fn decryption_read(&mut self) -> io::Result<Vec<u8>> {
        self.read().await
    }
}

impl Decryption {
    fn head_size(&self) -> usize {
        self.alg.iv_len().unwrap_or(0) + 32 + 8
    }

    fn read_iv<'a>(&self, head: &'a [u8]) -> &'a [u8] {
        let iv_len = self.alg.iv_len().unwrap();
        &head[..iv_len]
    }

    fn read_tag<'a>(&self, head: &'a [u8]) -> &'a [u8] {
        let iv_len = self.alg.iv_len().unwrap();
        &head[iv_len..iv_len + 16]
    }

    fn read_aad<'a>(&self, head: &'a [u8]) -> &'a [u8] {
        let start = self.alg.iv_len().unwrap() + 16;
        &head[start..start + 16]
    }

    fn read_body_size<'a>(&self, head: &'a [u8]) -> usize {
        let index = self.alg.iv_len().unwrap() + 32;
        head[index..].as_ref().get_u64() as usize
    }

    fn set_key(&mut self, buf: &[u8]) {
        (&mut self.cur_key[..]).write(buf).unwrap();
    }

    async fn read_head(&mut self) -> io::Result<Vec<u8>> {
        let mut head_buffer = vec![0_u8; self.head_size()];
        self.reader.read_exact(&mut head_buffer).await?;
        Ok(head_buffer)
    }

    async fn read_body(&mut self, body_size: usize) -> io::Result<Vec<u8>> {
        let mut body_buffer = vec![0_u8; body_size];
        self.reader.read_exact(&mut body_buffer).await?;
        Ok(body_buffer)
    }

    async fn read(&mut self) -> io::Result<Vec<u8>> {
        let head_buffer = self.read_head().await?;
        let iv = self.read_iv(&head_buffer);
        let tag = self.read_tag(&head_buffer);
        let aad = self.read_aad(&head_buffer);
        let body_size = self.read_body_size(&head_buffer);

        let pt_buffer = self.read_body(body_size).await?;

        match decrypt_aead(self.alg, &self.cur_key, Some(iv), aad, &pt_buffer, tag) {
            Err(err) => Err(Error::new(ErrorKind::InvalidData, err)),
            Ok(data) => {
                let new_key = &data[..self.alg.key_len()];
                let plain_text = &data[self.alg.key_len()..];
                self.set_key(new_key);
                io::Result::Ok(plain_text.to_vec())
            }
        }
    }
}
