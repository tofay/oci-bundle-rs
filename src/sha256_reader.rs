use openssl::sha::Sha256;
use std::io::{Read, Result};

/// Wraps a reader and calculates the sha256 digest of data read from the inner reader
pub struct Sha256Reader<R: Read> {
    inner: R,
    sha: Sha256,
}

impl<R: Read> Sha256Reader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            sha: Sha256::new(),
        }
    }

    /// Return the hex encoded sha256 digest of the read data
    pub fn finish(mut self) -> Result<(String, R)> {
        // Read all the data to end to ensure the digest is calculated correctly
        let mut buffer = Vec::new();
        self.read_to_end(&mut buffer)?;
        Ok((hex::encode(self.sha.finish()), self.inner))
    }
}

impl<R: Read> Read for Sha256Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = self.inner.read(buf)?;
        self.sha.update(&buf[..len]);
        Ok(len)
    }
}
