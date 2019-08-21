use std::{error, io, ops};
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;
use bytes::Bytes;
use derive_more::{Display, From};
use unwrap::unwrap;
use domain_core::ToDname;
use domain_core::iana::SecAlg;
use domain_core::rdata::{Ds, Dnskey};
use domain_core::utils::base64;


//------------ SigningKey ----------------------------------------------------

pub trait SigningKey {
    type Error;

    fn dnskey(&self) -> Result<Dnskey, Self::Error>;
    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error>;

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.algorithm())
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.key_tag())
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error>;
}


impl<'a, K: SigningKey> SigningKey for &'a K {
    type Error = K::Error;

    fn dnskey(&self) -> Result<Dnskey, Self::Error> {
        (*self).dnskey()
    }
    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error> {
        (*self).ds(owner)
    }

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        (*self).algorithm()
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        (*self).key_tag()
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error> {
        (*self).sign(data)
    }
}


//------------ StoredKey -----------------------------------------------------

/// A type allowing to load a private key in the format used by Bind and ldns.
pub enum StoredKey {
    Rsa(RsaStoredKey),
    Ec(EcStoredKey),
}

impl StoredKey {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        Self::read(&mut BufReader::new(File::open(path)?).lines())
    }

    pub fn read<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<Self, LoadError> {
        Self::read_version(lines)?;
        let algorithm = Self::read_algorithm(lines)?;
        match algorithm {
            SecAlg::RsaMd5 | SecAlg::RsaSha1 | SecAlg::RsaSha1Nsec3Sha1 |
            SecAlg::RsaSha256 | SecAlg::RsaSha512 => {
                RsaStoredKey::load(algorithm, lines).map(StoredKey::Rsa)
            }
            SecAlg::EcdsaP256Sha256 | SecAlg::EcdsaP384Sha384 |
            SecAlg::Ed25519 | SecAlg::Ed448 => {
                EcStoredKey::load(algorithm, lines).map(StoredKey::Ec)
            }
            _ => Err(LoadError::UnsupportedAlgorithm(algorithm))
        }
    }

    fn read_version<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<(), LoadError> {
        let line = Line::read(lines, "Private-key-format")?;
        if !line.starts_with("v1.") {
            Err(LoadError::UnsupportedVersion(line.as_ref().into()))
        }
        else {
            Ok(())
        }
    }

    fn read_algorithm<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<SecAlg, LoadError> {
        let line = Line::read(lines, "Algorithm")?;
        SecAlg::from_str(line.first_token().unwrap_or("")).map_err(|_| {
            LoadError::InvalidParameterValue("Algorithm")
        })
    }
}


//------------ RsaStoredKey --------------------------------------------------

pub struct RsaStoredKey {
    pub algorithm: SecAlg,
    pub modulus: NumString,             // n
    pub public_exponent: NumString,     // e
    pub private_exponent: NumString,    // d
    pub prime_1: NumString,             // p
    pub prime_2: NumString,             // q
    pub exponent_1: NumString,          // d mod (p - 1)
    pub exponent_2: NumString,          // d mod (q - 1)
    pub coefficient: NumString,         // q^-1 mod p
}

impl RsaStoredKey {
    fn load<R: io::BufRead>(
        algorithm: SecAlg, lines: &mut io::Lines<R>
    ) -> Result<Self, LoadError> {
        Ok(RsaStoredKey {
            algorithm,
            modulus: Line::read_num(lines, "Modulus", 512)?,
            public_exponent: Line::read_num(lines, "PublicExponent", 512)?,
            private_exponent: Line::read_num(lines, "PrivateExponent", 512)?,
            prime_1: Line::read_num(lines, "Prime1", 512)?,
            prime_2: Line::read_num(lines, "Prime2", 512)?,
            exponent_1: Line::read_num(lines, "Exponent1", 512)?,
            exponent_2: Line::read_num(lines, "Exponent2", 512)?,
            coefficient: Line::read_num(lines, "Coefficient", 512)?,
        })
    }

    pub fn to_dnskey(&self, flags: u16) -> Dnskey {
        let mut public = Vec::new();
        if let Ok(len) = u8::try_from(self.public_exponent.len()) {
            // One byte exponent length.
            public.push(len)
        }
        else {
            // Two byte exponent length: 0 | exponent length
            public.push(0);
            let len = unwrap!(u16::try_from(self.public_exponent.len()));
            public.extend_from_slice(len.to_be_bytes().as_ref());
        }
        public.extend_from_slice(&self.public_exponent);
        public.extend_from_slice(&self.modulus);
        Dnskey::new(flags, 3, self.algorithm, public.into())
    }

    pub fn into_der(self) -> Vec<u8> {
        let mut res = vec![0x30];
        append_der_len(
            3 // version
            + self.modulus.der_len()
            + self.public_exponent.der_len()
            + self.private_exponent.der_len()
            + self.prime_1.der_len()
            + self.prime_2.der_len()
            + self.exponent_1.der_len()
            + self.exponent_2.der_len()
            + self.coefficient.der_len(),
            &mut res,
        );
        res.extend_from_slice(b"\x02\x01\x00");
        self.modulus.append_as_der(&mut res);
        self.public_exponent.append_as_der(&mut res);
        self.private_exponent.append_as_der(&mut res);
        self.prime_1.append_as_der(&mut res);
        self.prime_2.append_as_der(&mut res);
        self.exponent_1.append_as_der(&mut res);
        self.exponent_2.append_as_der(&mut res);
        self.coefficient.append_as_der(&mut res);
        res
    }
}


//------------ EcStoredKey ---------------------------------------------------

pub struct EcStoredKey {
    pub algorithm: SecAlg,
    pub private_key: NumString,
}

impl EcStoredKey {
    fn load<R: io::BufRead>(
        algorithm: SecAlg,
        lines: &mut io::Lines<R>
    ) -> Result<Self, LoadError> {
        Ok(EcStoredKey {
            algorithm,
            private_key: Line::read(lines, "PrivateKey")?.try_into()?,
        })
    }
}


//------------ Line ----------------------------------------------------------

struct Line {
    line: String,
    start: usize,
    end: usize
}

impl Line {
    fn read<R: io::BufRead>(
        lines: &mut io::Lines<R>,
        key: &'static str
    ) -> Result<Line, LoadError> {
        let line = match lines.next() {
            Some(line) => line?,
            None => {
                return Err(LoadError::SyntaxError)
            }
        };
        Line::new(line, key)
    }

    fn read_num<R: io::BufRead>(
        lines: &mut io::Lines<R>,
        key: &'static str,
        max_len: usize,
    ) -> Result<NumString, LoadError> {
        let res = NumString::try_from(Self::read(lines, key)?)?;
        if res.len() > max_len {
            Err(LoadError::InvalidParameterValue(key))
        }
        else {
            Ok(res)
        }
    }

    fn new(line: String, key: &str) -> Result<Self, LoadError> {
        let mut res = Line { end: line.len(), line, start: 0 };
        res.trim();
        if !res.starts_with(key) {
            return Err(LoadError::SyntaxError)
        }
        res.start += key.len();
        res.trim();
        if !res.starts_with(':') {
            return Err(LoadError::SyntaxError)
        }
        res.start += 1;
        res.trim();
        Ok(res)
    }

    fn as_str(&self) -> &str {
        &self.line[self.start..self.end]
    }

    fn trim(&mut self) {
        self.start += self.as_str().len() - self.as_str().trim_start().len();
        self.end -= self.as_str().len() - self.as_str().trim_end().len();
    }

    fn first_token(&self) -> Option<&str> {
        self.as_str().split_ascii_whitespace().next()
    }
}

impl ops::Deref for Line {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Line {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}


//------------ NumString -----------------------------------------------------

pub struct NumString(Vec<u8>);

impl NumString {
    fn der_len(&self) -> usize {
        let len = match self.0.first() {
            Some(&ch) if ch > 0x7f => {
                self.0.len() + 1
            }
            Some(_) => self.0.len(),
            None => 1
        };
        1 + der_len_len(len) + len
    }

    fn append_as_der(&self, target: &mut Vec<u8>) {
        target.push(0x02);
        match self.0.first() {
            Some(&ch) if ch > 0x7F => {
                append_der_len(self.0.len() + 1, target);
                target.push(0);
                target.extend_from_slice(&self.0);
            }
            Some(_) => {
                append_der_len(self.0.len(), target);
                target.extend_from_slice(&self.0);
            }
            None => {
                append_der_len(1, target);
                target.push(0);
            }
        }
    }
}

impl TryFrom<String> for NumString {
    type Error = io::Error;

    fn try_from(line: String) -> Result<Self, io::Error> {
        base64::decode_to_vec(&line).map_err(|err| {
            io::Error::new(io::ErrorKind::Other, err)
        }).map(NumString)
    }
}

impl TryFrom<Line> for NumString {
    type Error = io::Error;

    fn try_from(line: Line) -> Result<Self, io::Error> {
        base64::decode_to_vec(&line).map_err(|err| {
            io::Error::new(io::ErrorKind::Other, err)
        }).map(NumString)
    }
}

impl ops::Deref for NumString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for NumString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//============ Helpers =======================================================

fn der_len_len(len: usize) -> usize {
    if len < 0x80 { 1 }
    else if len < 0x1_00 { 2 }
    else if len < 0x1_0000 { 3 }
    else if len < 0x100_0000 { 4 }
    else {
        panic!("excessive length")
    }
}

fn append_der_len(len: usize, target: &mut Vec<u8>) {
    if len < 0x80 {
        target.push(len as u8);
    }
    else if len < 0x1_00 {
        target.push(0x81);
        target.push(len as u8);
    }
    else if len < 0x1_0000 {
        target.push(0x82);
        target.extend_from_slice(&(len as u16).to_be_bytes());
    }
    else if len < 0x100_0000 {
        let bytes = (len as u32).to_be_bytes();
        target.push(0x83);
        target.extend_from_slice(&bytes[1..]);
    }
    else if len < 0x1_0000_0000 {
        target.push(0x84);
        target.extend_from_slice(&(len as u32).to_be_bytes());
    }
    else {
        panic!("excessive length")
    }
}


//============ Errors ========================================================

#[derive(Debug, Display, From)]
pub enum LoadError {
    #[display(fmt = "unsupported algorithm {}", _0)]
    UnsupportedAlgorithm(SecAlg),

    #[display(fmt = "unsupported format version {}", _0)]
    UnsupportedVersion(String),

    #[display(fmt = "unexpected parameter {}", _0)]
    UnexpectedParameter(String),

    #[display(fmt = "invalid value for parameter {}", _0)]
    InvalidParameterValue(&'static str),

    #[display(fmt = "syntax error")]
    SyntaxError,

    #[display(fmt = "{}", _0)]
    Io(io::Error),
}

impl error::Error for LoadError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::io::BufRead;
    use unwrap::unwrap;
    use super::*;

    #[test]
    fn load_stored_rsa() {
        let data = include_bytes!("../test-data/rsa.private");
        let mut lines = io::Cursor::new(data.as_ref()).lines();
        let _ = unwrap!(StoredKey::read(&mut lines));
    }
}

