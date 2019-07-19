use std::{io, ops};
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;
use bytes::Bytes;
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
    Dsa(DsaStoredKey),
    Gost(GostStoredKey),
    Ec(EcStoredKey),
}

impl StoredKey {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        Self::read(&mut BufReader::new(File::open(path)?).lines())
    }

    pub fn read<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<Self, io::Error> {
        Self::read_version(lines)?;
        let algorithm = Self::read_algorithm(lines)?;
        match algorithm {
            SecAlg::RsaMd5 | SecAlg::RsaSha1 | SecAlg::RsaSha1Nsec3Sha1 |
            SecAlg::RsaSha256 | SecAlg::RsaSha512 => {
                RsaStoredKey::load(algorithm, lines).map(StoredKey::Rsa)
            }
            SecAlg::Dsa | SecAlg::DsaNsec3Sha1 => {
                DsaStoredKey::load(algorithm, lines).map(StoredKey::Dsa)
            }
            SecAlg::EccGost => {
                GostStoredKey::load(lines).map(StoredKey::Gost)
            }
            SecAlg::EcdsaP256Sha256 | SecAlg::EcdsaP384Sha384 |
            SecAlg::Ed25519 | SecAlg::Ed448 => {
                EcStoredKey::load(algorithm, lines).map(StoredKey::Ec)
            }
            _ => {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unsupported algorithm {}", algorithm)
                ))
            }
        }
    }

    fn read_version<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<(), io::Error> {
        let line = Line::read(lines, "Private-key-format")?;
        if !line.starts_with("v1.") {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported file format version"
            ))
        }
        else {
            Ok(())
        }
    }

    fn read_algorithm<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<SecAlg, io::Error> {
        let line = Line::read(lines, "Algorithm")?;
        SecAlg::from_str(line.first_token().unwrap_or("")).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "invalid algorithm")
        }).map(|alg| { dbg!(alg); alg} )
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
    ) -> Result<Self, io::Error> {
        let res = RsaStoredKey {
            algorithm,
            modulus: Line::read(lines, "Modulus")?.try_into()?,
            public_exponent: Line::read(lines, "PublicExponent")?.try_into()?,
            private_exponent: Line::read(lines, "PrivateExponent")?.try_into()?,
            prime_1: Line::read(lines, "Prime1")?.try_into()?,
            prime_2: Line::read(lines, "Prime2")?.try_into()?,
            exponent_1: Line::read(lines, "Exponent1")?.try_into()?,
            exponent_2: Line::read(lines, "Exponent2")?.try_into()?,
            coefficient: Line::read(lines, "Coefficient")?.try_into()?,
        };
        if res.modulus.len() > 4096 || res.public_exponent.len() > 4096 {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "bad key component size"
            ))
        }
        else {
            Ok(res)
        }
    }
}


//------------ DsaStoredKey --------------------------------------------------

pub struct DsaStoredKey {
    pub algorithm: SecAlg,
    pub primep: NumString,          // p
    pub subprimeq: NumString,       // q
    pub baseg: NumString,           // g
    pub private_valuex: NumString,  // x
    pub public_valuey: NumString,   // y
}

impl DsaStoredKey {
    fn load<R: io::BufRead>(
        algorithm: SecAlg,
        lines: &mut io::Lines<R>
    ) -> Result<Self, io::Error> {
        Ok(DsaStoredKey {
            algorithm,
            primep: Line::read(lines, "Primep")?.try_into()?,
            subprimeq: Line::read(lines, "Subprimeq")?.try_into()?,
            baseg: Line::read(lines, "Baseg")?.try_into()?,
            private_valuex: Line::read(lines, "Private_valuex")?.try_into()?,
            public_valuey: Line::read(lines, "Public_valuey")?.try_into()?,
        })
    }
}


//------------ GostStoredKey -------------------------------------------------

pub struct GostStoredKey {
    pub asn1: NumString,
}

impl GostStoredKey {
    fn load<R: io::BufRead>(
        lines: &mut io::Lines<R>
    ) -> Result<Self, io::Error> {
        let mut line = Line::read(lines, "GostAsn1")?.into_string();
        while line.len() < 96 {
            line.push_str(Line::read_full(lines)?.as_str());
        }
        Ok(GostStoredKey {
            asn1: line.try_into()?,
        })
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
    ) -> Result<Self, io::Error> {
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
        key: &str
    ) -> Result<Line, io::Error> {
        let line = match lines.next() {
            Some(line) => line?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "more lines expected"
                ))
            }
        };
        Line::new(line, key)
    }

    fn read_full<R: io::BufRead>(
        lines: &mut io::Lines<R>,
    ) -> Result<Line, io::Error> {
        let line = match lines.next() {
            Some(line) => line?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "more lines expected"
                ))
            }
        };
        let mut res = Line { end: line.len(), line, start: 0 };
        res.trim();
        Ok(res)
    }

    fn new(line: String, key: &str) -> Result<Self, io::Error> {
        let mut res = Line { end: line.len(), line, start: 0 };
        res.trim();
        if !res.starts_with(key) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("expected key '{}'", key)
            ))
        }
        res.start += key.len();
        res.trim();
        if !res.starts_with(":") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("expected key '{}'", key)
            ))
        }
        res.start += 1;
        res.trim();
        Ok(res)
    }

    fn as_str(&self) -> &str {
        &self.line[self.start..self.end]
    }

    fn into_string(self) -> String {
        self.as_str().into()
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
        let _ = unwrap!(StoredKey::load(&mut lines));
    }
}
