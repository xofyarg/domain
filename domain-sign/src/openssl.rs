//! Key and Signer using OpenSSL.
#![cfg(feature = "openssl")]

use std::convert::{TryFrom, TryInto};
use bytes::Bytes;
use domain_core::{Compose, ToDname};
use domain_core::iana::{DigestAlg, SecAlg};
use domain_core::rdata::{Ds, Dnskey};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::Signer as OpenSslSigner;
use unwrap::unwrap;
use crate::key::{NumString, SigningKey, StoredKey, RsaStoredKey};


//------------ Key -----------------------------------------------------------

pub struct Key {
    dnskey: Dnskey,
    key: PKey<Private>,
}

impl Key {
    pub fn set_flags(&mut self, flags: u16) {
        self.dnskey.set_flags(flags);
    }
}


//--- TryFrom

impl TryFrom<StoredKey> for Key {
    type Error = ErrorStack;

    fn try_from(key: StoredKey) -> Result<Self, Self::Error> {
        match key {
            StoredKey::Rsa(rsa) => Self::try_from(rsa),
            _ => unimplemented!()
        }
    }
}

impl TryFrom<RsaStoredKey> for Key {
    type Error = ErrorStack;

    fn try_from(key: RsaStoredKey) -> Result<Self, Self::Error> {
        // Public key: exponent length | exponent | modulus.
        let mut public = Vec::new();
        if let Ok(len) = u8::try_from(key.public_exponent.len()) {
            // One byte exponent length.
            public.push(len)
        }
        else {
            // Two byte exponent length: 0 | exponent length
            public.push(0);
            let len = unwrap!(u16::try_from(key.public_exponent.len()));
            public.extend_from_slice(len.to_be_bytes().as_ref());
        }
        public.extend_from_slice(&key.public_exponent);
        public.extend_from_slice(&key.modulus);

        let private = openssl::rsa::RsaPrivateKeyBuilder::new(
            key.modulus.try_into()?,
            key.public_exponent.try_into()?,
            key.private_exponent.try_into()?,
        )?.set_factors(
            key.prime_1.try_into()?,
            key.prime_2.try_into()?
        )?.set_crt_params(
            key.exponent_1.try_into()?,
            key.exponent_2.try_into()?,
            key.coefficient.try_into()?
        )?.build();

        Ok(Key {
            dnskey: Dnskey::new(256, 3, key.algorithm, public.into()),
            key: PKey::from_rsa(private)?,
        })
    }
}


//--- SigningKey

impl SigningKey for Key {
    type Error = ErrorStack;

    fn dnskey(&self) -> Result<Dnskey, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error> {
        let mut buf = Vec::new();
        owner.compose_canonical(&mut buf);
        self.dnskey.compose_canonical(&mut buf);
        let digest = Bytes::from(sha256(&buf).as_ref());
        Ok(Ds::new(
            self.key_tag()?,
            self.dnskey.algorithm(),
            DigestAlg::Sha256,
            digest,
        ))
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error> {
        let digest = match self.dnskey.algorithm() {
            SecAlg::RsaSha1 | SecAlg::RsaSha1Nsec3Sha1
                => Some(MessageDigest::sha1()),
            SecAlg::RsaSha256 => Some(MessageDigest::sha256()),
            SecAlg::RsaSha512 => Some(MessageDigest::sha512()),
            _ => None,
        };

        let mut signer = OpenSslSigner::new_intern(
            digest, &self.key
        )?;
        signer.update(data)?;
        signer.sign_to_vec().map(Into::into)
    }
}


//------------ crate::key::NumString -----------------------------------------

impl TryFrom<NumString> for BigNum {
    type Error = ErrorStack;

    fn try_from(num: NumString) -> Result<Self, Self::Error> {
        BigNum::from_slice(num.as_ref())
    }
}

