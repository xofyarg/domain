//! Key and Signer using OpenSSL.
#![cfg(feature = "openssl")]

use std::convert::{TryFrom, TryInto};
use bytes::Bytes;
use domain_core::{Compose, ToDname};
use domain_core::iana::{DigestAlg, SecAlg};
use domain_core::rdata::{Ds, Dnskey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::Signer as OpenSslSigner;
use unwrap::unwrap;
use crate::key::{EcStoredKey, NumString, SigningKey, RsaStoredKey, StoredKey};


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
            StoredKey::Ec(ec) => Self::try_from(ec),
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

impl TryFrom<EcStoredKey> for Key {
    type Error = ErrorStack;

    fn try_from(key: EcStoredKey) -> Result<Self, Self::Error> {
        match key.algorithm {
            SecAlg::EcdsaP256Sha256 =>
                ecdsa_try_from(key, Nid::X9_62_PRIME256V1),
            SecAlg::EcdsaP384Sha384 =>
                ecdsa_try_from(key, Nid::SECP384R1),
            _ => unreachable!()
        }
    }
}

fn ecdsa_try_from(key: EcStoredKey, curve: Nid) -> Result<Key, ErrorStack> {
    let mut ctx = BigNumContext::new()?;
    let private = BigNum::try_from(key.private_key)?;
    let group = EcGroup::from_curve_name(curve)?;
    let mut public = EcPoint::new(&group)?;
    public.mul_generator(&group, &private, &ctx)?;
    let private = EcKey::from_private_components(&group, &private, &public)?;
    let public = public.to_bytes(
        &group, PointConversionForm::UNCOMPRESSED, &mut ctx
    )?;
    let public = Bytes::from(&public[1..]);
    Ok(Key {
        dnskey: Dnskey::new(256, 3, key.algorithm, public),
        key: PKey::from_ec_key(private)?,
    })
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
        use SecAlg::*;

        match self.dnskey.algorithm() {
            RsaSha1 | RsaSha1Nsec3Sha1 | RsaSha256 | RsaSha512 => {
                self.sign_rsa(data)
            }
            EcdsaP256Sha256 => {
                self.sign_ecdsa(data, MessageDigest::sha256(), 32)
            }
            EcdsaP384Sha384 => {
                self.sign_ecdsa(data, MessageDigest::sha384(), 48)
            }
            _ => unreachable!()
        }
    }
}

impl Key {
    fn sign_rsa(&self, data: &[u8]) -> Result<Bytes, ErrorStack> {
        let digest = match self.dnskey.algorithm() {
            SecAlg::RsaSha1 | SecAlg::RsaSha1Nsec3Sha1
                => Some(MessageDigest::sha1()),
            SecAlg::RsaSha256 => Some(MessageDigest::sha256()),
            SecAlg::RsaSha512 => Some(MessageDigest::sha512()),
            SecAlg::EcdsaP256Sha256 => Some(MessageDigest::sha256()),
            SecAlg::EcdsaP384Sha384 => Some(MessageDigest::sha384()),
            _ => None,
        };

        let mut signer = OpenSslSigner::new_intern(
            digest, &self.key
        )?;
        signer.update(data)?;
        signer.sign_to_vec().map(Into::into)
    }

    fn sign_ecdsa(
        &self,
        data: &[u8],
        digest: MessageDigest,
        part_len: usize
    ) -> Result<Bytes, ErrorStack> {
        let digest = hash(digest, data)?;
        let sig = EcdsaSig::sign(&digest, self.key.ec_key()?.as_ref())?;
        let mut res = vec![0u8; part_len * 2];
        let r = sig.r().to_vec();
        let r0 = unwrap!(part_len.checked_sub(r.len()));
        &mut res[r0..part_len].copy_from_slice(&r);
        let s = sig.s().to_vec();
        let s0 = part_len + unwrap!(part_len.checked_sub(s.len()));
        &mut res[s0..].copy_from_slice(&s);

        Ok(res.into())
    }
}


//------------ crate::key::NumString -----------------------------------------

impl TryFrom<NumString> for BigNum {
    type Error = ErrorStack;

    fn try_from(num: NumString) -> Result<Self, Self::Error> {
        BigNum::from_slice(num.as_ref())
    }
}

