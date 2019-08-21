//! Key and Signer using ring.
#![cfg(feature = "ringsigner")]

use std::error;
use bytes::Bytes;
use derive_more::{Display, From};
use domain_core::{Compose, ToDname};
use domain_core::iana::{DigestAlg, SecAlg};
use domain_core::rdata::{Ds, Dnskey};
use ring::digest;
use ring::error::{KeyRejected, Unspecified};
use ring::rand::SecureRandom;
use ring::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, RsaEncoding,
    RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, 
    ECDSA_P384_SHA384_FIXED_SIGNING, RSA_PKCS1_SHA256, RSA_PKCS1_SHA512,
};
use crate::key::{EcStoredKey, SigningKey, StoredKey, RsaStoredKey};


//------------ Key -----------------------------------------------------------

pub struct Key<'a> {
    dnskey: Dnskey,
    key: RingKey,
    rng: &'a dyn SecureRandom,
}

#[allow(clippy::large_enum_variant)] // consider boxing RsaKeyPair.
enum RingKey {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair, &'static dyn RsaEncoding),
}

impl<'a> Key<'a> {
    pub fn from_stored(
        key: StoredKey,
        rng: &'a dyn SecureRandom
    ) -> Result<Self, StoredKeyError> {
        match key {
            StoredKey::Rsa(key) => Self::from_stored_rsa(key, rng),
            StoredKey::Ec(key) => Self::from_stored_ec(key, rng),
        }
    }

    fn from_stored_rsa(
        key: RsaStoredKey,
        rng: &'a dyn SecureRandom
    ) -> Result<Self, StoredKeyError> {
        let encoding = match key.algorithm {
            SecAlg::RsaSha256 => &RSA_PKCS1_SHA256,
            SecAlg::RsaSha512 => &RSA_PKCS1_SHA512,
            alg => return Err(alg.into()),
        };
        let dnskey = key.to_dnskey(256);
        let der = key.into_der();
        Ok(Key {
            dnskey,
            key: RingKey::Rsa(
                RsaKeyPair::from_der(&der)?,
                encoding
            ),
            rng
        })
    }

    fn from_stored_ec(
        key: EcStoredKey,
        rng: &'a dyn SecureRandom
    ) -> Result<Self, StoredKeyError> {
        match key.algorithm {
            SecAlg::EcdsaP256Sha256 => {
                Self::from_stored_ecdsa(
                    key, rng, &ECDSA_P256_SHA256_FIXED_SIGNING
                )
            }
            SecAlg::EcdsaP384Sha384 => {
                Self::from_stored_ecdsa(
                    key, rng, &ECDSA_P384_SHA384_FIXED_SIGNING
                )
            }
            SecAlg::Ed25519 => {
                Self::from_stored_ed25519(key, rng)
            }
            alg => Err(StoredKeyError::UnsupportedAlgorithm(alg)),
        }
    }

    fn from_stored_ecdsa(
        key: EcStoredKey,
        rng: &'a dyn SecureRandom,
        alg: &'static EcdsaSigningAlgorithm,
    ) -> Result<Self, StoredKeyError> {
        let ringkey = EcdsaKeyPair::from_private_key_unchecked(
            alg, &key.private_key
        )?;
        let dnskey = Dnskey::new(
            256, 3, key.algorithm, 
            ringkey.public_key().as_ref()[1..].into()
        );
        Ok(Key { dnskey, key: RingKey::Ecdsa(ringkey), rng })
    }

    fn from_stored_ed25519(
        key: EcStoredKey,
        rng: &'a dyn SecureRandom
    ) -> Result<Self, StoredKeyError> {
        let ringkey = Ed25519KeyPair::from_seed_unchecked(&key.private_key)?;
        let dnskey = Dnskey::new(
            256, 3, key.algorithm, 
            ringkey.public_key().as_ref()[1..].into()
        );
        Ok(Key { dnskey, key: RingKey::Ed25519(ringkey), rng })
    }

    pub fn throwaway_13(
        flags: u16,
        rng: &'a dyn SecureRandom
    ) -> Result<Self, Unspecified> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING, rng
        )?;
        let keypair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref()
        )?;
        let public_key = keypair.public_key().as_ref()[1..].into();
        Ok(Key {
            dnskey: Dnskey::new(
                flags, 3, SecAlg::EcdsaP256Sha256, public_key
            ),
            key: RingKey::Ecdsa(keypair),
            rng
        })
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.dnskey.set_flags(flags);
    }
}

impl<'a> SigningKey for Key<'a> {
    type Error = Unspecified;

    fn dnskey(&self) -> Result<Dnskey, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error> {
        let mut buf = Vec::new();
        owner.compose_canonical(&mut buf);
        self.dnskey.compose_canonical(&mut buf);
        let digest = digest::digest(&digest::SHA256, &buf);
        Ok(Ds::new(
            self.key_tag()?,
            self.dnskey.algorithm(),
            DigestAlg::Sha256,
            Bytes::from(digest.as_ref())
        ))
    }

    fn sign(&self, msg: &[u8]) -> Result<Bytes, Self::Error> {
        match self.key {
            RingKey::Ecdsa(ref key) => {
                Ok(Bytes::from(key.sign(self.rng, msg)?.as_ref()))
            }
            RingKey::Ed25519(ref key) => {
                Ok(Bytes::from(key.sign(msg).as_ref()))
            }
            RingKey::Rsa(ref key, encoding) => {
                let mut sig = vec![0; key.public_modulus_len()];
                key.sign(encoding, self.rng, msg, &mut sig)?;
                Ok(sig.into())
            }
        }
    }
}


//============ Errors ========================================================

#[derive(Debug, Display, From)]
pub enum StoredKeyError {
    #[display(fmt = "unsupported algorithm {}", _0)]
    UnsupportedAlgorithm(SecAlg),

    #[display(fmt = "key rejected: {}", _0)]
    Rejected(KeyRejected)
}

impl error::Error for StoredKeyError { }
