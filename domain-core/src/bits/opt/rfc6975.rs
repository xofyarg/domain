//! EDNS Options from RFC 6975.

use std::slice;
use bytes::{BufMut, Bytes};
use crate::bits::compose::Compose;
use crate::bits::message_builder::OptBuilder;
use crate::bits::octets::Octets;
use crate::bits::parse::{ParseAll, Parser, ShortBuf};
use crate::iana::{OptionCode, SecAlg};
use super::CodeOptData;


//------------ Dau, Dhu, N3u -------------------------------------------------

macro_rules! option_type {
    ( $name:ident ) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name<O=Bytes> {
            octets: O,
        }

        impl<O> $name<O> {
            pub fn from_octets(octets: O) -> Self {
                $name { octets }
            }
        }

        impl<O: Octets> $name<O> {
            pub fn iter(&self) -> SecAlgsIter {
                SecAlgsIter::new(self.octets.as_ref())
            }
        }

        impl $name<&'static [u8]> {
            pub fn push(builder: &mut OptBuilder, algs: &[SecAlg])
                        -> Result<(), ShortBuf> {
                assert!(algs.len() <= ::std::u16::MAX as usize);
                builder.build(OptionCode::$name, algs.len() as u16, |buf| {
                    for alg in algs {
                        buf.compose(&alg.to_int())?
                    }
                    Ok(())
                })
            }
        }

        //--- ParseAll, Compose

        impl<O: Octets> ParseAll<O> for $name<O> {
            type Err = ShortBuf;

            fn parse_all(parser: &mut Parser<O>, len: usize)
                         -> Result<Self, Self::Err> {
                parser.parse_octets(len).map(Self::from_octets)
            }
        }

        impl<O: Octets> Compose for $name<O> {
            fn compose_len(&self) -> usize {
                self.octets.len()
            }

            fn compose<B: BufMut>(&self, buf: &mut B) {
                buf.put_slice(self.octets.as_ref())
            }
        }


        //--- CodeOptData
        
        impl<O> CodeOptData for $name<O> {
            const CODE: OptionCode = OptionCode::$name;
        }

        
        //--- IntoIter

        impl<'a, O: Octets> IntoIterator for &'a $name<O> {
            type Item = SecAlg;
            type IntoIter = SecAlgsIter<'a>;

            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }
    }
}

option_type!(Dau);
option_type!(Dhu);
option_type!(N3u);


//------------ SecAlgsIter ---------------------------------------------------

pub struct SecAlgsIter<'a>(slice::Iter<'a, u8>);

impl<'a> SecAlgsIter<'a> {
    fn new(slice: &'a [u8]) -> Self {
        SecAlgsIter(slice.iter())
    }
}

impl<'a> Iterator for SecAlgsIter<'a> {
    type Item = SecAlg;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| SecAlg::from_int(*x))
    }
}
