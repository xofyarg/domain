//! EDNS Options from RFC 8145.

use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use crate::bits::compose::Compose;
use crate::bits::message_builder::OptBuilder;
use crate::bits::octets::Octets;
use crate::bits::parse::{ParseAll, ParseAllError, Parser, ShortBuf};
use crate::iana::OptionCode;
use super::CodeOptData;


//------------ KeyTag -------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyTag<O: Octets=Bytes> {
    octets: O,
}

impl<O: Octets> KeyTag<O> {
    pub fn new(octets: O) -> Self {
        KeyTag { octets }
    }

    pub fn iter(&self) -> KeyTagIter {
        KeyTagIter(self.octets.as_ref())
    }
}

impl KeyTag<&'static [u8]> {
    pub fn push(
        builder: &mut OptBuilder,
        tags: &[u16]
    ) -> Result<(), ShortBuf> {
        let len = tags.len() * 2;
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::KeyTag, len as u16, |buf| {
            for tag in tags {
                buf.compose(&tag)?
            }
            Ok(())
        })
    }
}


//--- ParseAll and Compose

impl<O: Octets> ParseAll<O> for KeyTag<O> {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Self, Self::Err> {
        if len % 2 == 1 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::new(parser.parse_octets(len)?))
        }
    }
}

impl<O: Octets> Compose for KeyTag<O> {
    fn compose_len(&self) -> usize {
        self.octets.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.octets.as_ref())
    }
}


//--- CodeOptData

impl CodeOptData for KeyTag {
    const CODE: OptionCode = OptionCode::KeyTag;
}


//--- IntoIterator

impl<'a, O: Octets> IntoIterator for &'a KeyTag<O> {
    type Item = u16;
    type IntoIter = KeyTagIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ KeyTagIter ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct KeyTagIter<'a>(&'a [u8]);

impl<'a> Iterator for KeyTagIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            None
        }
        else {
            let (item, tail) = self.0.split_at(2);
            self.0 = tail;
            Some(BigEndian::read_u16(item))
        }
    }
}

