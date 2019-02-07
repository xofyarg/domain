/// EDNS0 Options from RFC 5001.

use std::fmt;
use bytes::{BufMut, Bytes};
use crate::bits::compose::Compose;
use crate::bits::message_builder::OptBuilder;
use crate::bits::octets::Octets;
use crate::bits::parse::{ParseAll, Parser, ShortBuf};
use crate::iana::OptionCode;
use super::CodeOptData;


//------------ Nsid ---------------------------------------------------------/

/// The Name Server Identifier (NSID) Option.
///
/// Specified in RFC 5001.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsid<O=Bytes> {
    octets: O
}

impl<O> Nsid<O> {
    pub fn new(octets: O) -> Self {
        Nsid { octets }
    }
}

impl Nsid<&'static [u8]> {
    pub fn push<T: AsRef<[u8]>>(builder: &mut OptBuilder, data: &T)
                                -> Result<(), ShortBuf> {
        let data = data.as_ref();
        assert!(data.len() <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Nsid, data.len() as u16, |buf| {
            buf.compose(data)
        })
    }
}

impl<O: Octets> ParseAll<O> for Nsid<O> {
    type Err = ShortBuf;

    fn parse_all(
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Self, Self::Err> {
        parser.parse_octets(len).map(Nsid::new)
    }
}

impl<O: Octets> CodeOptData for Nsid<O> {
    const CODE: OptionCode = OptionCode::Nsid;
}


impl<O: Octets> Compose for Nsid<O> {
    fn compose_len(&self) -> usize {
        self.octets.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        assert!(self.octets.len() < ::std::u16::MAX as usize);
        buf.put_slice(self.octets.as_ref())
    }
}

impl<O: Octets> fmt::Display for Nsid<O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // RFC 5001 § 2.4:
        // | User interfaces MUST read and write the contents of the NSID
        // | option as a sequence of hexadecimal digits, two digits per
        // | payload octet.
        for v in self.octets.as_ref() {
            write!(f, "{:X}", *v)?
        }
        Ok(())
    }
}

