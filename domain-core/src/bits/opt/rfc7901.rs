//! EDNS Options from RFC 7901

use bytes::{Bytes, BufMut};
use crate::bits::compose::Compose;
use crate::bits::message_builder::OptBuilder;
use crate::bits::name::{Dname, ToDname};
use crate::bits::octets::Octets;
use crate::bits::parse::{ParseAll, Parser, ShortBuf};
use crate::iana::OptionCode;
use super::CodeOptData;


//------------ Chain --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Chain<O: Octets=Bytes> {
    start: Dname<O>,
}

impl<O: Octets> Chain<O> {
    pub fn new(start: Dname<O>) -> Self {
        Chain { start }
    }

    pub fn start(&self) -> &Dname<O> {
        &self.start
    }
}

impl Chain<&'static [u8]> {
    pub fn push<N: ToDname>(
        builder: &mut OptBuilder,
        start: &N
    ) -> Result<(), ShortBuf> {
        let len = start.compose_len();
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Chain, len as u16, |buf| {
            buf.compose(start)
        })
    }
}


//--- ParseAll and Compose

impl<O: Octets> ParseAll<O> for Chain<O> {
    type Err = <Dname as ParseAll>::Err;

    fn parse_all(
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Self, Self::Err> {
        Dname::parse_all(parser, len).map(Self::new)
    }
}

impl<O: Octets> Compose for Chain<O> {
    fn compose_len(&self) -> usize {
        self.start.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.start.compose(buf)
    }
}


//--- CodeOptData

impl<O: Octets> CodeOptData for Chain<O> {
    const CODE: OptionCode = OptionCode::Chain;
}

