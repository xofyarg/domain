//! EDNS Options from RFC 7314

use bytes::BufMut;
use crate::bits::compose::Compose;
use crate::bits::message_builder::OptBuilder;
use crate::bits::octets::Octets;
use crate::bits::parse::{ParseAll, Parser, ParseAllError, ShortBuf};
use crate::iana::OptionCode;
use super::CodeOptData;


//------------ Expire --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(Option<u32>);

impl Expire {
    pub fn new(expire: Option<u32>) -> Self {
        Expire(expire)
    }

    pub fn push(builder: &mut OptBuilder, expire: Option<u32>)
                -> Result<(), ShortBuf> {
        builder.push(&Self::new(expire))
    }

    pub fn expire(self) -> Option<u32> {
        self.0
    }
}


//--- ParseAll and Compose

impl<O: Octets> ParseAll<O> for Expire {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Self, Self::Err> {
        if len == 0 {
            Ok(Expire::new(None))
        }
        else {
            u32::parse_all(parser, len).map(|res| Expire::new(Some(res)))
        }
    }
}

impl Compose for Expire {
    fn compose_len(&self) -> usize {
        match self.0 {
            Some(_) => 4,
            None => 0,
        }
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        if let Some(value) = self.0 {
            value.compose(buf)
        }
    }
}


//--- OptData

impl CodeOptData for Expire {
    const CODE: OptionCode = OptionCode::Expire;
}

