// XXX TODO: Easier access to individual options.
// XXX TODO: Documentation and tests.
//
//! Record data for OPT records.
//!
//! Since DNS message headers are relatively short, the amount of information
//! that can be conveyed through them is very limited. In order to provide an
//! extensible means to transmit additional information, [RFC 6891] introduces
//! a resource record called OPT that can be added to the additional section
//! of a message. The record data in turn consists of a sequence of options.
//!
//! This module contains the types for working with both the OPT record and
//! its record data. It defines types for each of the currently defined
//! options. As with record data types in the [rdata] module, these are
//! arranged in sub-modules according to the RFC that defined them and then
//! re-exported here.
//! 
//! [RFC 6891]: https://tools.ietf.org/html/rfc6891
//! [rdata]: ../rdata/index.html


//============ Sub-modules and Re-exports ====================================
//
// All of these are in a macro. The macro also defines `AllOptData`.

#[macro_use] mod macros;
opt_types!{
    rfc5001::{Nsid<O>};
    rfc6975::{Dau<O>, Dhu<O>, N3u<O>};
    rfc7314::{Expire};
    rfc7828::{TcpKeepalive};
    rfc7830::{Padding};
    rfc7871::{ClientSubnet};
    rfc7873::{Cookie};
    rfc7901::{Chain<O>};
    rfc8145::{KeyTag<O>};
}


//============ Module Content ================================================

use std::{fmt, mem, ops};
use std::marker::PhantomData;
use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use crate::iana::{OptionCode, OptRcode, Rtype};
use super::compose::{Compose, Compress, Compressor};
use super::header::Header;
use super::name::ToDname;
use super::octets::Octets;
use super::parse::{Parse, ParseAll, Parser, ShortBuf};
use super::rdata::RtypeRecordData;
use super::record::Record;


//------------ Opt -----------------------------------------------------------

/// OPT record data.
///
/// This type wraps a bytes value containing the record data of an OPT record.
//
//  XXX Deriving PartialEq etc. might be wrong for some options. Have a look
//      at this again once we have proper option handling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Opt<O=Bytes> {
    octets: O,
}

impl<O: Octets> Opt<O> {
    /// Creates OPT record data from the underlying octets.
    ///
    /// The function checks whether the bytes value contains a sequence of
    /// options. It does not check whether the options itself are valid.
    pub fn from_octets(octets: O) -> Result<Self, ShortBuf> {
        let mut parser = Parser::from_octets(octets);
        while parser.remaining() > 0 {
            parser.advance(2)?;
            let len = parser.parse_u16()?;
            parser.advance(len as usize)?;
        }
        Ok(Opt { octets: parser.unwrap() })
    }

    /// Returns an iterator over options of a given type.
    ///
    /// The returned iterator will return only options represented by type
    /// `D` and quietly skip over all the others.
    pub fn iter<D: OptData<O>>(&self) -> OptIter<O, D> {
        OptIter::new(self.octets.clone())
    }
}

impl Opt<Bytes> {
    /// Creates OPT record data from a bytes value.
    ///
    /// The function checks whether the bytes value contains a sequence of
    /// options. It does not check whether the options itself are valid.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ShortBuf> {
        Self::from_octets(bytes)
    }
}


//--- ParseAll, Compose, Compress

impl<O: Octets> ParseAll<O> for Opt<O> {
    type Err = ShortBuf;

    fn parse_all(
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Self, Self::Err> {
        Self::from_octets(parser.parse_octets(len)?)
    }
}

impl<O: Octets> Compose for Opt<O> {
    fn compose_len(&self) -> usize {
        self.octets.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.octets.as_ref())
    }
}

impl<O: Octets> Compress for Opt<O> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

impl<O: Octets> RtypeRecordData for Opt<O> {
    const RTYPE: Rtype = Rtype::Opt;
}


//--- Display

impl<O: Octets> fmt::Display for Opt<O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // XXX TODO Print this properly.
        f.write_str("OPT ...")
    }
}


//------------ OptHeader -----------------------------------------------------

/// The header of an OPT record.
///
/// The OPT record reappropriates the record header for encoding some
/// basic information. This type provides access to this information. It
/// consists of the record header accept for its `rdlen` field.
///
/// This is so that `OptBuilder` can safely deref to this type.
///
//    +------------+--------------+------------------------------+
//    | Field Name | Field Type   | Description                  |
//    +------------+--------------+------------------------------+
//    | NAME       | domain name  | MUST be 0 (root domain)      |
//    | TYPE       | u_int16_t    | OPT (41)                     |
//    | CLASS      | u_int16_t    | requestor's UDP payload size |
//    | TTL        | u_int32_t    | extended RCODE and flags     |
//    | RDLEN      | u_int16_t    | length of all RDATA          |
//    | RDATA      | octet stream | {attribute,value} pairs      |
//    +------------+--------------+------------------------------+
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OptHeader {
    /// The bytes of the header.
    inner: [u8; 9],
}

impl OptHeader {
    pub fn for_record_slice(slice: &[u8]) -> &OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &*(slice.as_ptr() as *const OptHeader) }
    }

    pub fn for_record_slice_mut(slice: &mut [u8]) -> &mut OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &mut *(slice.as_ptr() as *mut OptHeader) }
    }

    pub fn udp_payload_size(&self) -> u16 {
        BigEndian::read_u16(&self.inner[3..])
    }

    pub fn set_udp_payload_size(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.inner[3..], value)
    }

    pub fn rcode(&self, header: Header) -> OptRcode {
        OptRcode::from_parts(header.rcode(), self.inner[5])
    }

    pub fn set_rcode(&mut self, rcode: OptRcode) {
        self.inner[5] = rcode.ext()
    }

    pub fn version(&self) -> u8 {
        self.inner[6]
    }

    pub fn set_version(&mut self, version: u8) {
        self.inner[6] = version
    }

    pub fn dnssec_ok(&self) -> bool {
        self.inner[7] & 0x80 != 0
    }

    pub fn set_dnssec_ok(&mut self, value: bool) {
        if value {
            self.inner[7] |= 0x80
        }
        else {
            self.inner[7] &= 0x7F
        }
    }
}

impl Default for OptHeader {
    fn default() -> Self {
        OptHeader { inner: [0, 0, 41, 0, 0, 0, 0, 0, 0] }
    }
}

impl Compose for OptHeader {
    fn compose_len(&self) -> usize {
        9
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.inner)
    }
}


//------------ OptRecord -----------------------------------------------------

/// An entire OPT record.
#[derive(Clone, Debug)]
pub struct OptRecord<O=Bytes> {
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    flags: u16,
    data: Opt<O>,
}

impl<O: Octets> OptRecord<O> {
    pub fn from_record<N: ToDname>(record: Record<N, Opt<O>>) -> Self {
        OptRecord {
            udp_payload_size: record.class().to_int(),
            ext_rcode: (record.ttl() >> 24) as u8,
            version: (record.ttl() >> 16) as u8,
            flags: record.ttl() as u16,
            data: record.into_data()
        }
    }

    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    pub fn rcode(&self, header: Header) -> OptRcode {
        OptRcode::from_parts(header.rcode(), self.ext_rcode)
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn dnssec_ok(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn as_opt(&self) -> &Opt<O> {
        &self.data
    }
}


//--- From

impl<O: Octets, N: ToDname> From<Record<N, Opt<O>>> for OptRecord<O> {
    fn from(record: Record<N, Opt<O>>) -> Self {
        Self::from_record(record)
    }
}


//--- Deref and AsRef

impl<O: Octets> ops::Deref for OptRecord<O> {
    type Target = Opt<O>;

    fn deref(&self) -> &Opt<O> {
        &self.data
    }
}

impl<O: Octets> AsRef<Opt<O>> for OptRecord<O> {
    fn as_ref(&self) -> &Opt<O> {
        &self.data
    }
}


//------------ OptionHeader --------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptionHeader {
    code: u16,
    len: u16,
}

#[allow(len_without_is_empty)]
impl OptionHeader {
    pub fn new(code: u16, len: u16) -> Self {
        OptionHeader { code, len }
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn len(&self) -> u16 {
        self.len
    }
}

impl<O: Octets> Parse<O> for OptionHeader {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser<O>) -> Result<Self, Self::Err> {
        Ok(OptionHeader::new(parser.parse_u16()?, parser.parse_u16()?))
    }

    fn skip(parser: &mut Parser<O>) -> Result<(), Self::Err> {
        parser.advance(4)
    }
}

impl Compose for OptionHeader {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.code.compose(buf);
        self.len.compose(buf);
    }
}


//------------ OptIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptIter<O, D: OptData<O>> { 
    parser: Parser<O>,
    marker: PhantomData<D>
}

impl<O: Octets, D: OptData<O>> OptIter<O, D> {
    fn new(octets: O) -> Self {
        OptIter {
            parser: Parser::from_octets(octets),
            marker: PhantomData
        }
    }
}

impl<O: Octets, D: OptData<O>> Iterator for OptIter<O, D> {
    type Item = Result<D, D::ParseErr>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.remaining() > 0 {
            match self.next_step() {
                Ok(Some(res)) => return Some(Ok(res)),
                Ok(None) => { }
                Err(err) => return Some(Err(err)),
            }
        }
        None
    }
}

impl<O: Octets, D: OptData<O>> OptIter<O, D> {
    fn next_step(&mut self) -> Result<Option<D>, D::ParseErr> {
        let code = self.parser.parse_u16().unwrap().into();
        let len = self.parser.parse_u16().unwrap() as usize;
        D::parse_option(code, &mut self.parser, len)
    }
}


//------------ OptData -------------------------------------------------------

pub trait OptData<O=Bytes>: Compose + Sized {
    type ParseErr;

    fn code(&self) -> OptionCode;

    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Option<Self>, Self::ParseErr>;
}


//------------ CodeOptData ---------------------------------------------------

pub trait CodeOptData {
    const CODE: OptionCode;
}

impl<O, T: CodeOptData + ParseAll<O> + Compose + Sized> OptData<O> for T {
    type ParseErr = <Self as ParseAll<O>>::Err;

    fn code(&self) -> OptionCode { Self::CODE }

    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Option<Self>, Self::ParseErr> {
        if code == Self::CODE {
            Self::parse_all(parser, len).map(Some)
        }
        else {
            Ok(None)
        }
    }
}


//------------ UnknownOptData ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UnknownOptData<O=Bytes> {
    code: OptionCode,
    data: O,
}

impl<O> UnknownOptData<O> {
    pub fn from_octets(code: OptionCode, data: O) -> Self {
        UnknownOptData { code, data }
    }

    pub fn code(&self) -> OptionCode {
        self.code
    }

    pub fn data(&self) -> &O {
        &self.data
    }
}


//--- Compose

impl<O: Octets> Compose for UnknownOptData<O> {
    fn compose_len(&self) -> usize {
        self.data.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.data.as_ref())
    }
}


//--- OptData

impl<O: Octets> OptData<O> for UnknownOptData<O> {
    type ParseErr = ShortBuf;

    fn code(&self) -> OptionCode {
        self.code
    }

    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<O>,
        len: usize
    ) -> Result<Option<Self>, Self::ParseErr> {
        parser.parse_octets(len)
            .map(|data| Some(Self::from_octets(code, data)))
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use super::super::record::ParsedRecord;

    #[test]
    fn opt_record_header() {
        let mut header = OptHeader::default();
        header.set_udp_payload_size(0x1234);
        header.set_rcode(OptRcode::BadVers);
        header.set_version(0xbd);
        header.set_dnssec_ok(true);
        let mut buf = Vec::with_capacity(11);
        header.compose(&mut buf);
        0u16.compose(&mut buf);
        let mut buf = Parser::from_bytes(buf.into());
        let record = ParsedRecord::parse(&mut buf).unwrap()
            .into_record::<Opt>().unwrap().unwrap();
        let record = OptRecord::from_record(record);
        assert_eq!(record.udp_payload_size(), 0x1234);
        assert_eq!(record.ext_rcode, OptRcode::BadVers.ext());
        assert_eq!(record.version(), 0xbd);
        assert!(record.dnssec_ok());
    }
}

