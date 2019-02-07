/// Uncompressed, absolute domain names.
///
/// This is a private module. Its public types are re-exported by the parent.

use std::{cmp, fmt, hash, ops, str};
use bytes::{BufMut, Bytes};
use crate::bits::compose::{Compose, Compress, Compressor};
use crate::bits::octets::Octets;
use crate::bits::parse::{Parse, ParseAll, Parser, ShortBuf};
use crate::master::scan::{CharSource, Scan, Scanner, ScanError, SyntaxError};
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::relative::{RelativeDname, DnameIter};
use super::traits::{ToLabelIter, ToDname};
use super::uncertain::{UncertainDname, FromStrError};


//------------ Dname ---------------------------------------------------------

/// An uncompressed, absolute domain name.
///
/// The type wraps a [`Bytes`] value and guarantees that it always contains
/// a correctly encoded, absolute domain name. It derefs to [`Bytes`] and
/// therefore to `[u8]` allowing you direct access to the underlying byte
/// slice. It does overide all applicable methods providing access to parts
/// of the byte slice, though, returning either `Dname` or [`RelativeDname`]s
/// instead.
///
/// You can construct a domain name from a string via the `FromStr` trait or
/// manually via a [`DnameBuilder`]. In addition, you can also parse it from
/// a message. This will, however, require the name to be uncompressed.
///
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`DnameBuilder`]: struct.DnameBuilder.html
/// [`RelativeDname`]: struct.RelativeDname.html
#[derive(Clone)]
pub struct Dname<O=Bytes> {
    octets: O
}

/// # Creation and Conversion
///
impl<O> Dname<O> {
    /// Creates a domain name from the underlying octets without any check.
    ///
    /// Since this will allow to actually construct an incorrectly encoded
    /// domain name value, the function is unsafe.
    pub(super) unsafe fn from_octets_unchecked(octets: O) -> Self {
        Dname { octets }
    }

    /// Converts the octets of a name into a different octets type.
    pub fn convert_octets<P: From<O>>(self) -> Dname<P> {
        unsafe { Dname::from_octets_unchecked(self.octets.into()) }
    }
}


impl<O: Octets> Dname<O> {
    /// Creates a domain name from a octets.
    ///
    /// This will only succeed if `octets` contains a properly encoded
    /// absolute domain name. Because the function checks, this will take
    /// a wee bit of time.
    pub fn from_octets(octets: O) -> Result<Self, DnameOctetsError> {
        if octets.len() > 255 {
            return Err(DnameError::LongName.into());
        }
        {
            let mut tmp = octets.as_ref();
            loop {
                let (label, tail) = Label::split_from(tmp)?;
                if label.is_root() {
                    if tail.is_empty() {
                        break;
                    }
                    else {
                        return Err(DnameOctetsError::TrailingData)
                    }
                }
                if tail.is_empty() {
                    return Err(DnameOctetsError::RelativeName)
                }
                tmp = tail;
            }
        }
        Ok(unsafe { Dname::from_octets_unchecked(octets) })
    }

    /// Creates a domain name representing the root.
    ///
    /// The resulting domain name will consist of the root label only.
    pub fn root() -> Self {
        unsafe { Self::from_octets_unchecked(O::from_static(b"\0")) }
    }

    /// Returns a reference to the underlying octets.
    pub fn as_octets(&self) -> &O {
        &self.octets
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.octets.as_ref()
    }

    /// Converts the name into a relative name by dropping the root label.
    pub fn into_relative(self) -> RelativeDname<O> {
        unsafe {
            RelativeDname::from_octets_unchecked(
                self.octets.range_to(self.octets.len() - 1)
            )
        }
    }
}

impl Dname<Bytes> {
    /// Creates a domain name for a bytes value.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, DnameOctetsError> {
        Self::from_octets(bytes)
    }

    /// Creates a domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots.
    /// Actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// The name will always be an absolute name. If the last character in the
    /// sequence is not a dot, the function will quietly add a root label,
    /// anyway. In most cases, this is likely what you want. If it isn’t,
    /// though, use [`UncertainDname`] instead to be able to check.
    ///
    /// [`UncertainDname`]: enum.UncertainDname.html
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
                      where C: IntoIterator<Item=char> {
        UncertainDname::from_chars(chars).map(|res| res.into_absolute())
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.octets
    }

    /// Converts the domain name into its underlying bytes value.
    pub fn into_bytes(self) -> Bytes {
        self.octets
    }
}

impl<'a> Dname<&'a [u8]> {
    /// Creates a domain name for an octet slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, DnameOctetsError> {
        Self::from_octets(slice)
    }
}

impl Dname<&'static [u8]> {
    /// Creates a root name as a static octet slice.
    pub fn static_root() -> Self {
        Dname::root()
    }
}


/// # Properties
///
/// More of the usual methods on byte sequences, such as
/// [`len`](#method.len), are available via
/// [deref to `Bytes`](#deref-methods).
impl<O: Octets> Dname<O> {
    /// Returns whether the name is the root label only.
    pub fn is_root(&self) -> bool {
        self.len() == 1
    }
}


/// # Working with Labels
///
impl<O: Octets> Dname<O> {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.octets.as_ref())
    }

    /// Returns an iterator over the suffixes of the name.
    ///
    /// The returned iterator starts with the full name and then for each
    /// additional step returns a name with the left-most label stripped off
    /// until it reaches the root label.
    pub fn iter_suffixes(&self) -> SuffixIter<O> {
        SuffixIter::new(self)
    }

    /// Returns the number of labels in the domain name.
    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    /// Returns a reference to the first label.
    pub fn first(&self) -> &Label {
        self.iter().next().unwrap()
    }

    /// Returns a reference to the last label.
    ///
    /// Because the last label in an absolute name is always the root label,
    /// this method can return a static reference. It is also a wee bit silly,
    /// but here for completeness.
    pub fn last(&self) -> &'static Label {
        Label::root()
    }

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns whether an index points to the first byte of a non-root label.
    pub fn is_label_start(&self, mut index: usize) -> bool {
        if index == 0 {
            return true
        }
        let mut tmp = self.as_slice();
        while !tmp.is_empty() {
            let (label, tail) = Label::split_from(tmp).unwrap();
            let len = label.len() + 1;
            if index < len || len == 1 { // length 1: root label.
                return false
            }
            else if index == len {
                return true
            }
            index -= len;
            tmp = tail;
        }
        false
    }

    /// Like `is_label_start` but panics if it isn’t.
    fn check_index(&self, index: usize) {
        if !self.is_label_start(index) {
            panic!("index not at start of a label");
        }
    }

    /// Returns the part of the name indicated by start and end octet indexes.
    ///
    /// The returned name will start at position `begin` and end right before
    /// position `end`. Both positions must point to the begining of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position is not the start of a label or
    /// is out of bounds.
    ///
    /// Because the returned domain name is relative, the method will also
    /// panic if the end is equal to the length of the name. If you
    /// want to slice the entire end of the name including the final root
    /// label, you can use [`slice_from()`] instead.
    ///
    /// [`slice_from()`]: #method.slice_from
    pub fn range(&self, start: usize, end: usize) -> RelativeDname<O> {
        self.check_index(start);
        self.check_index(end);
        unsafe {
            RelativeDname::from_octets_unchecked(
                self.octets.range(start, end)
            )
        }
    }

    /// Returns the part of the name indicated by start and end octet indexes.
    ///
    /// This is the old name of [`range`] and is therefore obsolete.
    ///
    /// [`range`]: #method.range
    #[deprecated(since="0.5.0", note="renamed to range")]
    pub fn slice(&self, start: usize, end: usize) -> RelativeDname<O> {
        self.range(start, end)
    }

    /// Returns the part of the name starting at the given octet index.
    ///
    /// # Panics
    ///
    /// The method panics if `start` isn’t the index of the beginning of a
    /// label or is out of bounds.
    pub fn range_from(&self, start: usize) -> Self {
        self.check_index(start);
        unsafe {
            Self::from_octets_unchecked(self.octets.range_from(start))
        }
    }

    /// Returns the part of the name starting at the given octet index.
    ///
    /// This is the old name of [`range_from`] and is therefore obsolete.
    ///
    /// [`range_from`]: #method.range_from
    #[deprecated(since="0.5.0", note="renamed to range_from")]
    pub fn slice_from(&self, start: usize) -> Self {
        self.range_from(start)
    }

    /// Returns the part of the name ending at the given octet index.
    ///
    /// # Panics
    ///
    /// The method panics if `end` is not the beginning of a label or is out
    /// of bounds. Because the returned domain name is relative, the method
    /// will also panic if the end is equal to the length of the name.
    pub fn range_to(&self, end: usize) -> RelativeDname<O> {
        self.check_index(end);
        unsafe {
            RelativeDname::from_octets_unchecked(self.octets.range_to(end))
        }
    }

    /// Returns the part of the name ending at the given octet index.
    ///
    /// This is the old name of [`range_to`] and is therefore obsolete.
    ///
    /// [`range_to`]: #method.range_from
    pub fn slice_to(&self, end: usize) -> RelativeDname<O> {
        self.range_to(end)
    }

    /// Splits the name into two at the given octet index.
    ///
    /// The returned tuple will contain the relative name ending right before
    /// `mid` and the absolute name starting at `mid`.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the index of the beginning of
    /// a label or if it is out of bounds.
    pub fn split_at(self, mid: usize) -> (RelativeDname<O>, Dname<O>) {
        self.check_index(mid);
        let left = self.octets.range_to(mid);
        let right = self.octets.range_from(mid);
        unsafe {(
            RelativeDname::from_octets_unchecked(left),
            Dname::from_octets_unchecked(right)
        )}
    }

    /// Splits the name into two at the given position.
    ///
    /// Unlike the namesake on [`Bytes`], the method consumes `self` since
    /// the left side needs to be converted into a [`RelativeDname`].
    /// Consequently, it returns a pair of the left and right parts.
    ///
    /// This method is deprecated as it has been renamed to [`split_at`].
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the index of the beginning of
    /// a label or if it is out of bounds.
    ///
    /// [`Bytes`]: ../../../bytes/struct.Bytes.html#method.split_off
    /// [`RelativeDname`]: struct.RelativeDname.html
    /// [`split_at`]: #method.split_at
    #[deprecated(since="0.5.0", note="renamed to split_at")]
    pub fn split_off(self, mid: usize) -> (RelativeDname<O>, Self) {
        self.split_at(mid)
    }

    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name starting at the position
    /// while the name ending right before it will be returned.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the start of a new label or is
    /// out of bounds.
    pub fn split_to(&mut self, mid: usize) -> RelativeDname<O> {
        self.check_index(mid);
        let left = self.octets.range_to(mid);
        self.octets = self.octets.range_from(mid);
        unsafe {
            RelativeDname::from_octets_unchecked(left)
        }
    }

    /// Truncates the name before `len`.
    ///
    /// Because truncating converts the name into a relative name, the method
    /// consumes self.
    ///
    /// # Panics
    ///
    /// The method will panic if `len` is not the index of a new label or if
    /// it is out of bounds.
    pub fn truncate(self, len: usize) -> RelativeDname<O> {
        self.check_index(len);
        unsafe {
            RelativeDname::from_octets_unchecked(self.octets.range_to(len))
        }
    }

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns the first
    /// label as a relative name and removes it from the name itself. If the
    /// name is only the root label, returns `None` and does nothing.
    pub fn split_first(&mut self) -> Option<RelativeDname<O>> {
        if self.len() == 1 {
            return None
        }
        let end = self.iter().next().unwrap().len() + 1;
        Some(self.split_to(end))
    }

    /// Reduces the name to the parent of the current name.
    ///
    /// If the name consists of the root label only, returns `false` and does
    /// nothing. Otherwise, drops the first label and returns `true`.
    pub fn parent(&mut self) -> bool {
        self.split_first().is_some()
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// If `base` is indeed a suffix, returns a relative domain name with the
    /// remainder of the name. Otherwise, returns an error with an unmodified
    /// `self`.
    pub fn strip_suffix<N: ToDname>(self, base: &N)
                                    -> Result<RelativeDname<O>, Dname<O>> {
        if self.ends_with(base) {
            let len = self.compose_len() - base.compose_len();
            Ok(self.truncate(len))
        }
        else {
            Err(self)
        }
    }
}


//--- Parse, ParseAll, and Compose

impl<O: Octets> Parse<O> for Dname<O> {
    type Err = DnameParseError;

    fn parse(parser: &mut Parser<O>) -> Result<Self, Self::Err> {
        let len = name_len(parser)?;
        Ok(unsafe {
            Self::from_octets_unchecked(parser.parse_octets(len).unwrap())
        })
    }

    fn skip(parser: &mut Parser<O>) -> Result<(), Self::Err> {
        let len = name_len(parser)?;
        parser.advance(len)?;
        Ok(())
    }
}

fn name_len<O: Octets>(
    parser: &mut Parser<O>
) -> Result<usize, DnameParseError> {
    let len = {
        let mut tmp = parser.peek_all();
        loop {
            if tmp.is_empty() {
                return Err(ShortBuf.into())
            }
            let (label, tail) = Label::split_from(tmp)?;
            tmp = tail;
            if label.is_root() {
                break;
            }
        }
        parser.remaining() - tmp.len()
    };
    if len > 255 {
        Err(DnameError::LongName.into())
    }
    else {
        Ok(len)
    }
}

impl<O: Octets> ParseAll<O> for Dname<O> {
    type Err = DnameOctetsError;

    fn parse_all(
        parser: &mut Parser<O>, len: usize
    ) -> Result<Self, Self::Err> {
        Self::from_octets(parser.parse_octets(len)?)
    }
}


impl<O: Octets> Compose for Dname<O> {
    fn compose_len(&self) -> usize {
        self.octets.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.as_ref())
    }
}

impl<O: Octets> Compress for Dname<O> {
    fn compress(&self, compressor: &mut Compressor) -> Result<(), ShortBuf> {
        compressor.compress_name(self)
    }
}


//--- FromStr

impl str::FromStr for Dname<Bytes> {
    type Err = FromStrError;

    /// Parses a string into an absolute domain name.
    ///
    /// The implementation assumes that the string refers to an absolute name
    /// whether it ends in a dot or not. If you need to be able to distinguish
    /// between those two cases, you can use [`UncertainDname`] instead.
    ///
    /// [`UncertainDname`]: struct.UncertainDname.html
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UncertainDname::from_str(s).map(|res| res.into_absolute())
    }
}


//--- ToLabelIter and ToDname

impl<'a, O: Octets> ToLabelIter<'a> for Dname<O> {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl<O: Octets> ToDname for Dname<O> {
    fn to_name(&self) -> Dname<Bytes> {
        unsafe {
            Dname::from_octets_unchecked(self.octets.clone().into_bytes())
        }
    }

    fn as_flat_slice(&self) -> Option<&[u8]> {
        Some(self.as_slice())
    }
}


//--- Deref and AsRef

impl<O: Octets> ops::Deref for Dname<O> {
    type Target = O;

    fn deref(&self) -> &O {
        self.as_octets()
    }
}

impl<O: Octets> AsRef<O> for Dname<O> {
    fn as_ref(&self) -> &O {
        &self.octets
    }
}

impl<O: Octets> AsRef<[u8]> for Dname<O> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}


//--- IntoIterator

impl<'a, O: Octets> IntoIterator for &'a Dname<O> {
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl<N: ToDname, O: Octets> PartialEq<N> for Dname<O> {
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl<O: Octets> Eq for Dname<O> { }


//--- PartialOrd and Ord

impl<N: ToDname, O: Octets> PartialOrd<N> for Dname<O> {
    /// Returns the ordering between `self` and `other`.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        Some(self.name_cmp(other))
    }
}

impl<O: Octets> Ord for Dname<O> {
    /// Returns the ordering between `self` and `other`.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name_cmp(other)
    }
}


//--- Hash

impl<O: Octets> hash::Hash for Dname<O> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}


//--- Scan and Display

impl Scan for Dname<Bytes> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        let pos = scanner.pos();
        let name = match UncertainDname::scan(scanner)? {
            UncertainDname::Relative(name) => name,
            UncertainDname::Absolute(name) => return Ok(name)
        };
        let origin = match *scanner.origin() {
            Some(ref origin) => origin,
            None => return Err((SyntaxError::NoOrigin, pos).into())
        };
        name.into_builder().append_origin(origin)
                           .map_err(|err| (SyntaxError::from(err), pos).into())
    }
}

impl<O: Octets> fmt::Display for Dname<O> {
    /// Formats the domain name.
    ///
    /// This will produce the domain name in ‘common display format’ without
    /// the trailing dot.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        write!(f, "{}", iter.next().unwrap())?;
        for label in iter {
            if !label.is_root() {
                write!(f, ".{}", label)?
            }
        }
        Ok(())
    }
}


//--- Debug

impl<O: Octets> fmt::Debug for Dname<O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dname({}.)", self)
    }
}


//------------ SuffixIter ----------------------------------------------------

/// An iterator over ever shorter suffixes of a domain name.
#[derive(Clone, Debug)]
pub struct SuffixIter<O: Octets> {
    name: Option<Dname<O>>,
}

impl<O: Octets> SuffixIter<O> {
    /// Creates a new iterator cloning `name`.
    fn new(name: &Dname<O>) -> Self {
        SuffixIter {
            name: Some(name.clone())
        }
    }
}

impl<O: Octets> Iterator for SuffixIter<O> {
    type Item = Dname<O>;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, ok) = match self.name {
            Some(ref mut name) => (name.clone(), name.parent()),
            None => return None
        };
        if !ok {
            self.name = None
        }
        Some(res)
    }
}


//------------ DnameError ----------------------------------------------------

/// A domain name wasn’t encoded correctly.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameError {
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    #[fail(display="compressed domain name")]
    CompressedName,

    #[fail(display="long domain name")]
    LongName,
}

impl From<LabelTypeError> for DnameError {
    fn from(err: LabelTypeError) -> DnameError {
        DnameError::BadLabel(err)
    }
}


//------------ DnameParseError -----------------------------------------------

/// An error happened while parsing a domain name.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameParseError {
    #[fail(display="{}", _0)]
    BadName(DnameError),

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl<T: Into<DnameError>> From<T> for DnameParseError {
    fn from(err: T) -> DnameParseError {
        DnameParseError::BadName(err.into())
    }
}

impl From<SplitLabelError> for DnameParseError {
    fn from(err: SplitLabelError) -> DnameParseError {
        match err {
            SplitLabelError::Pointer(_)
                => DnameParseError::BadName(DnameError::CompressedName),
            SplitLabelError::BadType(t)
                => DnameParseError::BadName(DnameError::BadLabel(t)),
            SplitLabelError::ShortBuf => DnameParseError::ShortBuf,
        }
    }
}

impl From<ShortBuf> for DnameParseError {
    fn from(_: ShortBuf) -> DnameParseError {
        DnameParseError::ShortBuf
    }
}


//------------ DnameOctetsError -----------------------------------------------

/// An error happened while converting a bytes value into a domain name.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameOctetsError {
    #[fail(display="{}", _0)]
    ParseError(DnameParseError),

    #[fail(display="relative name")]
    RelativeName,

    #[fail(display="trailing data")]
    TrailingData,
}

impl<T: Into<DnameParseError>> From<T> for DnameOctetsError {
    fn from(err: T) -> DnameOctetsError {
        DnameOctetsError::ParseError(err.into())
    }
}


//============ Testing =======================================================
//
// Some of the helper functions herein are resused by the tests of other
// sub-modules of ::bits::name. Hence the `pub(crate)` designation.

#[cfg(test)]
pub(crate) mod test {
    use std::cmp::Ordering;
    use super::*;

    macro_rules! assert_panic {
        ( $cond:expr ) => {
            {
                let result = ::std::panic::catch_unwind(|| $cond);
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn root() {
        assert_eq!(Dname::static_root().as_slice(), b"\0");
    }

    #[test]
    fn from_slice() {
        // a simple good name
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0")
                         .unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");
        
        // relative name
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com"),
                   Err(DnameOctetsError::RelativeName));

        // bytes shorter than what label length says.
        assert_eq!(Dname::from_slice(b"\x03www\x07exa"),
                   Err(ShortBuf.into()));

        // label 63 long ok, 64 bad.
        let mut slice = [0u8; 65];
        slice[0] = 63;
        assert!(Dname::from_slice(&slice[..]).is_ok());
        let mut slice = [0u8; 66];
        slice[0] = 64;
        assert!(Dname::from_slice(&slice[..]).is_err());

        // name 255 long ok, 256 bad.
        let mut buf = Vec::new();
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        assert_eq!(buf.len(), 250);
        let mut tmp = buf.clone();
        tmp.extend_from_slice(b"\x03123\0");
        assert_eq!(Dname::from_slice(&tmp).map(|_| ()), Ok(()));
        buf.extend_from_slice(b"\x041234\0");
        assert!(Dname::from_slice(&buf).is_err());

        // trailing data
        assert!(Dname::from_slice(b"\x03com\0\x03www\0").is_err());

        // bad label heads: compressed, other types.
        assert_eq!(Dname::from_slice(b"\xa2asdasds"),
                   Err(LabelTypeError::Undefined.into()));
        assert_eq!(Dname::from_slice(b"\x62asdasds"),
                   Err(LabelTypeError::Extended(0x62).into()));
        assert_eq!(Dname::from_slice(b"\xccasdasds"),
                   Err(DnameError::CompressedName.into()));

        // empty input
        assert_eq!(Dname::from_slice(b""), Err(ShortBuf.into()));
    }

    // No test for `Dname::from_chars` necessary since it only defers to
    // `UncertainDname`.
    //
    // No tests for the simple conversion methods because, well, simple.

    #[test]
    fn into_relative() {
        assert_eq!(Dname::from_slice(b"\x03www\0").unwrap()
                         .into_relative().as_slice(),
                   b"\x03www");
    }

    #[test]
    fn is_root() {
        assert_eq!(Dname::from_slice(b"\0").unwrap().is_root(), true);
        assert_eq!(Dname::from_slice(b"\x03www\0").unwrap().is_root(), false);
        assert_eq!(Dname::static_root().is_root(), true);
    }

    pub fn cmp_iter<I>(mut iter: I, labels: &[&[u8]])
    where
        I: Iterator,
        I::Item: AsRef<[u8]>
    {
        let mut labels = labels.iter();
        loop {
            match (iter.next(), labels.next()) {
                (Some(left), Some(right)) => assert_eq!(left.as_ref(), *right),
                (None, None) => break,
                (_, None) => panic!("extra items in iterator"),
                (None, _) => panic!("missing items in iterator"),
            }
        }
    }

    #[test]
    fn iter() {
        cmp_iter(Dname::static_root().iter(), &[b""]);
        cmp_iter(Dname::from_slice(b"\x03www\x07example\x03com\0")
                       .unwrap().iter(),
                 &[b"www", b"example", b"com", b""]);
    }

    pub fn cmp_iter_back<I>(mut iter: I, labels: &[&[u8]])
    where
        I: DoubleEndedIterator,
        I::Item: AsRef<[u8]>
    {
        let mut labels = labels.iter();
        loop {
            match (iter.next_back(), labels.next()) {
                (Some(left), Some(right)) => assert_eq!(left.as_ref(), *right),
                (None, None) => break,
                (_, None) => panic!("extra items in iterator"),
                (None, _) => panic!("missing items in iterator"),
            }
        }
    }

    #[test]
    fn iter_back() {
        cmp_iter_back(Dname::static_root().iter(), &[b""]);
        cmp_iter_back(Dname::from_slice(b"\x03www\x07example\x03com\0")
                            .unwrap().iter(),
                      &[b"", b"com", b"example", b"www"]);
    }

    #[test]
    fn iter_suffixes() {
        cmp_iter(Dname::static_root().iter_suffixes(), &[b"\0"]);
        cmp_iter(Dname::from_slice(b"\x03www\x07example\x03com\0")
                       .unwrap().iter_suffixes(),
                 &[b"\x03www\x07example\x03com\0", b"\x07example\x03com\0",
                   b"\x03com\0", b"\0"]);
    }

    #[test]
    fn label_count() {
        assert_eq!(Dname::static_root().label_count(), 1);
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
                         .label_count(),
                   4);
    }

    #[test]
    fn first() {
        assert_eq!(Dname::static_root().first().as_slice(), b"");
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
                         .first().as_slice(),
                   b"www");
    }

    // No test for `last` because it is so trivial.

    #[test]
    fn last() {
        assert_eq!(Dname::static_root().last().as_slice(), b"");
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
                         .last().as_slice(),
                   b"");
    }

    #[test]
    fn starts_with() {
        let root = Dname::static_root();
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert!(root.starts_with(&root));
        assert!(wecr.starts_with(&wecr));
        
        assert!( root.starts_with(&RelativeDname::static_empty()));
        assert!( wecr.starts_with(&RelativeDname::static_empty()));
        
        let test = RelativeDname::from_slice(b"\x03www").unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));
        
        let test = RelativeDname::from_slice(b"\x03www\x07example").unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www\x07example\x03com")
                                 .unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(!wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www").unwrap()
                    .chain(RelativeDname::from_slice(b"\x07example").unwrap())
                    .unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));

        let test = test.chain(RelativeDname::from_slice(b"\x03com")
                                            .unwrap())
                       .unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));
    }

    #[test]
    fn ends_with() {
        let root = Dname::static_root();
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        for name in wecr.iter_suffixes() {
            if name.is_root() {
                assert!(root.ends_with(&name));
            }
            else {
                assert!(!root.ends_with(&name));
            }
            assert!(wecr.ends_with(&name));
        }
    }

    #[test]
    fn is_label_start() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert!( wecr.is_label_start(0)); // \x03
        assert!(!wecr.is_label_start(1)); // w
        assert!(!wecr.is_label_start(2)); // w
        assert!(!wecr.is_label_start(3)); // w
        assert!( wecr.is_label_start(4)); // \x07
        assert!(!wecr.is_label_start(5)); // e
        assert!(!wecr.is_label_start(6)); // x
        assert!(!wecr.is_label_start(7)); // a
        assert!(!wecr.is_label_start(8)); // m
        assert!(!wecr.is_label_start(9)); // p
        assert!(!wecr.is_label_start(10)); // l
        assert!(!wecr.is_label_start(11)); // e
        assert!( wecr.is_label_start(12)); // \x03
        assert!(!wecr.is_label_start(13)); // c
        assert!(!wecr.is_label_start(14)); // o
        assert!(!wecr.is_label_start(15)); // m
        assert!( wecr.is_label_start(16)); // \0
        assert!(!wecr.is_label_start(17)); //
        assert!(!wecr.is_label_start(18)); //
    }

    #[test]
    fn range() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.range(0, 4).as_slice(), b"\x03www");
        assert_eq!(wecr.range(0, 12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.range(4, 12).as_slice(), b"\x07example");
        assert_eq!(wecr.range(4, 16).as_slice(), b"\x07example\x03com");

        assert_panic!(wecr.range(0,3));
        assert_panic!(wecr.range(1,4));
        assert_panic!(wecr.range(0,11));
        assert_panic!(wecr.range(1,12));
        assert_panic!(wecr.range(0,17));
        assert_panic!(wecr.range(4,17));
        assert_panic!(wecr.range(0,18));
    }

    #[test]
    fn range_from() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.range_from(0).as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(wecr.range_from(4).as_slice(), b"\x07example\x03com\0");
        assert_eq!(wecr.range_from(12).as_slice(), b"\x03com\0");
        assert_eq!(wecr.range_from(16).as_slice(), b"\0");

        assert_panic!(wecr.range_from(17));
        assert_panic!(wecr.range_from(18));
    }

    #[test]
    fn range_to() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.range_to(0).as_slice(), b"");
        assert_eq!(wecr.range_to(4).as_slice(), b"\x03www");
        assert_eq!(wecr.range_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.range_to(16).as_slice(), b"\x03www\x07example\x03com");

        assert_panic!(wecr.range_to(17));
        assert_panic!(wecr.range_to(18));
    }

    #[test]
    fn split_at() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        let (left, right) = wecr.clone().split_at(0);
        assert_eq!(left.as_slice(), b"");
        assert_eq!(right.as_slice(), b"\x03www\x07example\x03com\0");

        let (left, right) = wecr.clone().split_at(4);
        assert_eq!(left.as_slice(), b"\x03www");
        assert_eq!(right.as_slice(), b"\x07example\x03com\0");

        let (left, right) = wecr.clone().split_at(12);
        assert_eq!(left.as_slice(), b"\x03www\x07example");
        assert_eq!(right.as_slice(), b"\x03com\0");

        let (left, right) = wecr.clone().split_at(16);
        assert_eq!(left.as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(right.as_slice(), b"\0");

        assert_panic!(wecr.clone().split_at(1));
        assert_panic!(wecr.clone().split_at(14));
        assert_panic!(wecr.clone().split_at(17));
        assert_panic!(wecr.clone().split_at(18));
    }

    #[test]
    fn split_to() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(0).as_slice(), b"");
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com\0");

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(4).as_slice(), b"\x03www");
        assert_eq!(tmp.as_slice(), b"\x07example\x03com\0");

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(tmp.as_slice(), b"\x03com\0");

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(16).as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(tmp.as_slice(), b"\0");

        assert_panic!(wecr.clone().split_to(1));
        assert_panic!(wecr.clone().split_to(14));
        assert_panic!(wecr.clone().split_to(17));
        assert_panic!(wecr.clone().split_to(18));
    }

    #[test]
    fn truncate() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.clone().truncate(0).as_slice(),
                   b"");
        assert_eq!(wecr.clone().truncate(4).as_slice(),
                   b"\x03www");
        assert_eq!(wecr.clone().truncate(12).as_slice(),
                   b"\x03www\x07example");
        assert_eq!(wecr.clone().truncate(16).as_slice(),
                   b"\x03www\x07example\x03com");
        
        assert_panic!(wecr.clone().truncate(1));
        assert_panic!(wecr.clone().truncate(14));
        assert_panic!(wecr.clone().truncate(17));
        assert_panic!(wecr.clone().truncate(18));
    }

    #[test]
    fn split_first() {
        let mut wecr = Dname::from_slice(b"\x03www\x07example\x03com\0")
                             .unwrap();

        assert_eq!(wecr.split_first().unwrap().as_slice(), b"\x03www");
        assert_eq!(wecr.as_slice(), b"\x07example\x03com\0");
        assert_eq!(wecr.split_first().unwrap().as_slice(), b"\x07example");
        assert_eq!(wecr.as_slice(), b"\x03com\0");
        assert_eq!(wecr.split_first().unwrap().as_slice(), b"\x03com");
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(wecr.split_first().is_none());
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(wecr.split_first().is_none());
        assert_eq!(wecr.as_slice(), b"\0");
    }

    #[test]
    fn parent() {
        let mut wecr = Dname::from_slice(b"\x03www\x07example\x03com\0")
                             .unwrap();

        assert!(wecr.parent());
        assert_eq!(wecr.as_slice(), b"\x07example\x03com\0");
        assert!(wecr.parent());
        assert_eq!(wecr.as_slice(), b"\x03com\0");
        assert!(wecr.parent());
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(!wecr.parent());
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(!wecr.parent());
        assert_eq!(wecr.as_slice(), b"\0");
    }

    #[test]
    fn strip_suffix() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        let ecr = Dname::from_slice(b"\x07example\x03com\0").unwrap();
        let cr = Dname::from_slice(b"\x03com\0").unwrap();
        let wenr = Dname::from_slice(b"\x03www\x07example\x03net\0").unwrap();
        let enr = Dname::from_slice(b"\x07example\x03net\0").unwrap();
        let nr = Dname::from_slice(b"\x03net\0").unwrap();

        assert_eq!(wecr.clone().strip_suffix(&wecr).unwrap().as_slice(),
                   b"");
        assert_eq!(wecr.clone().strip_suffix(&ecr).unwrap().as_slice(),
                   b"\x03www");
        assert_eq!(wecr.clone().strip_suffix(&cr).unwrap().as_slice(),
                   b"\x03www\x07example");
        assert_eq!(wecr.clone().strip_suffix(&Dname::static_root())
                               .unwrap().as_slice(),
                   b"\x03www\x07example\x03com");

        assert_eq!(wecr.clone().strip_suffix(&wenr).unwrap_err().as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(wecr.clone().strip_suffix(&enr).unwrap_err().as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(wecr.clone().strip_suffix(&nr).unwrap_err().as_slice(),
                   b"\x03www\x07example\x03com\0");
    }

    #[test]
    fn parse() {
        // Parse a correctly formatted name.
        let mut p = Parser::from_slice(b"\x03www\x07example\x03com\0af");
        assert_eq!(Dname::parse(&mut p).unwrap().as_slice(),
                  b"\x03www\x07example\x03com\0");
        assert_eq!(p.peek_all(), b"af");

        // Short buffer in middle of label.
        let mut p = Parser::from_slice(b"\x03www\x07exam");
        assert_eq!(Dname::parse(&mut p), Err(ShortBuf.into()));

        // Short buffer at end of label.
        let mut p = Parser::from_slice(b"\x03www\x07example");
        assert_eq!(Dname::parse(&mut p), Err(ShortBuf.into()));

        // Compressed name.
        let mut p = Parser::from_slice(b"\x03com\x03www\x07example\xc0\0");
        p.advance(4).unwrap();
        assert_eq!(Dname::parse(&mut p),
                   Err(DnameError::CompressedName.into()));

        // Bad label header.
        let mut p = Parser::from_slice(b"\x03www\x07example\xbffoo");
        assert_eq!(Dname::parse(&mut p),
                   Err(LabelTypeError::Undefined.into()));

        // Long name: 255 bytes is fine.
        let mut buf = Vec::new();
        for _ in 0..50 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\x03123\0");
        assert_eq!(buf.len(), 255);
        let mut p = Parser::from_bytes(buf.into());
        assert!(Dname::parse(&mut p).is_ok());
        assert_eq!(p.peek_all(), b"");

        // Long name: 256 bytes are bad.
        let mut buf = Vec::new();
        for _ in 0..51 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\0");
        assert_eq!(buf.len(), 256);
        let mut p = Parser::from_bytes(buf.into());
        assert_eq!(Dname::parse(&mut p),
                   Err(DnameError::LongName.into()));
    }

    #[test]
    fn parse_all() {
        // The current implementation defers to `Dname::from_bytes`. As there
        // are test cases for the error cases with that function, all we need
        // to do is make sure it defers correctly.

        let mut p = Parser::from_slice(b"\x03www\x07example\x03com\0af");
        assert_eq!(Dname::parse_all(&mut p, 17).unwrap().as_slice(),
                  b"\x03www\x07example\x03com\0");
        assert_eq!(p.peek_all(), b"af");
        
        let mut p = Parser::from_slice(b"\0af");
        assert_eq!(Dname::parse_all(&mut p, 1).unwrap().as_slice(), b"\0");
        assert_eq!(p.peek_all(), b"af");
    }

    // I don’t think we need tests for `Compose` and `Compress`. The
    // former only copies the underlying bytes, the latter simply
    // defers to `Compressor::compress_name` which is tested separately.

    #[test]
    fn from_str() {
        // Another simple test. `UncertainDname` does all the heavy lifting,
        // so we don’t need to test all the escape sequence shenanigans here.
        // Just check that we’ll always get a name, final dot or not, unless
        // the string is empty.
        use std::str::FromStr;

        assert_eq!(Dname::from_str("www.example.com").unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(Dname::from_str("www.example.com.").unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");
    }

    #[test]
    fn eq() {
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
                   Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap());
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
                   Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap());
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_slice(b"\x03www").unwrap()
                .chain(RelativeDname::from_slice(b"\x07example\x03com")
                                     .unwrap())
                    .unwrap()
                .chain(Dname::static_root()).unwrap()
        );
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_slice(b"\x03wWw").unwrap()
                .chain(RelativeDname::from_slice(b"\x07eXAMple\x03coM")
                                     .unwrap())
                    .unwrap()
                .chain(Dname::static_root()).unwrap()
        );

        assert_ne!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
                   Dname::from_slice(b"\x03ww4\x07example\x03com\0").unwrap());
        assert_ne!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_slice(b"\x03www").unwrap()
                .chain(RelativeDname::from_slice(b"\x073xample\x03com")
                                     .unwrap())
                    .unwrap()
                .chain(Dname::static_root()).unwrap()
        );
    }

    #[test]
    fn cmp() {
        // The following is taken from section 6.1 of RFC 4034.
        let names = [
            Dname::from_slice(b"\x07example\0").unwrap(),
            Dname::from_slice(b"\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x08yljkjljk\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x01Z\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x04zABC\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x01z\x07example\0").unwrap(),
            Dname::from_slice(b"\x01\x01\x01z\x07example\0").unwrap(),
            Dname::from_slice(b"\x01*\x01z\x07example\0").unwrap(),
            Dname::from_slice(b"\x01\xc8\x01z\x07example\0").unwrap(),
        ];
        for i in 0..names.len() {
            for j in 0..names.len() {
                let ord = if i < j { Ordering::Less }
                          else if i == j { Ordering::Equal }
                          else { Ordering::Greater };
                assert_eq!(names[i].partial_cmp(&names[j]), Some(ord));
                assert_eq!(names[i].cmp(&names[j]), ord);
            }
        }

        let n1 = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        let n2 = Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap();
        assert_eq!(n1.partial_cmp(&n2), Some(Ordering::Equal));
        assert_eq!(n1.cmp(&n2), Ordering::Equal);
    }

    #[test]
    fn hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
              .hash(&mut s1);
        Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap()
              .hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    // Scan and Display skipped for now.
}

