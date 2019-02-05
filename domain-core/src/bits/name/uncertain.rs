//! A domain name that can be both relative or absolute.
//!
//! This is a private module. Its public types are re-exported by the parent.

use std::{fmt, hash, str};
use bytes::{BufMut, Bytes};
use crate::bits::compose::Compose;
use crate::bits::octets::Octets;
use crate::master::scan::{CharSource, Scan, Scanner, ScanError, Symbol};
use super::builder::{DnameBuilder, PushError, PushNameError};
use super::chain::{Chain, LongChainError};
use super::dname::Dname;
use super::relative::{DnameIter, RelativeDname};
use super::traits::{ToDname, ToLabelIter};


//------------ UncertainDname ------------------------------------------------

/// A domain name that may be absolute or relative.
///
/// This type is helpful when reading a domain name from some source where it
/// may end up being absolute or not.
#[derive(Clone)]
pub enum UncertainDname<O=Bytes> {
    Absolute(Dname<O>),
    Relative(RelativeDname<O>),
}

impl<O> UncertainDname<O> {
    /// Creates a new uncertain domain name from an absolute domain name.
    pub fn absolute(name: Dname<O>) -> Self {
        UncertainDname::Absolute(name)
    }

    /// Creates a new uncertain domain name from a relative domain name.
    pub fn relative(name: RelativeDname<O>) -> Self {
        UncertainDname::Relative(name)
    }

    /// Returns whether the name is absolute.
    pub fn is_absolute(&self) -> bool {
        match *self {
            UncertainDname::Absolute(_) => true,
            UncertainDname::Relative(_) => false,
        }
    }

    /// Returns whether the name is relative.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    /// Returns a reference to an absolute name, if this name is absolute.
    pub fn as_absolute(&self) -> Option<&Dname<O>> {
        match *self {
            UncertainDname::Absolute(ref name) => Some(name),
            _ => None
        }
    }

    /// Returns a reference to a relative name, if the name is relative.
    pub fn as_relative(&self) -> Option<&RelativeDname<O>> {
        match *self {
            UncertainDname::Relative(ref name) => Some(name),
            _ => None,
        }
    }

    /// Converts the name into an absolute name if it is absolute.
    ///
    /// Otherwise, returns itself as the error.
    pub fn try_into_absolute(self) -> Result<Dname<O>, Self> {
        if let UncertainDname::Absolute(name) = self {
            Ok(name)
        }
        else {
            Err(self)
        }
    }

    /// Converts the name into a relative name if it is relative.
    ///
    /// Otherwise just returns itself as the error.
    pub fn try_into_relative(self) -> Result<RelativeDname<O>, Self> {
        if let UncertainDname::Relative(name) = self {
            Ok(name)
        }
        else {
            Err(self)
        }
    }
}

impl<O: Octets> UncertainDname<O> {
    /// Creates a new uncertain domain name containing the root label only.
    pub fn root() -> Self {
        UncertainDname::Absolute(Dname::root())
    }

    /// Creates a new uncertain yet empty domain name.
    pub fn empty() -> Self {
        UncertainDname::Relative(RelativeDname::empty())
    }

    /// Makes an uncertain name absolute by chaining on a suffix if needed.
    ///
    /// The method converts the uncertain name into a chain that will
    /// be absolute. If the name is already absolute, the chain will be the
    /// name itself. If it is relative, if will be the concatenation of the
    /// name and `suffix`.
    pub fn chain<S: ToDname>(self, suffix: S)
                             -> Result<Chain<Self, S>, LongChainError> {
        Chain::new_uncertain(self, suffix)
    }

    /// Returns a byte slice with the raw content of the name.
    pub fn as_slice(&self) -> &[u8] {
        match *self {
            UncertainDname::Absolute(ref name) => name.as_slice(),
            UncertainDname::Relative(ref name) => name.as_slice(),
        }
    }
}

impl UncertainDname<Bytes> {
    /// Creates a domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots,
    /// actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// If the last character is a dot, the name will be absolute, otherwise
    /// it will be relative.
    ///
    /// If you have a string, you can also use the `FromStr` trait, which
    /// really does the same thing.
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
                      where C: IntoIterator<Item=char> {
        Self::_from_chars(chars.into_iter(), DnameBuilder::new())
    }

    /// Does the actual work for `from_chars` and `FromStr::from_str`.
    fn _from_chars<C>(mut chars: C, mut target: DnameBuilder)
                      -> Result<Self, FromStrError>
                   where C: Iterator<Item=char> {
        while let Some(ch) = chars.next() {
            match ch {
                '.' => {
                    if !target.in_label() {
                        return Err(FromStrError::EmptyLabel)
                    }
                    target.end_label();
                }
                '\\' => {
                    let in_label = target.in_label();
                    target.push(parse_escape(&mut chars, in_label)?)?;
                }
                ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                    target.push(ch as u8)?
                }
                _ => return Err(FromStrError::IllegalCharacter(ch))
            }
        }
        if target.in_label() || target.is_empty() {
            Ok(target.finish().into())
        }
        else {
            target.into_dname().map(Into::into)
                               .map_err(|_| FromStrError::LongName)
        }
    }

    /// Converts the name into an absolute name.
    ///
    /// If the name is relative, appends the root label to it using
    /// [`RelativeDname::into_absolute`].
    ///
    /// [`RelativeDname::into_absolute`]:
    ///     struct.RelativeDname.html#method.into_absolute
    pub fn into_absolute(self) -> Dname<Bytes> {
        match self {
            UncertainDname::Absolute(name) => unsafe {
                Dname::from_octets_unchecked(name.into_bytes())
            }
            UncertainDname::Relative(name) => name.into_absolute()
        }
    }
}


//--- Compose

impl<O: Octets> Compose for UncertainDname<O> {
    fn compose_len(&self) -> usize {
        match *self {
            UncertainDname::Absolute(ref name) => name.compose_len(),
            UncertainDname::Relative(ref name) => name.compose_len(),
        }
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        match *self {
            UncertainDname::Absolute(ref name) => name.compose(buf),
            UncertainDname::Relative(ref name) => name.compose(buf),
        }
    }
}


//--- From

impl<O> From<Dname<O>> for UncertainDname<O> {
    fn from(name: Dname<O>) -> Self {
        Self::absolute(name)
    }
}

impl<O> From<RelativeDname<O>> for UncertainDname<O> {
    fn from(name: RelativeDname<O>) -> Self {
        Self::relative(name)
    }
}


//--- FromStr

impl str::FromStr for UncertainDname<Bytes> {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::_from_chars(s.chars(), DnameBuilder::with_capacity(s.len()))
    }
}


//--- Scan

impl Scan for UncertainDname<Bytes> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        if let Ok(()) = scanner.skip_literal(".") {
            return Ok(UncertainDname::root())
        }
        scanner.scan_word(
            DnameBuilder::new(),
            |name, symbol| {
                match symbol {
                    Symbol::Char('.') => {
                        if name.in_label() {
                            name.end_label();
                        }
                        else {
                            return Err(FromStrError::EmptyLabel.into())
                        }
                    }
                    Symbol::Char(ch) | Symbol::SimpleEscape(ch) => {
                        if ch.is_ascii() {
                            if let Err(err) = name.push(ch as u8) {
                                return Err(FromStrError::from(err).into())
                            }
                        }
                        else {
                            return Err(FromStrError::IllegalCharacter(ch)
                                                    .into())
                        }
                    }
                    Symbol::DecimalEscape(ch) => {
                        if let Err(err) = name.push(ch) {
                            return Err(FromStrError::from(err).into())
                        }
                    }
                }
                Ok(())
            },
            |name| {
                if name.in_label() || name.is_empty() {
                    Ok(name.finish().into())
                }
                else {
                    name.into_dname()
                        .map(Into::into)
                        .map_err(|err| FromStrError::from(err).into())
                }
            }
        )
    }
}


//--- ToLabelIter

impl<'a, O: Octets> ToLabelIter<'a> for UncertainDname<O> {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        match *self {
            UncertainDname::Absolute(ref name) => name.iter_labels(),
            UncertainDname::Relative(ref name) => name.iter_labels(),
        }
    }
}


//--- PartialEq and Eq

impl<OS, OO> PartialEq<UncertainDname<OO>> for UncertainDname<OS>
where OS: Octets, OO: Octets {
    fn eq(&self, other: &UncertainDname<OO>) -> bool {
        use self::UncertainDname::*;

        match (self, other) {
            (&Absolute(ref left), &Absolute(ref right)) => left.eq(right),
            (&Relative(ref left), &Relative(ref right)) => left.eq(right),
            _ => false
        }
    }
}

impl<O: Octets> Eq for UncertainDname<O> { }


//--- Hash

impl<O: Octets> hash::Hash for UncertainDname<O> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match *self {
            UncertainDname::Absolute(ref inner) => inner.hash(state),
            UncertainDname::Relative(ref inner) => inner.hash(state),
        }
    }
}


//--- Display and Debug

impl<O: Octets> fmt::Display for UncertainDname<O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainDname::Absolute(ref name) => name.fmt(f),
            UncertainDname::Relative(ref name) => name.fmt(f),
        }
    }
}

impl<O: Octets> fmt::Debug for UncertainDname<O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainDname::Absolute(ref name) => {
                write!(f, "UncertainDname::Absolute({})", name)
            }
            UncertainDname::Relative(ref name) => {
                write!(f, "UncertainDname::Relative({})", name)
            }
        }
    }
}


//------------ Santa’s Little Helpers ----------------------------------------

/// Parses the contents of an escape sequence from `chars`.
///
/// The backslash should already have been taken out of `chars`.
fn parse_escape<C>(chars: &mut C, in_label: bool) -> Result<u8, FromStrError>
                where C: Iterator<Item=char> {
    let ch = try!(chars.next().ok_or(FromStrError::UnexpectedEnd));
    if ch >= '0' &&  ch <= '9' {
        let v = ch.to_digit(10).unwrap() * 100
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)))
                     * 10
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)));
        if v > 255 {
            return Err(FromStrError::IllegalEscape)
        }
        Ok(v as u8)
    }
    else if ch == '[' {
        // `\[` at the start of a label marks a binary label which we don’t
        // support. Within a label, the sequence is fine.
        if in_label {
            Ok(b'[')
        }
        else {
            Err(FromStrError::BinaryLabel)
        }
    }
    else { Ok(ch as u8) }
}


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    #[fail(display="unexpected end of input")]
    UnexpectedEnd,

    /// An empty label was encountered.
    #[fail(display="an empty label was encountered")]
    EmptyLabel,

    /// A binary label was encountered.
    #[fail(display="a binary label was encountered")]
    BinaryLabel,

    /// A domain name label has more than 63 octets.
    #[fail(display="label length limit exceeded")]
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    #[fail(display="illegal escape sequence")]
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    #[fail(display="illegal character '{}'", _0)]
    IllegalCharacter(char),

    /// The name has more than 255 characters.
    #[fail(display="long domain name")]
    LongName,
}

impl From<PushError> for FromStrError {
    fn from(err: PushError) -> FromStrError {
        match err {
            PushError::LongLabel => FromStrError::LongLabel,
            PushError::LongName => FromStrError::LongName,
        }
    }
}

impl From<PushNameError> for FromStrError {
    fn from(_: PushNameError) -> FromStrError {
        FromStrError::LongName
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_str() {
        use std::str::FromStr;

        fn name(s: &str) -> UncertainDname {
            UncertainDname::from_str(s).unwrap()
        }

        assert_eq!(name("www.example.com").as_relative().unwrap().as_slice(),
                   b"\x03www\x07example\x03com");
        assert_eq!(name("www.example.com.").as_absolute().unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");

        assert_eq!(name(r"www\.example.com").as_slice(),
                   b"\x0bwww.example\x03com");
        assert_eq!(name(r"w\119w.example.com").as_slice(),
                   b"\x03www\x07example\x03com");
        assert_eq!(name(r"w\000w.example.com").as_slice(),
                   b"\x03w\0w\x07example\x03com");

        assert_eq!(UncertainDname::from_str(r"w\01"),
                   Err(FromStrError::UnexpectedEnd));
        assert_eq!(UncertainDname::from_str(r"w\"),
                   Err(FromStrError::UnexpectedEnd));
        assert_eq!(UncertainDname::from_str(r"www..example.com"),
                   Err(FromStrError::EmptyLabel));
        assert_eq!(UncertainDname::from_str(r"www.example.com.."),
                   Err(FromStrError::EmptyLabel));
        assert_eq!(UncertainDname::from_str(r".www.example.com"),
                   Err(FromStrError::EmptyLabel));
        assert_eq!(UncertainDname::from_str(r"www.\[322].example.com"),
                   Err(FromStrError::BinaryLabel));
        assert_eq!(UncertainDname::from_str(r"www.\2example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(UncertainDname::from_str(r"www.\29example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(UncertainDname::from_str(r"www.\299example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(UncertainDname::from_str(r"www.\892example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(UncertainDname::from_str("www.e\0ample.com"),
                   Err(FromStrError::IllegalCharacter('\0')));
        assert_eq!(UncertainDname::from_str("www.eüample.com"),
                   Err(FromStrError::IllegalCharacter('ü')));

        // LongLabel
        let mut s = String::from("www.");
        for _ in 0..63 {
            s.push('x');
        }
        s.push_str(".com");
        assert!(UncertainDname::from_str(&s).is_ok());
        let mut s = String::from("www.");
        for _ in 0..64 {
            s.push('x');
        }
        s.push_str(".com");
        assert_eq!(UncertainDname::from_str(&s),
                   Err(FromStrError::LongLabel));

        // Long Name
        let mut s = String::new();
        for _ in 0..50 {
            s.push_str("four.");
        }
        let mut s1 = s.clone();
        s1.push_str("com.");
        assert_eq!(name(&s1).as_slice().len(), 255);
        let mut s1 = s.clone();
        s1.push_str("com");
        assert_eq!(name(&s1).as_slice().len(), 254);
        let mut s1 = s.clone();
        s1.push_str("coma.");
        assert_eq!(UncertainDname::from_str(&s1), Err(FromStrError::LongName));
        let mut s1 = s.clone();
        s1.push_str("coma");
        assert_eq!(UncertainDname::from_str(&s1), Err(FromStrError::LongName));
    }
}
