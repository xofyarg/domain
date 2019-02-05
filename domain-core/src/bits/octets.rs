//! Generic octet sequences.

use bytes::Bytes;


//------------ Octets --------------------------------------------------------

pub trait Octets: AsRef<[u8]> + Clone + Sized {
    fn from_static(slice: &'static [u8]) -> Self;
    fn range(&self, start: usize, end: usize) -> Self;
    fn into_bytes(self) -> Bytes;

    fn range_to(&self, end: usize) -> Self {
        self.range(0, end)
    }

    fn range_from(&self, start: usize) -> Self {
        self.range(start, self.as_ref().len())
    }

    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    fn len(&self) -> usize {
        self.as_ref().len()
    }
}

impl<'a> Octets for &'a [u8] {
    fn from_static(slice: &'static [u8]) -> Self {
        slice
    }

    fn range(&self, start: usize, end: usize) -> Self {
        &self[start..end]
    }

    fn into_bytes(self) -> Bytes {
        self.into()
    }
}

impl Octets for Bytes {
    fn from_static(slice: &'static [u8]) -> Self {
        Bytes::from_static(slice)
    }

    fn range(&self, start: usize, end: usize) -> Self {
        self.slice(start, end)
    }

    fn into_bytes(self) -> Bytes {
        self
    }
}

