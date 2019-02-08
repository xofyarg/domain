//! Generic octet sequences.

use std::{cmp, ptr};
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


//------------ OctetsMut -----------------------------------------------------

pub trait OctetsMut {
    /// Attempts to make sure that capacity is at least `remaining` octets.
    ///
    /// If it is not possible to provide space for `remaining` octets, the
    /// method returns `false`. If there is already enough space or the
    /// space has been grown to be large enough, returns `true`.
    fn ensure_remaining(&mut self, remaining: usize) -> bool;

    unsafe fn advance_mut(&mut self, count: usize);
    unsafe fn buf_mut(&mut self) -> &mut [u8];

    fn put_slice(&mut self, mut slice: &[u8]) {
        assert!(self.ensure_remaining(slice.len()));
        while !slice.is_empty() {
            let len = unsafe {
                let dst = self.buf_mut();
                assert!(!dst.is_empty());
                let len = cmp::min(slice.len(), dst.len());
                ptr::copy_nonoverlapping(
                    slice.as_ptr(), dst.as_mut_ptr(), len
                );
                len
            };
            slice = &slice[len..];
        }
    }

    fn put_u8(&mut self, value: u8) {
        let value = [value];
        self.put_slice(&value);
    }
}

