//! Generic octet sequences.

use std::{cmp, ops, ptr};
use bytes::{BigEndian, BufMut, ByteOrder, Bytes, BytesMut};


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
            unsafe {
                self.advance_mut(len);
            }
            slice = &slice[len..];
        }
    }

    fn put_u8(&mut self, value: u8) {
        let value = [value];
        self.put_slice(&value);
    }

    fn put_i8(&mut self, value: i8) {
        let value = [value as u8];
        self.put_slice(&value);
    }

    fn put_u16(&mut self, value: u16) {
        let mut buf = [0; 2];
        BigEndian::write_u16(&mut buf, value);
        self.put_slice(&buf);
    }

    fn put_i16(&mut self, value: i16) {
        let mut buf = [0; 2];
        BigEndian::write_i16(&mut buf, value);
        self.put_slice(&buf);
    }

    fn put_u32(&mut self, value: u32) {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf, value);
        self.put_slice(&buf);
    }

    fn put_i32(&mut self, value: i32) {
        let mut buf = [0; 4];
        BigEndian::write_i32(&mut buf, value);
        self.put_slice(&buf);
    }

    fn put_u64(&mut self, value: u64) {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf, value);
        self.put_slice(&buf);
    }
}

impl OctetsMut for BytesMut {
    fn ensure_remaining(&mut self, remaining: usize) -> bool {
        if self.remaining_mut() < remaining {
            self.reserve(remaining)
        }
        true
    }

    unsafe fn advance_mut(&mut self, count: usize) {
        <Self as BufMut>::advance_mut(self, count)
    }

    unsafe fn buf_mut(&mut self) -> &mut [u8] {
        <Self as BufMut>::bytes_mut(self)
    }
}


//------------ SliceBuf ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SliceBuf<B> {
    buf: B,
    pos: usize,
}

impl<B> SliceBuf<B> {
    pub fn new(buf: B, pos: usize) -> Self {
        SliceBuf { buf, pos }
    }

    pub fn from_empty_buf(buf: B) -> Self {
        Self::new(buf, 0)
    }

    pub fn unwrap(self) -> B {
        self.buf   
    }
}

impl<B: AsRef<[u8]>> SliceBuf<B> {
    pub fn from_filled_buf(buf: B) -> Self {
        let len = buf.as_ref().len();
        Self::new(buf, len)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf.as_ref()[..self.pos]
    }
}


//--- Deref and AsRef

impl<B: AsRef<[u8]>> ops::Deref for SliceBuf<B> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for SliceBuf<B> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}


//--- Octets and OctetsMut

impl<B: Octets> Octets for SliceBuf<B> {
    fn from_static(slice: &'static [u8]) -> Self {
        Self::from_filled_buf(B::from_static(slice))
    }

    fn range(&self, start: usize, end: usize) -> Self {
        assert!(start <= self.pos);
        assert!(end <= self.pos);
        Self::from_filled_buf(self.buf.range(start, end))
    }

    fn into_bytes(self) -> Bytes {
        self.as_slice().into()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> OctetsMut for SliceBuf<B> {
    fn ensure_remaining(&mut self, remaining: usize) -> bool {
        self.buf.as_ref().len() - self.pos >= remaining
    }

    unsafe fn advance_mut(&mut self, count: usize) {
        self.pos += count;
        assert!(self.pos <= self.buf.as_ref().len());
    }

    unsafe fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[self.pos..]
    }
}

