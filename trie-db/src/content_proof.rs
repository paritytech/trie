// Copyright 2023, 2023 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Compact content proof, a sequence of content as met in the trie.
//! Exception for hashes that are only encoded when node is popped, allowing to merge a few more key
//! manipulation op. Values are return as seen to avoid the need to keep them all (warning a return
//! value may be from an invalid proof and action on those value usually need to be revertible).
//! Proof validity as for compact proof is only possible to check at the end of the proof reading.

use crate::query_plan::RecorderOutput;
/// Representation of each encoded action
/// for building the proof.
/// TODO ref variant for encoding ?? or key using V and use Op<&H, &[u8]>.
use core::marker::PhantomData;

#[derive(Debug)]
pub enum Op<H, V> {
	// key content followed by a mask for last byte.
	// If mask erase some content the content need to
	// be set at 0 (or error).
	// Two consecutive `KeyPush` are invalid.
	KeyPush(Vec<u8>, u8), /* TODO could use BackingByteVec (but Vec for new as it scale
	                       * encode) */
	// Last call to pop is implicit (up to root), defining
	// one will result in an error.
	// Two consecutive `KeyPop` are invalid.
	// TODO should be compact encoding of number.
	KeyPop(u16),
	// u8 is child index, shorthand for key push one nibble followed by key pop.
	HashChild(H, u8),
	// All value variant are only after a `KeyPush` or at first position.
	HashValue(H),
	Value(V),
	// This is not strictly necessary, only if the proof is not sized, otherwhise if we know
	// the stream will end it can be skipped.
	EndProof,
}

// Limiting size to u32 (could also just use a terminal character).
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
struct VarInt(u32);

impl VarInt {
	fn encoded_len(&self) -> usize {
		if self.0 == 0 {
			return 1
		}
		let len = 32 - self.0.leading_zeros() as usize;
		if len % 7 == 0 {
			len / 7
		} else {
			len / 7 + 1
		}
		/*
		match self.0 {
			l if l < 2 ^ 7 => 1, // leading 0: 25
			l if l < 2 ^ 14 => 2, // leading 0: 18

			l if l < 2 ^ 21 => 3, // 11
			l if l < 2 ^ 28 => 4, // 4
			_ => 5,
		}
		*/
	}

	fn encode_into(&self, out: &mut impl RecorderOutput) {
		let mut to_encode = self.0;
		for _ in 0..self.encoded_len() - 1 {
			out.write_bytes(&[0b1000_0000 | to_encode as u8]);
			to_encode >>= 7;
		}
		out.write_bytes(&[to_encode as u8]);
	}

	fn decode(encoded: &[u8]) -> Result<(Self, usize), ()> {
		let mut value = 0u32;
		for (i, byte) in encoded.iter().enumerate() {
			let last = byte & 0b1000_0000 == 0;
			value |= ((byte & 0b0111_1111) as u32) << (i * 7);
			if last {
				return Ok((VarInt(value), i + 1))
			}
		}
		Err(())
	}
}

#[test]
fn varint_encode_decode() {
	let mut buf = super::InMemoryRecorder::default();
	for i in 0..u16::MAX as u32 + 1 {
		VarInt(i).encode_into(&mut buf);
		assert_eq!(buf.buffer.len(), VarInt(i).encoded_len());
		assert_eq!(Ok((VarInt(i), buf.buffer.len())), VarInt::decode(&buf.buffer));
		buf.buffer.clear();
	}
}

impl<H: AsRef<[u8]>, V: AsRef<[u8]>> Op<H, V> {
	/// Calculate encoded len.
	pub fn encoded_len(&self) -> usize {
		let mut len = 1;
		match self {
			Op::KeyPush(key, _mask) => {
				len += VarInt(key.len() as u32).encoded_len();
				len += key.len();
				len += 1;
			},
			Op::KeyPop(nb) => {
				len += VarInt(*nb as u32).encoded_len();
			},
			Op::HashChild(hash, _at) => {
				len += hash.as_ref().len();
				len += 1;
			},
			Op::HashValue(hash) => {
				len += hash.as_ref().len();
			},
			Op::Value(value) => {
				len += VarInt(value.as_ref().len() as u32).encoded_len();
				len += value.as_ref().len();
			},
			Op::EndProof => (),
		}
		len
	}

	/// Write op.
	pub fn encode_into(&self, out: &mut impl RecorderOutput) {
		match self {
			Op::KeyPush(key, mask) => {
				out.write_bytes(&[0]);
				VarInt(key.len() as u32).encode_into(out);
				out.write_bytes(&key);
				out.write_bytes(&[*mask]);
			},
			Op::KeyPop(nb) => {
				out.write_bytes(&[1]);
				VarInt(*nb as u32).encode_into(out);
			},
			Op::HashChild(hash, at) => {
				out.write_bytes(&[2]);
				out.write_bytes(hash.as_ref());
				out.write_bytes(&[*at]);
			},
			Op::HashValue(hash) => {
				out.write_bytes(&[3]);
				out.write_bytes(hash.as_ref());
			},
			Op::Value(value) => {
				out.write_bytes(&[4]);
				let value = value.as_ref();
				VarInt(value.len() as u32).encode_into(out);
				out.write_bytes(&value);
			},
			Op::EndProof => {
				out.write_bytes(&[5]);
			},
		}
	}
}

impl<H: AsRef<[u8]> + AsMut<[u8]> + Default> Op<H, Vec<u8>> {
	/// Read an op, return op and number byte read. Or error if invalid encoded.
	pub fn decode(encoded: &[u8]) -> Result<(Self, usize), ()> {
		let mut i = 0;
		if i >= encoded.len() {
			return Err(())
		}
		Ok(match encoded[i] {
			0 => {
				let (len, offset) = VarInt::decode(&encoded[i + 1..])?;
				i += 1 + offset;
				if i + len.0 as usize >= encoded.len() {
					return Err(())
				}
				let key = &encoded[i..i + len.0 as usize];
				let mask = encoded[i + len.0 as usize];
				(Op::KeyPush(key.to_vec(), mask), i + len.0 as usize + 1)
			},
			1 => {
				let (len, offset) = VarInt::decode(&encoded[i + 1..])?;
				if len.0 > u16::MAX as u32 {
					return Err(())
				}
				(Op::KeyPop(len.0 as u16), i + 1 + offset)
			},
			2 => {
				let mut hash = H::default();
				let end = i + 1 + hash.as_ref().len();
				if end >= encoded.len() {
					return Err(())
				}
				hash.as_mut().copy_from_slice(&encoded[i + 1..end]);
				let mask = encoded[end];
				(Op::HashChild(hash, mask), end + 1)
			},
			3 => {
				let mut hash = H::default();
				let end = i + 1 + hash.as_ref().len();
				if end >= encoded.len() {
					return Err(())
				}
				hash.as_mut().copy_from_slice(&encoded[i + 1..end]);
				(Op::HashValue(hash), end)
			},
			4 => {
				let (len, offset) = VarInt::decode(&encoded[i + 1..])?;
				i += 1 + offset;
				if i + len.0 as usize > encoded.len() {
					return Err(())
				}
				let value = &encoded[i..i + len.0 as usize];
				(Op::Value(value.to_vec()), i + len.0 as usize)
			},
			5 => (Op::EndProof, 1),
			_ => return Err(()),
		})
	}
}

/// Iterator on op from a in memory encoded proof.
pub struct IterOpProof<H: AsRef<[u8]> + AsMut<[u8]> + Default, B: AsRef<[u8]>>(
	B,
	usize,
	PhantomData<H>,
);

impl<H: AsRef<[u8]> + AsMut<[u8]> + Default, B: AsRef<[u8]>> From<B> for IterOpProof<H, B> {
	fn from(b: B) -> Self {
		Self(b, 0, PhantomData)
	}
}

impl<H: AsRef<[u8]> + AsMut<[u8]> + Default, B: AsRef<[u8]>> Iterator for IterOpProof<H, B> {
	type Item = Option<Op<H, Vec<u8>>>;

	fn next(&mut self) -> Option<Self::Item> {
		match Op::decode(&self.0.as_ref()[self.1..]) {
			Ok((op, len)) => {
				self.1 += len;
				Some(Some(op))
			},
			Err(_) => Some(None),
		}
	}
}
