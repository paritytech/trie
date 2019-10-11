// Copyright 2019 Parity Technologies
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

///! Common utilities for reference trie implementations.

use parity_scale_codec::{Compact, Decode, Encode, Error as CodecError, Input};
use trie_db::nibble_ops::NIBBLE_LENGTH;

use crate::std::{result::Result, vec::Vec};
use crate::node::{ProofBranchChild, ProofBranchValue};

pub fn take<'a>(input: &mut &'a[u8], count: usize) -> Option<&'a[u8]> {
    if input.len() < count {
        return None
    }
    let r = &(*input)[..count];
    *input = &(*input)[count..];
    Some(r)
}

pub const BITMAP_LENGTH: usize = 2;

/// Radix 16 trie, bitmap encoding implementation,
/// it contains children mapping information for a branch
/// (children presence only), it encodes into
/// a compact bitmap encoding representation.
pub struct Bitmap(u16);

impl Bitmap {
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        Ok(Bitmap(u16::decode(&mut &data[..])?))
    }

    pub fn value_at(&self, i: usize) -> bool {
        self.0 & (1u16 << i) != 0
    }

    pub fn encode<I: Iterator<Item = bool>>(has_children: I , dest: &mut [u8]) {
        let mut bitmap: u16 = 0;
        let mut cursor: u16 = 1;
        for v in has_children {
            if v { bitmap |= cursor }
            cursor <<= 1;
        }
        dest[0] = (bitmap % 256) as u8;
        dest[1] = (bitmap / 256) as u8;
    }
}

pub const BRANCH_VALUE_OMITTED: u8 = 0;
pub const BRANCH_VALUE_INLINE: u8 = 1;

pub fn encode_branch_value(output: &mut Vec<u8>, value: &ProofBranchValue) {
    match value {
        ProofBranchValue::Empty => {},
        ProofBranchValue::Omitted => {
            output.push(BRANCH_VALUE_OMITTED);
        }
        ProofBranchValue::Included(data) => {
            output.push(BRANCH_VALUE_INLINE);
            Compact(data.len() as u32).encode_to(output);
            output.extend_from_slice(data);
        }
    }
}

pub fn encode_branch_children(output: &mut Vec<u8>, children: &[ProofBranchChild; NIBBLE_LENGTH]) {
    let offset = output.len();
    output.extend_from_slice(&[0; 2 * BITMAP_LENGTH][..]);
    let (has_children, inline_children) = children.iter()
        .map(|child| match child {
            ProofBranchChild::Empty => (false, false),
            ProofBranchChild::Omitted => (true, false),
            ProofBranchChild::Included(data) => {
                Compact(data.len() as u32).encode_to(output);
                output.extend_from_slice(data);
                (true, true)
            }
        })
        .unzip::<_, _, Vec<_>, Vec<_>>();
    Bitmap::encode(
        has_children.iter().cloned(),
        &mut output[offset..(offset + BITMAP_LENGTH)]
    );
    Bitmap::encode(
        inline_children.iter().cloned(),
        &mut output[(offset + BITMAP_LENGTH)..(offset + 2 * BITMAP_LENGTH)]
    );
}

pub fn decode_branch_value<'a>(input: &mut &'a [u8], has_value: bool)
    -> Result<ProofBranchValue<'a>, CodecError>
{
    if has_value {
        match input.read_byte()? {
            BRANCH_VALUE_OMITTED => Ok(ProofBranchValue::Omitted),
            BRANCH_VALUE_INLINE => {
                let count = <Compact<u32>>::decode(input)?.0 as usize;
                let data = take(input, count).ok_or(CodecError::from("Bad format"))?;
                Ok(ProofBranchValue::Included(data))
            }
            _ => Err(CodecError::from("Bad format")),
        }
    } else {
        Ok(ProofBranchValue::Empty)
    }
}

pub fn decode_branch_children<'a>(input: &mut &'a [u8])
    -> Result<[ProofBranchChild<'a>; NIBBLE_LENGTH], CodecError>
{
    let bitmap_slice = take(input, BITMAP_LENGTH)
        .ok_or(CodecError::from("Bad format"))?;
    let has_children_bitmap = Bitmap::decode(&bitmap_slice[..])?;

    let bitmap_slice = take(input, BITMAP_LENGTH)
        .ok_or(CodecError::from("Bad format"))?;
    let inline_children_bitmap = Bitmap::decode(&bitmap_slice[..])?;

    let mut children = [ProofBranchChild::Empty; 16];
    for i in 0..NIBBLE_LENGTH {
        if inline_children_bitmap.value_at(i) {
            let count = <Compact<u32>>::decode(input)?.0 as usize;
            let data = take(input, count).ok_or(CodecError::from("Bad format"))?;
            children[i] = ProofBranchChild::Included(data);
        } else if has_children_bitmap.value_at(i) {
            children[i] = ProofBranchChild::Omitted;
        }
    }
    Ok(children)
}
