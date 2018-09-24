// Copyright 2017, 2018 Parity Technologies
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

#![feature(test)]

extern crate hashdb;
extern crate memorydb;
extern crate keccak_hasher;
extern crate test;

use memorydb::MemoryDB;
use keccak_hasher::KeccakHasher;
use hashdb::{HashDB, Hasher};
use test::{Bencher, black_box};

#[bench]
fn instantiation(b: &mut Bencher) {
    b.iter(|| {
        MemoryDB::<KeccakHasher, Vec<u8>>::new();
    })
}

#[bench]
fn compare_to_null_embedded_in_struct(b: &mut Bencher) {
    struct X {a_hash: <KeccakHasher as Hasher>::Out};
    let x = X {a_hash: KeccakHasher::hash(&[0u8][..])};
    let key = KeccakHasher::hash(b"abc");

    b.iter(|| {
        black_box(key == x.a_hash);
    })
}

#[bench]
fn compare_to_null_in_const(b: &mut Bencher) {
    let key = KeccakHasher::hash(b"abc");

    b.iter(|| {
        black_box(key == [0u8; 32]);
    })
}

#[bench]
fn contains_with_non_null_key(b: &mut Bencher) {
    let mut m = MemoryDB::<KeccakHasher, Vec<u8>>::new();
    let key = KeccakHasher::hash(b"abc");
    m.insert(b"abcefghijklmnopqrstuvxyz");
    b.iter(|| {
        m.contains(&key);
    })
}

#[bench]
fn contains_with_null_key(b: &mut Bencher) {
    let mut m = MemoryDB::<KeccakHasher, Vec<u8>>::default();
    let null_key = KeccakHasher::hash(&[0u8][..]);
    m.insert(b"abcefghijklmnopqrstuvxyz");
    b.iter(|| {
        m.contains(&null_key);
    })
}
