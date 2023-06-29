#![no_main]
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use reference_trie::{RefHasher, SubstrateV1};
use trie_db::query_plan::ProofKind;
use trie_db_test::fuzz::query_plan::{
	build_state, fuzz_query_plan_conf, ArbitraryQueryPlan, FuzzContext, CONF1,
};
use arbitrary::Arbitrary;

lazy_static! {
	static ref CONTEXT: FuzzContext<SubstrateV1<RefHasher>> = build_state(CONF1);
}

#[derive(Debug, Clone, Copy, Arbitrary)]
#[repr(usize)]
enum SplitSize {
	One = 1,
	Two = 2,
	Three = 3,
	More = 10,
	MoreMore = 50,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Arbitrary)]
enum SplitKind {
	Stateless,
	Stateful,
}

fuzz_target!(|input: (ArbitraryQueryPlan, SplitSize, SplitKind)| {
	let (plan, split_size, split_kind) = input;
	let mut conf = CONTEXT.conf.clone();
	conf.kind = ProofKind::CompactNodes;
	conf.limit = split_size as usize;
	conf.proof_spawn_with_persistence = split_kind == SplitKind::Stateful;
	fuzz_query_plan_conf::<SubstrateV1<RefHasher>>(&CONTEXT, conf, plan);
});
