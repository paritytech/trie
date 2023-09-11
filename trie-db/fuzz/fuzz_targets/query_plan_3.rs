#![no_main]
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use reference_trie::{RefHasher, SubstrateV1};
use trie_db_test::fuzz::query_plan::{
	build_state, fuzz_query_plan, ArbitraryQueryPlan, FuzzContext, CONF2,
};

lazy_static! {
	static ref CONTEXT: FuzzContext<SubstrateV1<RefHasher>> = build_state(CONF2);
}

fuzz_target!(|plan: ArbitraryQueryPlan| {
	fuzz_query_plan::<SubstrateV1<RefHasher>>(&CONTEXT, plan);
});
