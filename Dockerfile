
FROM ubuntu:20.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang curl
RUN curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN ${HOME}/.cargo/bin/rustup default nightly
RUN ${HOME}/.cargo/bin/cargo install -f cargo-fuzz

ADD . /trie
WORKDIR /trie

## TODO: ADD YOUR BUILD INSTRUCTIONS HERE.
# RUN ${HOME}/.cargo/bin/cargo build --all
RUN cd trie-db && \
    cd fuzz && ${HOME}/.cargo/bin/cargo fuzz build

# Package Stage
FROM ubuntu:20.04


## TODO: Change <Path in Builder Stage>
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/trie_root_new /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/trie_root /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/trie_root_fix_len /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/no_ext_insert /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/no_ext_insert_rem /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/prefix_iter /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/seek_iter /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/trie_proof_valid /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/trie_codec_proof /
COPY --from=builder trie/trie-db/fuzz/target/x86_64-unknown-linux-gnu/release/trie_proof_invalid /
