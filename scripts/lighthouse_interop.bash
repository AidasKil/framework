#!/usr/bin/env bash

# You can use this to install non-Rust dependencies on Debian-based distributions.
install_dependencies_on_debian() {
    apt-get install \
        bash        \
        git         \
        moreutils   \
        pipexec     \
        ruby
}

set -o errexit

readonly LIBP2P_PORT=9000
readonly LIGHTHOUSE_LIBP2P_PORT=9001
readonly LIGHTHOUSE_HTTP_PORT=9002
readonly FIRST_VALIDATOR=0
readonly VALIDATOR_COUNT=64

readonly script_dir="$(dirname "$0")"
readonly lighthouse_dir="$script_dir"/../lighthouse
readonly genesis_time="$(date +%s)"

genesis_state() {
    exec erb genesis_time="$genesis_time" "$script_dir"/interop_minimal_genesis_state.yaml.erb
}

beacon_node() {
    exec cargo run                                  \
        --manifest-path "$script_dir"/../Cargo.toml \
        --release                                   \
        --                                          \
        "
            preset: Minimal
            genesis_state_path: "<(genesis_state)"
            network_dir: /tmp/beacon_node
            libp2p_port: $LIBP2P_PORT
            discovery_port: $LIBP2P_PORT
            libp2p_nodes:
                - /dns4/localhost/tcp/$LIGHTHOUSE_LIBP2P_PORT
        "
}

lighthouse() {
    exec cargo run                                   \
        --bin lighthouse                             \
        --manifest-path "$lighthouse_dir"/Cargo.toml \
        --release                                    \
        --                                           \
        "$@"
}

lighthouse_beacon_node() {
    lighthouse                                                \
        --datadir /tmp/lighthouse_beacon_node                 \
        --spec minimal                                        \
        beacon_node                                           \
        --dummy-eth1                                          \
        --http                                                \
        --http-port "$LIGHTHOUSE_HTTP_PORT"                   \
        --libp2p-addresses /dns4/localhost/tcp/"$LIBP2P_PORT" \
        --port "$LIGHTHOUSE_LIBP2P_PORT"                      \
        testnet                                               \
        --force                                               \
        quick "$VALIDATOR_COUNT" "$genesis_time"
}

lighthouse_validator_client() {
    lighthouse                                            \
        --datadir /tmp/lighthouse_validator_client        \
        --spec minimal                                    \
        validator_client                                  \
        --server http://localhost:"$LIGHTHOUSE_HTTP_PORT" \
        testnet                                           \
        insecure "$FIRST_VALIDATOR" "$VALIDATOR_COUNT"
}

git submodule update --init "$lighthouse_dir"

exec  {bn}< <(beacon_node                 |& ts 'beacon_node                 |')
exec {lbn}< <(lighthouse_beacon_node      |& ts 'lighthouse_beacon_node      |')
exec {lvc}< <(lighthouse_validator_client |& ts 'lighthouse_validator_client |')

exec peet                 \
    "$bn"   "$bn"<&"$bn"  \
    "$lbn" "$lbn"<&"$lbn" \
    "$lvc" "$lvc"<&"$lvc"
