#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

cargo test --manifest-path rust/Cargo.toml --workspace
cargo build --manifest-path rust/Cargo.toml -p rusquitto-broker

test_root="$repo_dir/rust/target/mosquitto-test-root"
mkdir -p "$test_root/src"
cp "$repo_dir/rust/target/debug/mosquitto" "$test_root/src/mosquitto"

export BUILD_ROOT="$test_root"

(
    cd test/broker
    python3 01-connect-allow-anonymous.py
    python3 01-connect-listener-allow-anonymous.py
    python3 01-connect-uname-no-password-denied.py
    python3 01-connect-uname-or-anon.py
    python3 01-connect-uname-password-denied.py
    python3 01-connect-uname-password-denied-no-will.py
    python3 01-connect-disconnect-v5.py
    python3 01-connect-auto-id.py
    python3 01-connect-zero-length-id.py
    python3 01-connect-accept-protocol.py
    python3 01-connect-windows-line-endings.py
    python3 01-connect-take-over.py
    python3 02-shared-qos0-v5.py
    python3 02-subpub-recover-subscriptions.py
    python3 02-subpub-qos0-long-topic.py
    python3 02-subpub-qos0-subscription-id.py
    python3 02-subpub-qos0-send-retain.py
    python3 02-subpub-qos0-topic-alias.py
    python3 03-publish-b2c-disconnect-qos2.py
    python3 03-publish-b2c-qos2-len.py
    python3 03-publish-qos1-no-subscribers-v5.py
    python3 03-publish-qos1-retain-disabled.py
    python3 04-retain-clear-multiple.py
    python3 04-retain-qos0-repeated.py
    python3 04-retain-upgrade-outgoing-qos.py
    python3 07-will-qos0.py
    python3 09-acl-empty-file.py
    python3 09-acl-access-variants.py
    python3 09-acl-change.py
    python3 10-listener-mount-point.py
    python3 12-prop-assigned-client-identifier.py
    python3 12-prop-server-keepalive.py
    python3 12-prop-response-topic.py
    python3 12-prop-response-topic-correlation-data.py
    python3 12-prop-maximum-packet-size-broker.py
    python3 12-prop-maximum-packet-size-publish-qos1.py
    python3 12-prop-maximum-packet-size-publish-qos2.py
)
