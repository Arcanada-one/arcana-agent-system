//! V-AC-10(e) / Task-AC-3: no Kafka/broker crate in the resolved dep tree.
//!
//! The suspend/resume channel is in-process tokio only. This asserts the
//! workspace `Cargo.lock` resolves no message-broker crate — the "premature
//! scale (broker before one loop closes)" risk is gated in the lockfile.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

/// Broker crate names that MUST NOT appear as a resolved package.
const BROKER_CRATES: &[&str] = &[
    "kafka", "rdkafka", "amqp", "lapin", "nats", "async-nats", "pulsar", "rabbitmq-stream-client",
    "nsq",
];

fn workspace_lock() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.lock")
}

#[test]
fn no_broker_dep() {
    let lock = workspace_lock();
    let contents = std::fs::read_to_string(&lock)
        .unwrap_or_else(|err| panic!("read {}: {err}", lock.display()));

    for broker in BROKER_CRATES {
        let needle = format!("name = \"{broker}\"");
        assert!(
            !contents.contains(&needle),
            "broker crate '{broker}' must not appear in the resolved dependency tree ({})",
            lock.display()
        );
    }
}
