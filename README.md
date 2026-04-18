# iroh-dht (triblespace fork)

> **This repository is archived.**
>
> The code has been integrated into
> [`triblespace-rs`](https://github.com/triblespace/triblespace-rs)
> as a private module of the `triblespace-net` crate — see
> [`triblespace-net/src/dht/mod.rs`](https://github.com/triblespace/triblespace-rs/blob/main/triblespace-net/src/dht/mod.rs).
> It is no longer released as a separate crate.

## Why it moved

This fork carried ~300 lines of work ahead of n0's
[`iroh-dht-experiment`](https://github.com/n0-computer/iroh-dht-experiment):
API migration to iroh main, a `ContentDiscovery` trait impl for
iroh-blobs integration, and small cleanups. Triblespace was the only
consumer, so keeping it as an independent crate meant taking on a
release + publication line for an experimental DHT that served exactly
one downstream. Inlining it into `triblespace-net` removes that
overhead and lets the DHT code evolve at the same cadence as its
consumer.

If n0 upstreams our API-migration changes to `iroh-dht-experiment` and
that crate becomes a stable published dependency, `triblespace-net`
can switch back to a crate-level dep — the integration is
self-contained enough that re-extraction is a mechanical reverse.

## Where to look

- **Source:** [`triblespace-rs/triblespace-net/src/dht`](https://github.com/triblespace/triblespace-rs/tree/main/triblespace-net/src/dht)
- **Issues & PRs:** [triblespace-rs/issues](https://github.com/triblespace/triblespace-rs/issues)
- **Distributed-sync book chapter:** [triblespace book](https://docs.rs/triblespace/)

## History

All commits from this repo (including the six ahead of upstream — API
migration, `ContentDiscovery` impl, etc.) are preserved in this repo's
git history. The integration into `triblespace-net` was done as a
direct copy rather than a subtree merge, so commit-by-commit authorship
lives here.

## License

Copyright 2025 N0, INC. and triblespace contributors

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option.
