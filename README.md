# socker

![](https://badgers.space/badge/MSRV/Edition%202024%20(1.85)/blue)

A [SOCKS5](https://datatracker.ietf.org/doc/html/rfc1928) implementation available as as [library](./lib).

It provides APIs for working with the protocol in a runtime-independant maner thanks to *[futures](https://crates.io/crates/futures/)* crate.

## `cargo` features

* `tokio` (disabled by default) - provides *[Tokio](https://crates.io/crates/tokio/)*-based implementations for `trait Client` and `trait Server`.

## How to use

I'd recommend you looking into the implementations of the *[Tokio](https://crates.io/crates/tokio/)*-based [client](./lib/src/socks5/client/tokio.rs) and [server](./lib/src/socks5/server/tokio.rs) to understand how to use the library.

# License

This project uses [Tiwaz License, version 1.0](https://github.com/tiwaz-license/version-1.0).