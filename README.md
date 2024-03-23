<a href="https://atsign.com#gh-light-mode-only"><img width=250px src="https://atsign.com/wp-content/uploads/2022/05/atsign-logo-horizontal-color2022.svg#gh-light-mode-only" alt="The Atsign Foundation"></a><a href="https://atsign.com#gh-dark-mode-only"><img width=250px src="https://atsign.com/wp-content/uploads/2023/08/atsign-logo-horizontal-reverse2022-Color.svg#gh-dark-mode-only" alt="The Atsign Foundation"></a>

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_rust/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_rust)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8148/badge)](https://www.bestpractices.dev/projects/8148)

# Rust SDK - (⚠️Alpha version⚠️)
This repo contains libraries, tools, samples and examples for developers who wish to work with the atPlatform from Rust code.

It currently has limited functionality with minimal tests.

## Requirements
The following need to be installed:
- `rust` - [Installation instructions](https://doc.rust-lang.org/book/ch01-01-installation.html)
- `pkg-config`

## Tests
Run `cargo test --workspace` to run all tests in the different workspaces.
Add `-- --nocapture` to see the logs during the tests.
Run `cargo test -p <workspace_name>` to run tests for a specific workspace.

## Run examples
Prefix all commands with `RUST_LOG=info` (or `debug` or `trace`) to see logs.
### Scan
Get the keys currently in the @sign's server.
Run `cargo run --example scan_example -- --help` for more information.

### Put data
Put data into the @sign's server.
Run `cargo run --example put_data_example -- --help` for more information.

### Get data
Get data from the @sign's server.
Run `cargo run --example get_data_example -- --help` for more information.


## Structure
This repo is broken down into workspaces to help with organization and separation of concerns. It will also make adding implementations for specific harware easier. The workspaces are:
- `at_chops` (Cryptographic and Hashing Operations (CHOPS)).
  - `lib.rs` - Contains the specific combination of crypto operations required by the `AtProtocol`.
  - `crypto_functions_trait.rs` - A trait which defines the methods that `AtChops` requires.
  - `default_crypto_functions.rs` - Contains an implementation of the `CryptoFunctions` trait using [RustCrypto](https://github.com/RustCrypto), a pure Rust implementation of cryptographic algorithms.
- `at_errors` - Contains the error types that the library can return including associated functions for creating them.
- `at_records` - Contains the `AtRecord` struct which is used to store the data that is sent and received.
- `at_secrets` - Contains the `AtSecrets` struct which is used to store the secrets required by the `AtClient` as well as associated functions for creating them from a file.
- `at_sign` - Contains the `AtSign` struct which is used for working with AtSigns.
- `at_tls` - Contains the `TlsClient` struct which is used to establish a TLS connection with the atServer and send and receive data.
  - `lib.rs` - Contains the `TlsClient` struct and methods for TLS related operations.
  - `tls_connection_trait.rs` - A trait which defines the signature for creating a connection.
  - `rustls_connection.rs` - Contains an implementation of the `TlsConnection` trait using [Rustls](https://github.com/rustls/)
- `at_verbs` - Contains a trait that all verbs have to implement. Also contains implementations for the verbs.
- `src` - Contains the main library code.
  - `at_client.rs` - Contains the `AtClient` struct which is used to interact with the atPlatform.

## Logging
This library uses the `log` crate. This means implementors of this library can use something like `env_logger` and get info from the library.

## Contributions welcome!
All of our software is open with intent. We welcome contributions - we want pull requests, and we want to hear about issues. See also [CONTRIBUTING.md](CONTRIBUTING.md).

## Steps to Beta
- [ ] Notifications using the `monitor` verb
- [x] Interoperability with other SDKs

## Future goals
- [ ] Full test coverage
- [ ] Ability to implement different cryptographic and TLS libraries
- [ ] `no_std` implementation
- [ ] Distribute to `crates.io`
- [ ] Support for `async` runtime
- [ ] Add default implementations for TLS connection on multiple platforms (ESP32, Linux, Pico W)
