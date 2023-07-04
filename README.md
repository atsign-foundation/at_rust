<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_rust/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_rust)

# Rust SDK - (⚠️Alpha version⚠️)
This repo contains libraries, tools, samples and examples for developers who wish to work with the atPlatform from Rust code.

It currently has limited functionality with minimal tests.

## Requirements
The following need to be installed:
- `rust` - [Installation instructions](https://doc.rust-lang.org/book/ch01-01-installation.html)
- `openssl`
- `libssl-dev`
- `pkg-config`

## Run examples
### Send data
Send data to an atSign - `cargo run --example send_data_example <path-to-at-keys> <message> <atSign-of-sender> <atSign-of-receiver>`
- `path-to-at-keys` - Absolute path to the `.atKeys` of the sender
- `message` - Text data to send to receiver
- `atSign-of-sender` - The name of the atSign (without `@`) who is sending the data
- `atSign-of-receiver` - The name of the atSign (without `@`) who is receiving the data
#### E.g.
```sh 
RUST_LOG=info cargo run --example send_data_example ~/.atsign/keys/@aliens12_key.atKeys hello_there aliens12 virgogigantic64
```

### Fetch data
Fetch data from an atSign - `cargo run --example fetch_data_example <path-to-at-keys> <atSign-of-receiver> <atSign-of-sender>`
- `path-to-at-keys` - Absolute path to the `.atKeys` of the receiver
- `atSign-of-receiver` - The name of the atSign (without `@`) who is receiving the data
- `atSign-of-sender` - The name of the atSign (without `@`) who is sending the data
#### E.g.
```sh 
RUST_LOG=info cargo run --example fetch_data_example ~/.atsign/keys/@virgogigantic64_key.atKeys virgogigantic64 aliens12
```

## Structure
- `at_client` - What consumers of the library will mostly interact with
- `at_secrets` - Struct for constructing secrets from a file
- `at_chops` (Cryptographic and Hashing Operations (CHOPS))
    - `utils.rs` - Contains the generic, low level crypto operations
    - `at_chops.rs` - Contains the specific combination of crypto operations that the client and verbs can use
- `verbs` - Contains a trait that all verbs have to implement. Verbs execute the atProtocol verbs by taking in arguments from the client.

## Logging
This library uses the `log` crate. This means implementors of this library can use something like `env_logger` and get info from the library.

## Contributions welcome!

All of our software is open with intent. We welcome contributions - we want pull requests, and we want to hear about issues. See also [CONTRIBUTING.md](CONTRIBUTING.md).

## Steps to Beta
- [ ] Notifications using the `monitor` verb
- [ ] Interoperability with other SDKs

## Future goals
- [ ] `no_std` implementation
- [ ] Distribute to `crates.io`
- [ ] Support for `async` runtime
- [ ] Add default implementations for TLS connection on multiple platforms (ESP32, Linux, Pico W)
