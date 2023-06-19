<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

# Rust SDK - (⚠️Alpha version⚠️)
This repo contains libraries, tools, samples and examples for developers who wish to work with the atPlatform from Rust code.

It currently has limited functionality with minimal tests.

## Run examples
### Send data
Send data to an AtSign
```sh 
RUST_LOG=info cargo run --example send_data_example ~/.atsign/keys/@aliens12_key.atKeys hello_there aliens12 virgogigantic64
```

### Fetch data
Fetch data from an AtSign
```sh 
RUST_LOG=info cargo run --example fetch_data_example ~/.atsign/keys/@virgogigantic64_key.atKeys virgogigantic64 aliens12
```

## Structure
- `at_client` - What consumers of the library will mostly interact with
- `at_secrets` - Struct for constructing secrets from a file
- `at_chops` (Cryptographic and Hashing Operations (CHOPS))
    - `utils.rs` - Contains the generic, low level crypto operations
    - `at_chops.rs` - Contains the specific combination of crypto operations that the client and verbs can use
- `verbs` - Contains a trait that all verbs have to implement. Verbs execute the at protocol verbs by taking in arguments from the client.

## Logging
This library uses the `log` crate. This means implementors of this library can use something like `env_logger` and get info from the library.

## Contributions welcome!

All of our software is open with intent. We welcome contributions - we want pull requests, and we want to hear about issues. See also [CONTRIBUTING.md](CONTRIBUTING.md).
