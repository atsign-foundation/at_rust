<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

# Rust SDK - (⚠️Alpha version⚠️)
This repo contains libraries, tools, samples and examples for developers who wish to work with the atPlatform from Rust code.

It currently has limited functionality with minimal tests.

## Run examples
### Send data
Send data to an AtSign
```sh 
cargo run --example send_data_example ~/.atsign/keys/@aliens12_key.atKeys hello_there aliens12 virgogigantic64
```

### Fetch data
Fetch data from an AtSign
```sh 
cargo run --example fetch_data_example ~/.atsign/keys/@virgogigantic64_key.atKeys virgogigantic64 aliens12
```

## Contributions welcome!

All of our software is open with intent. We welcome contributions - we want pull requests, and we want to hear about issues. See also [CONTRIBUTING.md](CONTRIBUTING.md).
