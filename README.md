# birdc

[![Current Crates.io Version](https://img.shields.io/crates/v/birdc.svg)](https://crates.io/crates/birdc)

![Build](https://github.com/amodm/birdc-rs/workflows/Main/badge.svg?branch=main)

Rust library to talk to the [Bird BGP server](https://bird.network.cz/) for administrative
and instrumentation purposes.

## Documentation

- [API Reference](https://docs.rs/birdc)

## Examples

```rust
use birdc::*;

// create the client
let client = Client::for_unix_socket("/run/bird/bird.ctl");

// we can either use raw protocol
async fn show_interfaces_raw(client: &Client) -> Result<()> {
    let mut connection = client.connect().await?;

    // we can either use raw protocol
    let messages = connection.send_request("show interfaces").await?;
    for message in &messages {
        println!("received message: {:?}", message);
    }
    Ok(())
}

// or we can use structured exchange
async fn show_interfaces(client: &Client) -> Result<()> {
    let mut connection = client.connect().await?;

    // let's make a semantic call now
    match connection.show_interfaces().await {
        Ok(entries) => {
            for e in &entries {
                println!("received entry: {:?}", e);
            }
        }
        Err(Error::ParseError(messages)) => {
            // we can still go through the raw response
            // even though semantic parsing failed
            for msg in &messages {
                println!("raw message: {:?}", msg);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(())
}
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
