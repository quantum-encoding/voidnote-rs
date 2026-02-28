# voidnote

Official Rust SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes and live encrypted streams.

**v0.3.0** · Rust 1.75+ · pure-Rust crypto, no OpenSSL · async + blocking API · zero-knowledge v1 API

## Install

```toml
[dependencies]
voidnote = "0.3"
```

Or with Cargo:

```sh
cargo add voidnote
```

---

## Quick start

```rust
use voidnote::{create, CreateOptions};

#[tokio::main]
async fn main() -> voidnote::Result<()> {
    // Create a note — content is encrypted locally, server never sees plaintext
    let result = create("my secret value", CreateOptions {
        api_key: "vn_...".into(),
        max_views: Some(1),   // destroy after this many reads (1–100)
        expires_in: Some(1),  // hours until expiry (1–720)
        ..Default::default()
    }).await?;

    println!("{}", result.url);    // https://voidnote.net/n/<tokenId>#<secret>
    println!("{}", result.expires_at);
    Ok(())
}
```

---

## API

### `async fn create(content, opts) → Result<CreateResult>`

Encrypt content locally and store the ciphertext. Requires an API key from your [dashboard](https://voidnote.net/dashboard).

```rust
use voidnote::{create, CreateOptions};

let result = create("deploy key: abc123", CreateOptions {
    api_key: "vn_...".into(),
    max_views: Some(3),
    expires_in: Some(6),  // 6 hours
    ..Default::default()
}).await?;

println!("{}", result.url);        // full shareable URL — includes #secret
println!("{}", result.expires_at);
```

### `async fn read(url_or_token) → Result<ReadResult>`

Fetch and decrypt a note. Consumes one view. Accepts both v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```rust
use voidnote::read;

let note = read("https://voidnote.net/n/<tokenId>#<secret>").await?;
println!("{}", note.content);
println!("destroyed: {}", note.destroyed);
```

### `async fn peek(url_or_token) → Result<PeekResult>`

Check metadata without consuming a view.

```rust
use voidnote::peek;

let meta = peek("https://voidnote.net/n/<tokenId>#<secret>").await?;
println!("exists: {}", meta.exists);
println!("views remaining: {}", meta.views_remaining);
println!("expires: {}", meta.expires_at);
```

### Void Streams

Live encrypted real-time channels. Messages are encrypted before leaving your machine.

```rust
use voidnote::{create_stream, StreamOptions};
use futures::StreamExt;

// Create a channel
let stream = create_stream(StreamOptions {
    api_key: "vn_...".into(),
    title: Some("Deploy log".into()),
    ..Default::default()
}).await?;

println!("share: {}", stream.url);

// Write messages
stream.write("Starting deployment...").await?;
stream.write("Build complete.").await?;
stream.close().await?;  // self-destructs all content

// Watch a stream — yields decrypted messages
let mut events = stream.watch();
while let Some(msg) = events.next().await {
    println!("{}", msg?);
}
```

---

## Blocking API

For synchronous contexts (scripts, CLI tools):

```rust
use voidnote::blocking;

let note = blocking::read("https://voidnote.net/n/<tokenId>#<secret>")?;
println!("{}", note.content);

let result = blocking::create("my secret", voidnote::CreateOptions {
    api_key: "vn_...".into(),
    ..Default::default()
})?;
println!("{}", result.url);
```

---

## Error handling

```rust
use voidnote::{Error, read};

match read(url).await {
    Ok(note) => println!("{}", note.content),
    Err(Error::NotFound) => eprintln!("note not found or already destroyed"),
    Err(Error::Unauthorized) => eprintln!("invalid API key"),
    Err(Error::DecryptionFailed) => eprintln!("bad token or tampered content"),
    Err(e) => eprintln!("error: {e}"),
}
```

| Variant | Meaning |
|---------|---------|
| `NotFound` | 404 — note gone or never existed |
| `Unauthorized` | 401 — invalid API key |
| `Api(String)` | Other HTTP error with message |
| `DecryptionFailed` | Ciphertext tampered or wrong key |
| `Network(reqwest::Error)` | HTTP transport error |
| `Json(serde_json::Error)` | Unexpected response format |
| `Hex(hex::FromHexError)` | Invalid token format |

---

## Security model

```
server generates  tokenId  (32-char hex — stored as lookup key)
client generates  secret   (32-char hex — NEVER sent to server)

key        = SHA-256(hex_decode(secret))
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

---

## License

MIT

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-rs)
