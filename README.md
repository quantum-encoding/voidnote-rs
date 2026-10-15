# voidnote

Official Rust SDK for [VoidNote](https://voidnote.net): zero-knowledge self-destructing notes and live encrypted streams.

**v0.4.0** · Rust 1.75+ · pure-Rust crypto, no OpenSSL · async + blocking API · no account needed for notes

## Install

```toml
[dependencies]
voidnote = "0.4"
```

Or with Cargo:

```sh
cargo add voidnote
```

---

## Quick start

```rust
use voidnote::{create, read, CreateOptions};

#[tokio::main]
async fn main() -> voidnote::Result<()> {
    // No account or API key needed. Content is encrypted locally; the server never sees it.
    let note = create("my secret value", CreateOptions::default()).await?;
    println!("{}", note.url);    // https://voidnote.net/n/<tokenId>#<secret>

    println!("{}", read(&note.url).await?.content);
    Ok(())
}
```

---

## API

### `async fn create(content, opts) → Result<CreateResult>`

Encrypt content locally and store the ciphertext. `expires_in` is in hours.

```rust
use voidnote::{create, CreateOptions};

let result = create("deploy key: abc123", CreateOptions {
    max_views: Some(3),   // default 1
    expires_in: Some(6),  // hours, default 1
    ..Default::default()
}).await?;

println!("{}", result.url);        // full shareable URL, includes #secret
println!("{} {} {}", result.token, result.expires_at, result.kdf);
```

Without an `api_key` the note is anonymous: up to 168 hours (7 days) and 10 views, rate-limited per IP. An API key from a free account raises that to 720 hours and 100 views:

```rust
create("deploy key: abc123", CreateOptions {
    api_key: Some("vn_...".into()),
    max_views: Some(50),
    expires_in: Some(720),
    ..Default::default()
}).await?;
```

Add a `password` and the reader needs it as well as the link. The key is then PBKDF2-HMAC-SHA256 (600,000 iterations) of the password, salted with the link's secret:

```rust
let guarded = create("db password: hunter2", CreateOptions {
    password: Some("correct horse".into()),
    ..Default::default()
}).await?;
// share guarded.url and the password through different channels
```

In an unoptimised (debug) build those 600,000 iterations take several seconds. If that matters during development, optimise this crate and `sha2` in your `Cargo.toml`:

```toml
[profile.dev.package.voidnote]
opt-level = 3

[profile.dev.package.sha2]
opt-level = 3
```

### `async fn read(url) / read_with(url, ReadOptions) → Result<ReadResult>`

Fetch and decrypt a note. Consumes one view. Accepts v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```rust
use voidnote::{read, read_with, ReadOptions};

let note = read("https://voidnote.net/n/<tokenId>#<secret>").await?;
println!("{}", note.content);
println!("views {}/{}, destroyed: {}", note.view_count, note.max_views, note.destroyed);

// A note created with a password
let guarded = read_with(url, ReadOptions {
    password: Some("correct horse".into()),
    ..Default::default()
}).await?;
```

Before using a view, `read` checks the note's metadata. A missing note (`Error::NotFound`), a password note read without a password (`Error::PasswordRequired`) or an unknown key derivation (`Error::UnsupportedKdf`) returns without touching the view. A wrong password (`Error::DecryptionFailed`) can only be detected after decrypting, so it does use the view.

### `async fn peek(url, base) → Result<PeekResult>`

Check metadata without consuming a view. `kdf` is `voidnote::KDF_PBKDF2` when the note needs a password.

```rust
use voidnote::peek;

let meta = peek("https://voidnote.net/n/<tokenId>#<secret>", None).await?;
println!("exists: {}", meta.exists);
println!("views remaining: {}", meta.views_remaining);
println!("expires: {} kdf: {}", meta.expires_at, meta.kdf);
```

### Void Streams

Live encrypted real-time channels. Creating one needs an API key from a free account.

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

// Watch a stream: yields decrypted messages
let mut events = stream.watch();
while let Some(msg) = events.next().await {
    println!("{}", msg?);
}
```

---

## Blocking API

For synchronous contexts (scripts, CLI tools). Each call starts its own Tokio runtime, so don't call these from inside one.

```rust
use voidnote::blocking;

let note = blocking::read("https://voidnote.net/n/<tokenId>#<secret>")?;
println!("{}", note.content);

let result = blocking::create("my secret", voidnote::CreateOptions::default())?;
println!("{}", result.url);
```

---

## Error handling

```rust
use voidnote::{Error, read};

match read(url).await {
    Ok(note) => println!("{}", note.content),
    Err(Error::NotFound) => eprintln!("note not found or already destroyed"),
    Err(Error::PasswordRequired) => eprintln!("this note needs a password (no view was used)"),
    Err(Error::Http { status: 429, message, retry_after }) => {
        eprintln!("rate limited: {message}, retry after {retry_after:?}s")
    }
    Err(e) => eprintln!("error: {e}"),
}
```

| Variant | Meaning |
|---------|---------|
| `NotFound` | note gone, expired or never existed |
| `PasswordRequired` | note needs a password; no view was used |
| `UnsupportedKdf(String)` | note uses a key derivation this version can't do; no view was used |
| `DecryptionFailed` | wrong password, wrong key or tampered content |
| `Http { status, message, retry_after }` | server refused, with its message (`retry_after` on 429) |
| `EmptyPassword` | `create` was given `Some("")` as the password |
| `MissingApiKey` | `create_stream` without an API key |
| `Network(reqwest::Error)` | HTTP transport error |
| `Json(serde_json::Error)` | unexpected response format |
| `InvalidToken` / `InvalidHex(hex::FromHexError)` | malformed URL or token |

---

## Security model

```
server generates  tokenId  (32-char hex, stored as lookup key)
client generates  secret   (32-char hex, NEVER sent to server)

key        = SHA-256(hex_decode(secret))                                  kdf "sha256"
key        = PBKDF2-HMAC-SHA256(password, hex_decode(secret), 600000)     kdf "pbkdf2-sha256-600k"
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

---

## Tests

```sh
cargo test                                      # mocked network
cargo test --test live -- --ignored --nocapture # creates real anonymous notes on voidnote.net
```

## License

MIT

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-rs)
