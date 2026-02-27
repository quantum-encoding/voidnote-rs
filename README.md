# voidnote — Official Rust SDK

Zero-knowledge self-destructing notes and live encrypted streams.
The key lives in the link. We never see it.

**https://voidnote.net**

---

## Install

```toml
[dependencies]
voidnote = "0.1"
```

Or with Cargo:

```sh
cargo add voidnote
```

---

## Quick start

### Read a note

```rust
use voidnote::read;

let note = read("https://voidnote.net/note/<token>").await?;
println!("{}", note.content);
println!("views: {}/{}", note.view_count, note.max_views);
println!("destroyed: {}", note.destroyed);
```

### Create a note

```rust
use voidnote::{create, CreateOptions};

let note = create(
    "launch codes: 4-8-15-16-23-42",
    CreateOptions {
        api_key: "vn_...".into(),
        max_views: Some(1),
        ..Default::default()
    },
)
.await?;

println!("share: {}", note.url);
println!("expires: {}", note.expires_at);
```

### Live encrypted stream

```rust
use voidnote::{create_stream, StreamOptions};
use futures::StreamExt;

let mut stream = create_stream(StreamOptions {
    api_key: "vn_...".into(),
    title: Some("Deploy log".into()),
    ..Default::default()
})
.await?;

println!("share: {}", stream.url);

stream.write("Starting deployment...").await?;
stream.write("Build complete.").await?;
stream.write("Service is live.").await?;
stream.close().await?;
```

### Watch a stream (SSE)

```rust
use futures::StreamExt;

let mut events = stream.watch();
while let Some(msg) = events.next().await {
    match msg {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("error: {e}"),
    }
}
```

---

## Blocking API

For use in synchronous contexts (scripts, CLI tools, non-async code):

```rust
use voidnote::blocking;

let note = blocking::read("https://voidnote.net/note/<token>")?;
println!("{}", note.content);

let created = blocking::create(
    "my secret",
    voidnote::CreateOptions {
        api_key: "vn_...".into(),
        ..Default::default()
    },
)?;
println!("{}", created.url);
```

---

## API reference

### `async fn read(url_or_token: &str) -> Result<ReadResult>`

Reads a note. Accepts either a full URL (`https://voidnote.net/note/<token>`) or a raw 64-character hex token.

**`ReadResult`**

| Field | Type | Description |
|-------|------|-------------|
| `content` | `String` | Decrypted plaintext |
| `title` | `Option<String>` | Note title if set |
| `view_count` | `u32` | How many times read |
| `max_views` | `u32` | Destruction threshold |
| `destroyed` | `bool` | Whether the note is gone |

---

### `async fn create(content: &str, opts: CreateOptions) -> Result<CreateResult>`

Creates a self-destructing encrypted note.

**`CreateOptions`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | `String` | required | Your VoidNote API key |
| `title` | `Option<String>` | `None` | Optional title (stored encrypted) |
| `max_views` | `Option<u32>` | `None` | Destroy after N reads |
| `ttl_minutes` | `Option<u32>` | `None` | Expire after N minutes |

**`CreateResult`**

| Field | Type | Description |
|-------|------|-------------|
| `url` | `String` | Shareable URL (contains key in fragment) |
| `expires_at` | `String` | ISO 8601 expiry timestamp |

---

### `async fn create_stream(opts: StreamOptions) -> Result<StreamHandle>`

Opens a live encrypted stream. Returns a handle for writing.

**`StreamOptions`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | `String` | required | Your VoidNote API key |
| `title` | `Option<String>` | `None` | Stream title |
| `max_views` | `Option<u32>` | `None` | Limit concurrent watchers |
| `ttl_minutes` | `Option<u32>` | `None` | Auto-close after N minutes |

**`StreamHandle`**

| Method | Description |
|--------|-------------|
| `.url` | Shareable URL for the stream |
| `async fn write(&mut self, msg: &str)` | Encrypt and send a message |
| `async fn close(&mut self)` | Close the stream |
| `fn watch(&self) -> impl Stream<Item = Result<String>>` | Subscribe to live messages (SSE) |

---

## Security model

VoidNote uses **zero-knowledge encryption** — the server never sees your plaintext.

1. A random 32-byte token is generated client-side
2. The first 16 bytes become the `tokenId` (sent to the server as a lookup key)
3. The last 16 bytes become the `secret` — used to derive an AES-256-GCM key via SHA-256
4. Content is encrypted locally before upload
5. The full 64-character hex token is embedded in the URL **fragment** (`#token`) — fragments are never sent to servers
6. Anyone with the link can decrypt; without the link, the server cannot

---

## Error handling

```rust
use voidnote::{Error, read};

match read(token).await {
    Ok(note) => println!("{}", note.content),
    Err(Error::NotFound) => eprintln!("note not found or already destroyed"),
    Err(Error::Unauthorized) => eprintln!("invalid API key"),
    Err(Error::DecryptionFailed) => eprintln!("bad token or tampered content"),
    Err(e) => eprintln!("error: {e}"),
}
```

**`Error` variants**

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

## Run the demo

```sh
git clone https://github.com/quantum-encoding/voidnote-rust
cd voidnote-rust

# Read a note
cargo run --example demo -- read <url-or-token>

# Create a note
cargo run --example demo -- create "my secret" vn_...

# Open a stream
cargo run --example demo -- stream vn_...
```

---

## License

MIT
