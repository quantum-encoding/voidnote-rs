//! # VoidNote — Official Rust SDK
//!
//! Zero-knowledge self-destructing notes and live encrypted streams.
//! The key lives in the link. We never see it.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use voidnote::{read, create, CreateOptions};
//!
//! #[tokio::main]
//! async fn main() -> voidnote::Result<()> {
//!     // Create a note
//!     let note = create("my secret message", CreateOptions {
//!         api_key: "vn_...".into(),
//!         max_views: Some(1),
//!         ..Default::default()
//!     }).await?;
//!     println!("share: {}", note.url);
//!
//!     // Read it back
//!     let result = read(&note.url).await?;
//!     println!("{}", result.content);
//!     Ok(())
//! }
//! ```

use std::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use futures_core::Stream;
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Re-export for convenience ─────────────────────────────────────────────────

pub use self::stream::StreamHandle;

const DEFAULT_BASE: &str = "https://voidnote.net";

// ── Error ─────────────────────────────────────────────────────────────────────

/// All errors this SDK can produce.
#[derive(Debug)]
pub enum Error {
    /// Token is not a valid 64-char hex string
    InvalidToken,
    /// An API key was required but not provided
    MissingApiKey,
    /// HTTP transport error (DNS, TLS, timeout)
    Network(reqwest::Error),
    /// Server returned a non-2xx status code
    Http { status: u16, body: String },
    /// Response JSON could not be parsed
    Json(serde_json::Error),
    /// AES-GCM authentication failed (wrong key or tampered data)
    DecryptionFailed,
    /// Hex string is invalid
    InvalidHex(hex::FromHexError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidToken => write!(f, "invalid token: expected 64-char hex string"),
            Error::MissingApiKey => write!(f, "api_key is required"),
            Error::Network(e) => write!(f, "network error: {e}"),
            Error::Http { status, body } => write!(f, "HTTP {status}: {body}"),
            Error::Json(e) => write!(f, "JSON parse error: {e}"),
            Error::DecryptionFailed => write!(f, "decryption failed: wrong key or tampered data"),
            Error::InvalidHex(e) => write!(f, "invalid hex: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Network(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidHex(e)
    }
}

/// SDK result type.
pub type Result<T> = std::result::Result<T, Error>;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Decrypted contents of a VoidNote.
#[derive(Debug, Clone)]
pub struct ReadResult {
    pub content: String,
    pub title: Option<String>,
    pub view_count: u32,
    pub max_views: u32,
    /// True if the note was destroyed after this read (view limit reached).
    pub destroyed: bool,
}

/// Options for creating a note.
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Required: vn_... API key from your dashboard
    pub api_key: String,
    pub title: Option<String>,
    /// 1–100; defaults to 1
    pub max_views: Option<u8>,
    /// Override the API base URL (default: https://voidnote.net)
    pub base: Option<String>,
}

/// Result of creating a note.
#[derive(Debug, Clone)]
pub struct CreateResult {
    /// Full shareable URL (contains the decryption key)
    pub url: String,
    pub expires_at: String,
}

/// Options for creating a Void Stream.
#[derive(Debug, Clone, Default)]
pub struct StreamOptions {
    /// Required: vn_... API key from your dashboard
    pub api_key: String,
    pub title: Option<String>,
    /// TTL in seconds: 3600 (1h), 21600 (6h), or 86400 (24h). Defaults to 3600.
    pub ttl: Option<u32>,
    /// Override the API base URL (default: https://voidnote.net)
    pub base: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read and decrypt a VoidNote.
///
/// `url_or_token` may be a full URL (`https://voidnote.net/note/<token>`)
/// or a raw 64-char hex token.
pub async fn read(url_or_token: &str) -> Result<ReadResult> {
    read_from(url_or_token, DEFAULT_BASE).await
}

/// Like [`read`] but allows overriding the API base URL.
pub async fn read_from(url_or_token: &str, base: &str) -> Result<ReadResult> {
    let token = extract_token(url_or_token)?;
    let token_id = &token[..32];
    let secret = &token[32..];

    let url = format!("{base}/api/note/{token_id}");
    let resp = reqwest::get(&url).await?;

    let status = resp.status().as_u16();
    let body = resp.text().await?;

    if status == 404 {
        return Err(Error::Http {
            status,
            body: "note not found or already destroyed".into(),
        });
    }
    if status != 200 {
        return Err(Error::Http { status, body });
    }

    // The API uses a mix of snake_case and camelCase; accept both.
    #[derive(Deserialize)]
    struct RawResponse {
        encrypted_content: Option<String>,
        iv: String,
        title: Option<String>,
        // Accept both naming conventions
        #[serde(alias = "viewCount", default)]
        view_count: u32,
        #[serde(alias = "maxViews", default)]
        max_views: u32,
        #[serde(default)]
        destroyed: bool,
    }

    let raw: RawResponse = serde_json::from_str(&body)?;
    let enc_hex = raw.encrypted_content.as_deref().unwrap_or_default();

    let content = decrypt_content(enc_hex, &raw.iv, secret)?;

    Ok(ReadResult {
        content,
        title: raw.title,
        view_count: raw.view_count,
        max_views: raw.max_views,
        destroyed: raw.destroyed,
    })
}

/// Create and encrypt a VoidNote client-side. Requires an API key.
/// The server never sees the plaintext.
pub async fn create(content: &str, opts: CreateOptions) -> Result<CreateResult> {
    if opts.api_key.is_empty() {
        return Err(Error::MissingApiKey);
    }
    let base = opts.base.as_deref().unwrap_or(DEFAULT_BASE);

    let (full_token, token_id, secret) = generate_token();
    let (enc_hex, iv_hex) = encrypt_content(content, &secret)?;

    let max_views = opts.max_views.unwrap_or(1);

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CreateBody<'a> {
        token_id: &'a str,
        encrypted_content: &'a str,
        iv: &'a str,
        max_views: u8,
        title: Option<&'a str>,
    }

    let payload = CreateBody {
        token_id: &token_id,
        encrypted_content: &enc_hex,
        iv: &iv_hex,
        max_views,
        title: opts.title.as_deref(),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/notes"))
        .bearer_auth(&opts.api_key)
        .json(&payload)
        .send()
        .await?;

    let status = resp.status().as_u16();
    let body = resp.text().await?;

    if status != 200 && status != 201 {
        return Err(Error::Http { status, body });
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct CreateResponse {
        #[serde(rename = "siteUrl")]
        site_url: Option<String>,
        #[serde(rename = "expiresAt", alias = "expires_at")]
        expires_at: Option<String>,
    }

    let raw: CreateResponse = serde_json::from_str(&body).unwrap_or_default();
    let site = raw.site_url.as_deref().unwrap_or(base);

    Ok(CreateResult {
        url: format!("{site}/note/{full_token}"),
        expires_at: raw.expires_at.unwrap_or_default(),
    })
}

/// Create a new Void Stream. Requires an API key. Costs 1 credit.
///
/// Returns a [`StreamHandle`] with `.write()`, `.close()`, and `.watch()`.
pub async fn create_stream(opts: StreamOptions) -> Result<StreamHandle> {
    if opts.api_key.is_empty() {
        return Err(Error::MissingApiKey);
    }
    let base = opts.base.unwrap_or_else(|| DEFAULT_BASE.into());
    let ttl = opts.ttl.unwrap_or(3600);

    let (full_token, token_id, secret) = generate_token();

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StreamBody<'a> {
        token_id: &'a str,
        title: Option<&'a str>,
        ttl: u32,
    }

    let payload = StreamBody {
        token_id: &token_id,
        title: opts.title.as_deref(),
        ttl,
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/api/stream"))
        .bearer_auth(&opts.api_key)
        .json(&payload)
        .send()
        .await?;

    let status = resp.status().as_u16();
    let body = resp.text().await?;

    if status != 200 && status != 201 {
        return Err(Error::Http { status, body });
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct StreamResponse {
        #[serde(rename = "siteUrl")]
        site_url: Option<String>,
        #[serde(rename = "expiresAt")]
        expires_at: Option<String>,
    }

    let raw: StreamResponse = serde_json::from_str(&body).unwrap_or_default();
    let site = raw.site_url.as_deref().unwrap_or(&base);

    // Derive key once; stored in handle for reuse across write/watch
    let key = derive_key_bytes(&secret)?;

    Ok(StreamHandle {
        url: format!("{site}/stream/{full_token}"),
        expires_at: raw.expires_at.unwrap_or_default(),
        full_token,
        secret,
        key,
        base,
        client: reqwest::Client::new(),
    })
}

// ── StreamHandle ──────────────────────────────────────────────────────────────

pub mod stream {
    use super::*;

    /// A live Void Stream handle. Write encrypted messages and close to self-destruct.
    pub struct StreamHandle {
        /// Shareable URL — share this with viewers (contains the decryption key)
        pub url: String,
        pub expires_at: String,
        pub(crate) full_token: String,
        pub(crate) secret: String,
        pub(crate) key: [u8; 32], // pre-derived AES key
        pub(crate) base: String,
        pub(crate) client: reqwest::Client,
    }

    impl StreamHandle {
        /// Encrypt `content` client-side and push it to the stream.
        pub async fn write(&self, content: &str) -> Result<()> {
            let (enc_hex, iv_hex) = encrypt_content(content, &self.secret)?;

            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct WriteBody<'a> {
                encrypted_content: &'a str,
                iv: &'a str,
            }

            let resp = self
                .client
                .post(format!(
                    "{}/api/stream/{}/write",
                    self.base, self.full_token
                ))
                .json(&WriteBody {
                    encrypted_content: &enc_hex,
                    iv: &iv_hex,
                })
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::Http { status, body });
            }
            Ok(())
        }

        /// Close the stream. Viewers receive a "closed" event and all content self-destructs.
        pub async fn close(&self) -> Result<()> {
            let resp = self
                .client
                .post(format!(
                    "{}/api/stream/{}/close",
                    self.base, self.full_token
                ))
                .json(&serde_json::json!({}))
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(Error::Http { status, body });
            }
            Ok(())
        }

        /// Watch the stream as an async [`Stream`] of decrypted messages.
        ///
        /// Automatically reconnects using SSE `Last-Event-ID` until the stream
        /// closes or expires.
        ///
        /// ```rust,ignore
        /// use futures::StreamExt;
        /// // stream is a StreamHandle from create_stream()
        /// let mut msgs = stream.watch();
        /// while let Some(Ok(msg)) = msgs.next().await {
        ///     println!("{msg}");
        /// }
        /// ```
        pub fn watch(&self) -> impl Stream<Item = Result<String>> + Send + 'static {
            let base = self.base.clone();
            let full_token = self.full_token.clone();
            let key = self.key;
            let client = self.client.clone();

            async_stream::stream! {
                let mut last_id: Option<String> = None;

                'outer: loop {
                    let mut req = client
                        .get(format!("{base}/api/stream/{full_token}/events"));

                    if let Some(ref id) = last_id {
                        req = req.header("Last-Event-ID", id);
                    }

                    let resp = match req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            yield Err(Error::Network(e));
                            return;
                        }
                    };

                    if !resp.status().is_success() {
                        yield Err(Error::Http {
                            status: resp.status().as_u16(),
                            body: resp.text().await.unwrap_or_default(),
                        });
                        return;
                    }

                    use futures::StreamExt as _;
                    let mut byte_stream = resp.bytes_stream();

                    let mut buf = String::new();
                    let mut event_id = String::new();
                    let mut event_data = String::new();

                    while let Some(chunk) = byte_stream.next().await {
                        let chunk = match chunk {
                            Ok(c) => c,
                            Err(_) => break, // reconnect
                        };

                        let text = match std::str::from_utf8(&chunk) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                        buf.push_str(text);

                        // Process complete lines
                        while let Some(nl_pos) = buf.find('\n') {
                            let raw_line = &buf[..nl_pos];
                            let line = raw_line.trim_end_matches('\r');
                            let owned_line = line.to_owned();
                            buf.drain(..nl_pos + 1);

                            if let Some(id) = owned_line.strip_prefix("id: ") {
                                event_id = id.to_owned();
                            } else if let Some(data) = owned_line.strip_prefix("data: ") {
                                event_data = data.to_owned();
                            } else if owned_line.is_empty() && !event_data.is_empty() {
                                // End of SSE event — process it
                                if !event_id.is_empty() {
                                    last_id = Some(event_id.clone());
                                    event_id.clear();
                                }

                                let data = event_data.clone();
                                event_data.clear();

                                #[derive(Deserialize)]
                                struct SseEvent {
                                    #[serde(rename = "type")]
                                    event_type: Option<String>,
                                    enc: Option<String>,
                                    iv: Option<String>,
                                }

                                let evt: SseEvent = match serde_json::from_str(&data) {
                                    Ok(e) => e,
                                    Err(_) => continue,
                                };

                                if let Some(ref t) = evt.event_type {
                                    if t == "closed" || t == "expired" {
                                        return; // stream ended
                                    }
                                }

                                if let (Some(enc_hex), Some(iv_hex)) = (evt.enc, evt.iv) {
                                    match decrypt_with_key(&enc_hex, &iv_hex, &key) {
                                        Ok(plaintext) => yield Ok(plaintext),
                                        Err(_) => continue, // tampered / wrong key — skip
                                    }
                                }
                            }
                        }
                    }
                    // Connection dropped — reconnect (continue outer loop)
                    continue 'outer;
                }
            }
        }
    }

    impl fmt::Debug for StreamHandle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("StreamHandle")
                .field("url", &self.url)
                .field("expires_at", &self.expires_at)
                .finish()
        }
    }
}

// ── Blocking wrappers ─────────────────────────────────────────────────────────

/// Synchronous wrapper around the async API.
/// Requires a Tokio runtime to be available (or use [`tokio::runtime::Runtime`]).
pub mod blocking {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().expect("failed to create tokio runtime")
    }

    /// Blocking version of [`read`].
    pub fn read(url_or_token: &str) -> Result<ReadResult> {
        rt().block_on(super::read(url_or_token))
    }

    /// Blocking version of [`create`].
    pub fn create(content: &str, opts: CreateOptions) -> Result<CreateResult> {
        rt().block_on(super::create(content, opts))
    }

    /// Blocking version of [`create_stream`].
    pub fn create_stream(opts: StreamOptions) -> Result<StreamHandle> {
        rt().block_on(super::create_stream(opts))
    }
}

// ── Internal: crypto ──────────────────────────────────────────────────────────

/// Generate a 32-byte random token, returning (full_token_hex, token_id, secret).
fn generate_token() -> (String, String, String) {
    use aes_gcm::aead::rand_core::RngCore;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let full = hex_encode(raw);
    let token_id = full[..32].to_owned();
    let secret = full[32..].to_owned();
    (full, token_id, secret)
}

/// Derive a 32-byte AES key: key = SHA-256(hex_decode(secret))
fn derive_key_bytes(secret_hex: &str) -> Result<[u8; 32]> {
    let secret_bytes = hex_decode(secret_hex)?;
    let hash = Sha256::digest(&secret_bytes);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

/// AES-256-GCM encrypt. Returns (ciphertext_hex, iv_hex).
/// Output ciphertext is ciphertext || 16-byte tag (Go SDK compatible).
fn encrypt_content(plaintext: &str, secret_hex: &str) -> Result<(String, String)> {
    use aes_gcm::aead::rand_core::RngCore;

    let key_bytes = derive_key_bytes(secret_hex)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    // aes-gcm Seal returns ciphertext || tag automatically
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| Error::DecryptionFailed)?;

    Ok((hex_encode(&ciphertext), hex_encode(iv_bytes)))
}

/// AES-256-GCM decrypt. Expects ciphertext || tag (16 bytes).
fn decrypt_content(enc_hex: &str, iv_hex: &str, secret_hex: &str) -> Result<String> {
    let key_bytes = derive_key_bytes(secret_hex)?;
    decrypt_with_key(enc_hex, iv_hex, &key_bytes)
}

/// Decrypt using a pre-derived 32-byte key (avoids SHA-256 per call in watch loop).
fn decrypt_with_key(enc_hex: &str, iv_hex: &str, key: &[u8; 32]) -> Result<String> {
    let ct_with_tag = hex_decode(enc_hex)?;
    let iv_bytes = hex_decode(iv_hex)?;

    if iv_bytes.len() != 12 {
        return Err(Error::DecryptionFailed);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&iv_bytes);

    let plaintext = cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| Error::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
}

/// Extract the 64-char hex token from a URL or return the raw string.
fn extract_token(url_or_token: &str) -> Result<String> {
    let s = if url_or_token.starts_with("http") {
        url_or_token
            .trim_end_matches('/')
            .split('/')
            .last()
            .unwrap_or("")
    } else {
        url_or_token
    };

    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidToken);
    }
    Ok(s.to_lowercase())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (_, _, secret) = generate_token();
        let plaintext = "Hello, VoidNote!";
        let (enc, iv) = encrypt_content(plaintext, &secret).unwrap();
        let decrypted = decrypt_content(&enc, &iv, &secret).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_token_generation_format() {
        let (full, id, secret) = generate_token();
        assert_eq!(full.len(), 64);
        assert_eq!(id.len(), 32);
        assert_eq!(secret.len(), 32);
        assert_eq!(&full[..32], id);
        assert_eq!(&full[32..], secret);
        assert!(full.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_extract_token_from_url() {
        let token = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let url = format!("https://voidnote.net/note/{token}");
        let extracted = extract_token(&url).unwrap();
        assert_eq!(token, extracted);
    }

    #[test]
    fn test_extract_token_raw() {
        let token = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let extracted = extract_token(token).unwrap();
        assert_eq!(token, extracted);
    }

    #[test]
    fn test_extract_token_invalid() {
        assert!(extract_token("tooshort").is_err());
        assert!(extract_token("zz000000000000000000000000000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let secret = "aabbccddeeff00112233445566778899";
        let k1 = derive_key_bytes(secret).unwrap();
        let k2 = derive_key_bytes(secret).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_decryption_wrong_key_fails() {
        let (_, _, secret) = generate_token();
        let (_, _, wrong_secret) = generate_token();
        let (enc, iv) = encrypt_content("secret", &secret).unwrap();
        assert!(decrypt_content(&enc, &iv, &wrong_secret).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (_, _, secret) = generate_token();
        let (mut enc, iv) = encrypt_content("secret", &secret).unwrap();
        // Flip a byte in the ciphertext hex
        let last = enc.len() - 1;
        enc.replace_range(last.., if enc.ends_with('f') { "0" } else { "f" });
        assert!(decrypt_content(&enc, &iv, &secret).is_err());
    }
}
