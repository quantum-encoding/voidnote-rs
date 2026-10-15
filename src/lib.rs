//! # VoidNote — Official Rust SDK
//!
//! Zero-knowledge self-destructing notes and live encrypted streams.
//! The key lives in the link. We never see it.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use voidnote::{read, read_with, create, CreateOptions, ReadOptions};
//!
//! #[tokio::main]
//! async fn main() -> voidnote::Result<()> {
//!     // Create a note — no account or API key needed
//!     let note = create("my secret message", CreateOptions::default()).await?;
//!     println!("share: {}", note.url);
//!
//!     // Read it back
//!     let result = read(&note.url).await?;
//!     println!("{}", result.content);
//!
//!     // A note that also needs a password
//!     let guarded = create("launch codes", CreateOptions {
//!         password: Some("correct horse".into()),
//!         ..Default::default()
//!     }).await?;
//!     let opened = read_with(&guarded.url, ReadOptions {
//!         password: Some("correct horse".into()),
//!         ..Default::default()
//!     }).await?;
//!     println!("{}", opened.content);
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

/// Note key derivation: key = SHA-256(secret bytes).
pub const KDF_SHA256: &str = "sha256";
/// Note key derivation: key = PBKDF2-HMAC-SHA256(password UTF-8, salt = secret bytes, 600000 iterations).
pub const KDF_PBKDF2: &str = "pbkdf2-sha256-600k";
/// PBKDF2 iteration count for [`KDF_PBKDF2`].
pub const PBKDF2_ITERATIONS: u32 = 600_000;

// ── Error ─────────────────────────────────────────────────────────────────────

/// All errors this SDK can produce.
#[derive(Debug)]
pub enum Error {
    /// Token is not a valid 64-char hex string
    InvalidToken,
    /// An API key was required but not provided
    MissingApiKey,
    /// The note does not exist, expired, or its views are used up
    NotFound,
    /// The note was created with a password and none was given. No view was used.
    PasswordRequired,
    /// The note uses a key derivation this SDK version cannot do. No view was used.
    UnsupportedKdf(String),
    /// An empty password was given to [`create`]
    EmptyPassword,
    /// HTTP transport error (DNS, TLS, timeout)
    Network(reqwest::Error),
    /// Server returned a non-2xx status code with its error message
    Http {
        status: u16,
        message: String,
        /// Seconds the server asked to wait (Retry-After), when it sent one
        retry_after: Option<u64>,
    },
    /// Response JSON could not be parsed
    Json(serde_json::Error),
    /// AES-GCM authentication failed: wrong password, wrong key or tampered data.
    /// For a note read with [`read_with`], the view was used.
    DecryptionFailed,
    /// Hex string is invalid
    InvalidHex(hex::FromHexError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidToken => write!(f, "invalid token: expected 64-char hex string"),
            Error::MissingApiKey => write!(f, "api_key is required"),
            Error::NotFound => write!(f, "note not found, expired or already destroyed"),
            Error::PasswordRequired => {
                write!(f, "this note needs a password — use read_with (no view was used)")
            }
            Error::UnsupportedKdf(kdf) => write!(
                f,
                "this note uses key derivation \"{kdf}\", which this SDK version cannot decrypt — upgrade voidnote"
            ),
            Error::EmptyPassword => write!(f, "password must not be empty"),
            Error::Network(e) => write!(f, "network error: {e}"),
            Error::Http { status, message, retry_after } => {
                write!(f, "HTTP {status}: {message}")?;
                if let Some(secs) = retry_after {
                    write!(f, " (retry after {secs}s)")?;
                }
                Ok(())
            }
            Error::Json(e) => write!(f, "JSON parse error: {e}"),
            Error::DecryptionFailed => {
                write!(f, "decryption failed: wrong password, wrong key or tampered data")
            }
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

/// Retry-After as seconds (delta-seconds form; the server sends no HTTP dates).
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// [`Error::Http`] from a status, Retry-After and body; the message is the body's
/// `error` field when it is JSON, else the body text.
fn http_error(status: u16, retry_after: Option<u64>, body: &str) -> Error {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let message = serde_json::from_str::<ErrorBody>(body)
        .map(|b| b.error)
        .unwrap_or_else(|_| body.trim().chars().take(300).collect());
    Error::Http { status, message, retry_after }
}

/// Body text of a 2xx response; any other status becomes [`Error::Http`].
async fn success_text(resp: reqwest::Response) -> Result<String> {
    let status = resp.status().as_u16();
    let wait = retry_after(resp.headers());
    let body = resp.text().await?;
    if !(200..300).contains(&status) {
        return Err(http_error(status, wait, &body));
    }
    Ok(body)
}

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
    /// Key derivation of a v1 note ([`KDF_SHA256`] or [`KDF_PBKDF2`]); empty for legacy notes.
    pub kdf: String,
}

/// Options for creating a note.
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Optional vn_... API key from a free account. `None` creates an anonymous note.
    pub api_key: Option<String>,
    /// Optional password the reader must also supply ([`KDF_PBKDF2`]).
    pub password: Option<String>,
    /// Views before the note is destroyed; defaults to 1. Up to 10 anonymous, 100 with an API key.
    pub max_views: Option<u8>,
    /// Hours until expiry; defaults to 1. Up to 168 anonymous, 720 with an API key.
    pub expires_in: Option<u16>,
    /// Override the API base URL (default: https://voidnote.net)
    pub base: Option<String>,
}

/// Result of creating a note.
#[derive(Debug, Clone)]
pub struct CreateResult {
    /// Full shareable URL (contains the decryption key)
    pub url: String,
    /// 32-char tokenId
    pub token: String,
    pub expires_at: String,
    pub view_limit: u32,
    pub kdf: String,
}

/// Options for [`read_with`].
#[derive(Debug, Clone, Default)]
pub struct ReadOptions {
    /// The sender's password, for notes created with one. Ignored for notes without one.
    pub password: Option<String>,
    /// Override the API base URL (default: https://voidnote.net)
    pub base: Option<String>,
}

/// Options for creating a Void Stream.
#[derive(Debug, Clone, Default)]
pub struct StreamOptions {
    /// Required: vn_... API key from a free account
    pub api_key: String,
    pub title: Option<String>,
    /// TTL in seconds: 3600 (1h), 21600 (6h), or 86400 (24h). Defaults to 3600.
    pub ttl: Option<u32>,
    /// Override the API base URL (default: https://voidnote.net)
    pub base: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read and decrypt a VoidNote. Consumes one view.
///
/// `url_or_token` may be a v1 URL (`https://voidnote.net/n/<tokenId>#<secret>`),
/// a legacy URL (`https://voidnote.net/note/<token>`) or a raw 64-char hex token.
/// Notes created with a password need [`read_with`].
pub async fn read(url_or_token: &str) -> Result<ReadResult> {
    read_with(url_or_token, ReadOptions::default()).await
}

/// Like [`read`] but allows overriding the API base URL.
pub async fn read_from(url_or_token: &str, base: &str) -> Result<ReadResult> {
    read_with(url_or_token, ReadOptions { password: None, base: Some(base.into()) }).await
}

/// Like [`read`], with a password for notes created with one.
///
/// v1 notes are checked first without using a view: a missing note returns
/// [`Error::NotFound`], a note that needs a password when none was given returns
/// [`Error::PasswordRequired`], and an unknown key derivation returns
/// [`Error::UnsupportedKdf`], all with the view unused. A wrong password
/// ([`Error::DecryptionFailed`]) is only detectable after the view is used.
pub async fn read_with(url_or_token: &str, opts: ReadOptions) -> Result<ReadResult> {
    let base = opts.base.as_deref().unwrap_or(DEFAULT_BASE);
    match parse_note_url(url_or_token)? {
        ParsedUrl::V1 { token_id, secret } => {
            read_v1(&token_id, &secret, base, opts.password.as_deref()).await
        }
        ParsedUrl::Legacy { full_token } => read_legacy(&full_token, base).await,
    }
}

enum ParsedUrl {
    V1 { token_id: String, secret: String },
    Legacy { full_token: String },
}

fn parse_note_url(input: &str) -> Result<ParsedUrl> {
    // v1 format: .../n/{32-hex}#{32-hex}
    if let Some(hash_pos) = input.find('#') {
        let secret = &input[hash_pos + 1..];
        let before = input[..hash_pos].trim_end_matches('/');
        let token_id = before.rsplit('/').next().unwrap_or("");
        if token_id.len() == 32 && secret.len() == 32
            && token_id.chars().all(|c| c.is_ascii_hexdigit())
            && secret.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Ok(ParsedUrl::V1 {
                token_id: token_id.to_lowercase(),
                secret: secret.to_lowercase(),
            });
        }
    }
    // Legacy: 64-char hex token in path or raw
    let token = extract_token(input)?;
    Ok(ParsedUrl::Legacy { full_token: token })
}

/// Maps an absent kdf to [`KDF_SHA256`] and rejects ones this SDK cannot derive.
fn check_kdf(kdf: &str) -> Result<&'static str> {
    match kdf {
        "" | KDF_SHA256 => Ok(KDF_SHA256),
        KDF_PBKDF2 => Ok(KDF_PBKDF2),
        other => Err(Error::UnsupportedKdf(other.to_owned())),
    }
}

/// Fetch encrypted blob via v1 API and decrypt client-side (true zero-knowledge).
async fn read_v1(token_id: &str, secret: &str, base: &str, password: Option<&str>) -> Result<ReadResult> {
    // Metadata costs no view: it gives the view limit (the consume response only
    // reports how many views remain) and the kdf, checked before the view is used.
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct MetaResponse {
        exists: bool,
        #[serde(rename = "viewLimit")]
        view_limit: u32,
        kdf: String,
    }
    let meta_body = success_text(reqwest::get(format!("{base}/api/v1/note/{token_id}/meta/")).await?).await?;
    let meta: MetaResponse = serde_json::from_str(&meta_body)?;
    if !meta.exists {
        return Err(Error::NotFound);
    }
    let meta_kdf = check_kdf(&meta.kdf)?;
    let password = password.filter(|p| !p.is_empty());
    if meta_kdf != KDF_SHA256 && password.is_none() {
        return Err(Error::PasswordRequired);
    }

    #[derive(Deserialize)]
    struct ConsumeResponse {
        encrypted: String,
        iv: String,
        #[serde(rename = "viewsRemaining", default)]
        views_remaining: u32,
        #[serde(default)]
        destroyed: bool,
        #[serde(default)]
        kdf: String,
    }

    let body = success_text(reqwest::get(format!("{base}/api/v1/note/{token_id}/consume/")).await?).await?;
    let raw: ConsumeResponse = serde_json::from_str(&body)?;
    let kdf = if raw.kdf.is_empty() { meta_kdf } else { check_kdf(&raw.kdf)? };
    let key = derive_note_key(secret, kdf, password)?;
    let content = decrypt_with_key(&raw.encrypted, &raw.iv, &key)?;

    Ok(ReadResult {
        content,
        title: None,
        view_count: meta.view_limit.saturating_sub(raw.views_remaining),
        max_views: meta.view_limit,
        destroyed: raw.destroyed,
        kdf: kdf.to_owned(),
    })
}

/// Fetch and decrypt via legacy server-decrypt endpoint (backward compat).
async fn read_legacy(full_token: &str, base: &str) -> Result<ReadResult> {
    let body = success_text(reqwest::get(format!("{base}/api/note/{full_token}/")).await?).await?;

    #[derive(Deserialize)]
    struct LegacyResponse {
        content: String,
        title: Option<String>,
        #[serde(alias = "viewCount", default)]
        view_count: u32,
        #[serde(alias = "maxViews", default)]
        max_views: u32,
        #[serde(default)]
        destroyed: bool,
    }

    let raw: LegacyResponse = serde_json::from_str(&body)?;
    Ok(ReadResult {
        content: raw.content,
        title: raw.title,
        view_count: raw.view_count,
        max_views: raw.max_views,
        destroyed: raw.destroyed,
        kdf: String::new(),
    })
}

/// Create and encrypt a VoidNote client-side using the v1 API.
/// The server generates the tokenId; the client holds the secret in the URL fragment.
/// The server never sees the plaintext or the secret.
/// Returns a URL in the form https://voidnote.net/n/{tokenId}#{secret}.
///
/// No API key is needed: without one the note is anonymous, held to 168 hours and
/// 10 views, and rate-limited per IP. With a password the key is derived with
/// PBKDF2 and the reader needs both the link and the password. Server refusals
/// come back as [`Error::Http`] with the server's message and Retry-After.
pub async fn create(content: &str, opts: CreateOptions) -> Result<CreateResult> {
    let base = opts.base.as_deref().unwrap_or(DEFAULT_BASE);
    let password = match opts.password.as_deref() {
        Some("") => return Err(Error::EmptyPassword),
        p => p,
    };
    let kdf = if password.is_some() { KDF_PBKDF2 } else { KDF_SHA256 };

    // Generate only the secret (16 bytes) — server generates tokenId
    let secret = generate_secret();
    let key = derive_note_key(&secret, kdf, password)?;
    let (enc_hex, iv_hex) = encrypt_with_key(content, &key)?;

    let max_views = opts.max_views.unwrap_or(1);
    let expires_in_secs = opts.expires_in.unwrap_or(1) as u32 * 3600; // hours → seconds

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CreateBody<'a> {
        encrypted: &'a str,
        iv: &'a str,
        expires_in: u32,
        view_limit: u8,
        kdf: &'a str,
    }

    let payload = CreateBody {
        encrypted: &enc_hex,
        iv: &iv_hex,
        expires_in: expires_in_secs,
        view_limit: max_views,
        kdf,
    };

    let client = reqwest::Client::new();
    let mut req = client.post(format!("{base}/api/v1/note/")).json(&payload);
    if let Some(api_key) = opts.api_key.as_deref().filter(|k| !k.is_empty()) {
        req = req.bearer_auth(api_key);
    }
    let body = success_text(req.send().await?).await?;

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct CreateResponse {
        token: Option<String>,
        url: Option<String>,
        #[serde(rename = "expiresAt")]
        expires_at: Option<String>,
        #[serde(rename = "viewLimit")]
        view_limit: Option<u32>,
        kdf: Option<String>,
    }

    let raw: CreateResponse = serde_json::from_str(&body).unwrap_or_default();
    let token = raw.token.unwrap_or_default();
    let base_url = raw.url.unwrap_or_else(|| format!("{base}/n/{token}"));

    Ok(CreateResult {
        // Append #secret — this is the only place the secret and URL are combined
        url: format!("{base_url}#{secret}"),
        token,
        expires_at: raw.expires_at.unwrap_or_default(),
        view_limit: raw.view_limit.unwrap_or(max_views as u32),
        kdf: raw.kdf.unwrap_or_else(|| kdf.to_owned()),
    })
}

/// Peek at note metadata without consuming a view. [`PeekResult::kdf`] is
/// [`KDF_PBKDF2`] when the note needs a password.
/// Accepts v1 URLs (https://voidnote.net/n/{tokenId}#{secret}) or raw 32-char tokenIds.
pub async fn peek(url_or_token: &str, base: Option<&str>) -> Result<PeekResult> {
    let api_base = base.unwrap_or(DEFAULT_BASE);

    // Extract tokenId: strip fragment, get last path segment
    let without_fragment = url_or_token.split('#').next().unwrap_or(url_or_token);
    let last_seg = without_fragment.trim_end_matches('/').rsplit('/').next().unwrap_or(without_fragment);
    let token_id = if last_seg.len() == 64 && last_seg.chars().all(|c| c.is_ascii_hexdigit()) {
        &last_seg[..32] // legacy: take first half
    } else {
        last_seg
    };

    let body = success_text(reqwest::get(format!("{api_base}/api/v1/note/{token_id}/meta/")).await?).await?;
    let raw: PeekResult = serde_json::from_str(&body)?;
    Ok(raw)
}

/// Metadata about a note (from the /meta endpoint).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PeekResult {
    pub exists: bool,
    #[serde(rename = "type", default)]
    pub note_type: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: String,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: String,
    #[serde(rename = "viewLimit", default)]
    pub view_limit: u32,
    #[serde(rename = "viewsRemaining", default)]
    pub views_remaining: u32,
    /// [`KDF_SHA256`] or [`KDF_PBKDF2`]; empty when the note does not exist.
    #[serde(default)]
    pub kdf: String,
}

/// Create a new Void Stream. Requires an API key from a free account.
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
        .post(format!("{base}/api/stream/"))
        .bearer_auth(&opts.api_key)
        .json(&payload)
        .send()
        .await?;

    let body = success_text(resp).await?;

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
        api_key: opts.api_key,
        client: reqwest::Client::new(),
    })
}

/// Join a stream and return its short-lived SSE access token (`?at=`).
async fn join_stream(
    client: &reqwest::Client,
    base: &str,
    full_token: &str,
    password: Option<&str>,
) -> Result<String> {
    let body = match password {
        Some(p) => serde_json::json!({ "password": p }),
        None => serde_json::json!({}),
    };
    let resp = client
        .post(format!("{base}/api/stream/{full_token}/join/"))
        .json(&body)
        .send()
        .await?;
    let text = success_text(resp).await?;

    #[derive(Deserialize)]
    struct JoinResponse {
        #[serde(rename = "accessToken")]
        access_token: String,
    }
    let parsed: JoinResponse = serde_json::from_str(&text)?;
    Ok(parsed.access_token)
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
        pub(crate) api_key: String, // the creator's key — broadcast write/close require it
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
                    "{}/api/stream/{}/write/",
                    self.base, self.full_token
                ))
                .bearer_auth(&self.api_key)
                .json(&WriteBody {
                    encrypted_content: &enc_hex,
                    iv: &iv_hex,
                })
                .send()
                .await?;

            success_text(resp).await?;
            Ok(())
        }

        /// Close the stream. Viewers receive a "closed" event and all content self-destructs.
        pub async fn close(&self) -> Result<()> {
            let resp = self
                .client
                .post(format!(
                    "{}/api/stream/{}/close/",
                    self.base, self.full_token
                ))
                .bearer_auth(&self.api_key)
                .json(&serde_json::json!({}))
                .send()
                .await?;

            success_text(resp).await?;
            Ok(())
        }

        /// Watch the stream as an async [`Stream`] of decrypted messages.
        ///
        /// Joins the stream for a short-lived access token, then reconnects using
        /// SSE `Last-Event-ID` (re-joining when the token expires) until the stream
        /// closes or expires. Use [`watch_with_password`](Self::watch_with_password)
        /// for password-protected streams.
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
            self.watch_inner(None)
        }

        /// [`watch`](Self::watch) for a password-protected stream.
        pub fn watch_with_password(
            &self,
            password: &str,
        ) -> impl Stream<Item = Result<String>> + Send + 'static {
            self.watch_inner(Some(password.to_owned()))
        }

        fn watch_inner(
            &self,
            password: Option<String>,
        ) -> impl Stream<Item = Result<String>> + Send + 'static {
            let base = self.base.clone();
            let full_token = self.full_token.clone();
            let key = self.key;
            let client = self.client.clone();

            async_stream::stream! {
                let mut last_id: Option<String> = None;
                let mut access_token: Option<String> = None;
                // A token rejected straight after a fresh join is a real failure, not expiry.
                let mut fresh_token = false;

                'outer: loop {
                    if access_token.is_none() {
                        match join_stream(&client, &base, &full_token, password.as_deref()).await {
                            Ok(at) => {
                                access_token = Some(at);
                                fresh_token = true;
                            }
                            Err(e) => {
                                yield Err(e);
                                return;
                            }
                        }
                    }
                    let at = access_token.clone().unwrap_or_default();

                    let mut req = client
                        .get(format!("{base}/api/stream/{full_token}/events/"))
                        .query(&[("at", at.as_str())]);

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

                    match resp.status().as_u16() {
                        410 => return, // closed or expired
                        401 if !fresh_token => {
                            access_token = None; // expired — join again
                            continue 'outer;
                        }
                        s if !(200..300).contains(&s) => {
                            let wait = retry_after(resp.headers());
                            let body = resp.text().await.unwrap_or_default();
                            yield Err(http_error(s, wait, &body));
                            return;
                        }
                        _ => {}
                    }
                    fresh_token = false;

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
                    // Connection dropped — reconnect after a short pause (continue outer loop)
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
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
/// Each call starts its own Tokio runtime, so do not call these from inside one.
pub mod blocking {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().expect("failed to create tokio runtime")
    }

    /// Blocking version of [`read`].
    pub fn read(url_or_token: &str) -> Result<ReadResult> {
        rt().block_on(super::read(url_or_token))
    }

    /// Blocking version of [`read_with`].
    pub fn read_with(url_or_token: &str, opts: ReadOptions) -> Result<ReadResult> {
        rt().block_on(super::read_with(url_or_token, opts))
    }

    /// Blocking version of [`peek`].
    pub fn peek(url_or_token: &str, base: Option<&str>) -> Result<PeekResult> {
        rt().block_on(super::peek(url_or_token, base))
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

/// Derive a note's AES key from its secret with the named kdf
/// ([`KDF_SHA256`] or [`KDF_PBKDF2`]; the password is hashed as its UTF-8 bytes).
fn derive_note_key(secret_hex: &str, kdf: &str, password: Option<&str>) -> Result<[u8; 32]> {
    if kdf != KDF_PBKDF2 {
        return derive_key_bytes(secret_hex);
    }
    let password = password.filter(|p| !p.is_empty()).ok_or(Error::PasswordRequired)?;
    let salt = hex_decode(secret_hex)?;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}

/// AES-256-GCM encrypt with the sha256-derived key (streams). Returns (ciphertext_hex, iv_hex).
fn encrypt_content(plaintext: &str, secret_hex: &str) -> Result<(String, String)> {
    encrypt_with_key(plaintext, &derive_key_bytes(secret_hex)?)
}

/// AES-256-GCM encrypt. Returns (ciphertext_hex, iv_hex).
/// Output ciphertext is ciphertext || 16-byte tag (Go SDK compatible).
fn encrypt_with_key(plaintext: &str, key_bytes: &[u8; 32]) -> Result<(String, String)> {
    use aes_gcm::aead::rand_core::RngCore;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));

    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    // aes-gcm Seal returns ciphertext || tag automatically
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| Error::DecryptionFailed)?;

    Ok((hex_encode(&ciphertext), hex_encode(iv_bytes)))
}

/// AES-256-GCM decrypt with the sha256-derived key. Expects ciphertext || tag (16 bytes).
#[cfg(test)]
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

/// Extract the 64-char hex token from a legacy URL or raw string.
fn extract_token(url_or_token: &str) -> Result<String> {
    let s = if url_or_token.starts_with("http") {
        url_or_token
            .trim_end_matches('/')
            .split('/')
            .next_back()
            .unwrap_or("")
    } else {
        url_or_token
    };

    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidToken);
    }
    Ok(s.to_lowercase())
}

/// Generate a 16-byte (32-hex-char) secret for use with the v1 API.
fn generate_secret() -> String {
    use aes_gcm::aead::rand_core::RngCore;
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    hex_encode(raw)
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

    // ── Cross-client known answers ────────────────────────────────────────────
    // Shared with the iOS and Android suites (secret, iv and ciphertexts produced
    // with WebCrypto).

    const KAT_SECRET: &str = "00112233445566778899aabbccddeeff";
    const KAT_IV: &str = "a1b2c3d4e5f6000102030405";
    const KAT_SHA256: &str = "8f6ee0eb13334ea99cf53aa86bf4dc0fa4686b9c74f1bf98f3aa4bc216d70fc058ba9452266c57c681a5";
    const KAT_PBKDF2: &str = "3ca068b802bd8f8d25145619048f5de9b50ae3319ad9bc9f6af38bd9980107a311fb228dfd0b3e6b2c24";
    const KAT_UNICODE: &str = "c9aa7b0cd91b24f9c7982e6c0acb6233391307fc327b512c1ec87571aa62dbc5";
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_known_answer_keys() {
        let cases = [
            (KDF_SHA256, None, "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811"),
            (KDF_PBKDF2, Some("correct horse battery staple"), "7c0123695eb46911838d4c16fa259d7280c59060c6031130b8269b624faacd02"),
            (KDF_PBKDF2, Some("pässwörd-日本"), "2b547d9425d7d2a2dd01af3de73ec8d103c6a4f77c667f14ab406f92bbe88ac6"),
            (KDF_PBKDF2, Some("pässwörd🔑"), "bd9dc18065862b49fcb0b4f514fbc6021c5bc751313d261bd57ea9bd7dddbf10"),
        ];
        for (kdf, password, want) in cases {
            assert_eq!(hex_encode(derive_note_key(KAT_SECRET, kdf, password).unwrap()), want, "{kdf} {password:?}");
        }
    }

    #[test]
    fn test_pbkdf2_needs_a_password() {
        assert!(matches!(derive_note_key(KAT_SECRET, KDF_PBKDF2, None), Err(Error::PasswordRequired)));
        assert!(matches!(derive_note_key(KAT_SECRET, KDF_PBKDF2, Some("")), Err(Error::PasswordRequired)));
    }

    // ── HTTP behaviour against a mock server ─────────────────────────────────

    use mockito::{Matcher, Server, ServerGuard};
    use std::sync::{Arc, Mutex};

    fn note_url(server: &ServerGuard) -> String {
        format!("{}/n/{TOKEN}#{KAT_SECRET}", server.url())
    }

    fn meta_body(kdf: &str) -> String {
        serde_json::json!({"token": TOKEN, "exists": true, "type": "note", "viewLimit": 2, "viewsRemaining": 2, "kdf": kdf}).to_string()
    }

    fn consume_body(kdf: &str, encrypted: &str) -> String {
        serde_json::json!({"token": TOKEN, "encrypted": encrypted, "iv": KAT_IV, "kdf": kdf, "consumed": true, "viewsRemaining": 1, "destroyed": false}).to_string()
    }

    async fn mock_note(server: &mut ServerGuard, kdf: &str, encrypted: &str, consumes: usize) -> mockito::Mock {
        server.mock("GET", format!("/api/v1/note/{TOKEN}/meta/").as_str())
            .with_body(meta_body(kdf)).create_async().await;
        server.mock("GET", format!("/api/v1/note/{TOKEN}/consume/").as_str())
            .with_body(consume_body(kdf, encrypted)).expect(consumes).create_async().await
    }

    /// Mock create endpoint that keeps the request body so the test can decrypt it.
    async fn mock_create(server: &mut ServerGuard, matcher: Matcher, auth: Matcher) -> (mockito::Mock, Arc<Mutex<Vec<u8>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let mock = server.mock("POST", "/api/v1/note/")
            .match_header("authorization", auth)
            .match_body(matcher)
            .with_status(201)
            .with_body_from_request(move |req| {
                let body = req.body().unwrap().clone();
                let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
                *sink.lock().unwrap() = body;
                serde_json::json!({"token": TOKEN, "url": format!("https://voidnote.net/n/{TOKEN}"),
                    "expiresAt": "2026-10-15 12:00:00", "viewLimit": parsed["viewLimit"], "kdf": parsed["kdf"]})
                    .to_string().into_bytes()
            })
            .create_async().await;
        (mock, captured)
    }

    fn open_created(body: &[u8], url: &str, kdf: &str, password: Option<&str>) -> String {
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        let secret = url.rsplit('#').next().unwrap();
        let key = derive_note_key(secret, kdf, password).unwrap();
        decrypt_with_key(v["encrypted"].as_str().unwrap(), v["iv"].as_str().unwrap(), &key).unwrap()
    }

    #[tokio::test]
    async fn test_create_anonymous_sends_no_authorization() {
        let mut server = Server::new_async().await;
        let (mock, body) = mock_create(
            &mut server,
            Matcher::PartialJson(serde_json::json!({"expiresIn": 3600, "viewLimit": 1, "kdf": "sha256"})),
            Matcher::Missing,
        ).await;
        let res = create("hello", CreateOptions { base: Some(server.url()), ..Default::default() }).await.unwrap();
        mock.assert_async().await;
        assert_eq!((res.kdf.as_str(), res.view_limit, res.token.as_str()), ("sha256", 1, TOKEN));
        assert_eq!(open_created(&body.lock().unwrap(), &res.url, KDF_SHA256, None), "hello");
    }

    #[tokio::test]
    async fn test_create_with_key_sends_bearer() {
        let mut server = Server::new_async().await;
        let (mock, _) = mock_create(&mut server, Matcher::Any, Matcher::Exact("Bearer vn_test".into())).await;
        create("hello", CreateOptions { api_key: Some("vn_test".into()), base: Some(server.url()), ..Default::default() })
            .await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_create_with_password_uses_pbkdf2() {
        let mut server = Server::new_async().await;
        let (mock, body) = mock_create(
            &mut server,
            Matcher::PartialJson(serde_json::json!({"expiresIn": 7200, "viewLimit": 3, "kdf": "pbkdf2-sha256-600k"})),
            Matcher::Missing,
        ).await;
        let res = create("guarded", CreateOptions {
            password: Some("pässwörd-日本".into()),
            max_views: Some(3),
            expires_in: Some(2),
            base: Some(server.url()),
            ..Default::default()
        }).await.unwrap();
        mock.assert_async().await;
        assert_eq!(res.kdf, KDF_PBKDF2);
        assert_eq!(open_created(&body.lock().unwrap(), &res.url, KDF_PBKDF2, Some("pässwörd-日本")), "guarded");
    }

    #[tokio::test]
    async fn test_create_refuses_empty_password() {
        let mut server = Server::new_async().await;
        let mock = server.mock("POST", "/api/v1/note/").expect(0).create_async().await;
        let err = create("x", CreateOptions { password: Some(String::new()), base: Some(server.url()), ..Default::default() })
            .await.unwrap_err();
        assert!(matches!(err, Error::EmptyPassword));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_create_surfaces_429_retry_after() {
        let mut server = Server::new_async().await;
        server.mock("POST", "/api/v1/note/").with_status(429).with_header("retry-after", "60")
            .with_body(r#"{"error":"Too many notes created. Try again shortly."}"#).create_async().await;
        let err = create("x", CreateOptions { base: Some(server.url()), ..Default::default() }).await.unwrap_err();
        match &err {
            Error::Http { status: 429, message, retry_after: Some(60) } => {
                assert_eq!(message, "Too many notes created. Try again shortly.")
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(err.to_string(), "HTTP 429: Too many notes created. Try again shortly. (retry after 60s)");
    }

    #[tokio::test]
    async fn test_create_surfaces_400_limit_message() {
        let mut server = Server::new_async().await;
        server.mock("POST", "/api/v1/note/").with_status(400)
            .with_body(r#"{"error":"viewLimit must be 1–10 without an account."}"#).create_async().await;
        let err = create("x", CreateOptions { max_views: Some(50), base: Some(server.url()), ..Default::default() })
            .await.unwrap_err();
        assert!(matches!(err, Error::Http { status: 400, ref message, retry_after: None } if message == "viewLimit must be 1–10 without an account."));
    }

    #[tokio::test]
    async fn test_read_known_answers() {
        let cases = [
            (KDF_SHA256, KAT_SHA256, None, "voidnote-v1-sha256-kat ✓"),
            (KDF_PBKDF2, KAT_PBKDF2, Some("correct horse battery staple"), "voidnote-v1-pbkdf2-kat ✓"),
            (KDF_PBKDF2, KAT_UNICODE, Some("pässwörd-日本"), "unicode password"),
        ];
        for (kdf, encrypted, password, want) in cases {
            let mut server = Server::new_async().await;
            mock_note(&mut server, kdf, encrypted, 1).await;
            let note = read_with(&note_url(&server), ReadOptions {
                password: password.map(String::from),
                base: Some(server.url()),
            }).await.unwrap();
            assert_eq!(note.content, want);
            assert_eq!((note.kdf.as_str(), note.max_views, note.view_count), (kdf, 2, 1));
        }
    }

    #[tokio::test]
    async fn test_read_password_note_without_password_fails_before_consume() {
        let mut server = Server::new_async().await;
        let consume = mock_note(&mut server, KDF_PBKDF2, KAT_PBKDF2, 0).await;
        let err = read_from(&note_url(&server), &server.url()).await.unwrap_err();
        assert!(matches!(err, Error::PasswordRequired));
        consume.assert_async().await;
    }

    #[tokio::test]
    async fn test_read_wrong_password() {
        let mut server = Server::new_async().await;
        mock_note(&mut server, KDF_PBKDF2, KAT_PBKDF2, 1).await;
        let err = read_with(&note_url(&server), ReadOptions { password: Some("wrong".into()), base: Some(server.url()) })
            .await.unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed));
    }

    #[tokio::test]
    async fn test_read_unknown_kdf_fails_before_consume() {
        let mut server = Server::new_async().await;
        let consume = mock_note(&mut server, "argon2id", KAT_SHA256, 0).await;
        let err = read_with(&note_url(&server), ReadOptions { password: Some("x".into()), base: Some(server.url()) })
            .await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedKdf(ref k) if k == "argon2id"));
        consume.assert_async().await;
    }

    #[tokio::test]
    async fn test_read_missing_note() {
        let mut server = Server::new_async().await;
        server.mock("GET", format!("/api/v1/note/{TOKEN}/meta/").as_str())
            .with_body(format!(r#"{{"token":"{TOKEN}","exists":false}}"#)).create_async().await;
        let err = read_from(&note_url(&server), &server.url()).await.unwrap_err();
        assert!(matches!(err, Error::NotFound));
    }

    #[tokio::test]
    async fn test_peek_exposes_kdf() {
        let mut server = Server::new_async().await;
        mock_note(&mut server, KDF_PBKDF2, KAT_PBKDF2, 0).await;
        let meta = peek(&note_url(&server), Some(&server.url())).await.unwrap();
        assert_eq!((meta.kdf.as_str(), meta.views_remaining), (KDF_PBKDF2, 2));
    }
}
