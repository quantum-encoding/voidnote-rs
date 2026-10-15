//! Live round trip against voidnote.net (creates real anonymous notes).
//!
//! ```sh
//! VOIDNOTE_LIVE_IN=in.json VOIDNOTE_LIVE_OUT=out.json cargo test --test live -- --ignored --nocapture
//! ```
//!
//! `VOIDNOTE_LIVE_IN` holds notes another SDK created; this test reads them
//! (cross-language), then creates its own and writes them to `VOIDNOTE_LIVE_OUT`.

use serde_json::{json, Value};
use voidnote::{create, peek, read_with, CreateOptions, Error, ReadOptions, KDF_PBKDF2, KDF_SHA256};

const LANG: &str = "rust";
const PASSWORD: &str = "pässwörd-日本🔑";

fn pass(step: &str) {
    println!("PASS {LANG}: {step}");
}

#[tokio::test]
#[ignore = "creates real notes on voidnote.net"]
async fn live_round_trip() {
    let base = std::env::var("VOIDNOTE_BASE").ok();
    let read_opts = |password: Option<&str>| ReadOptions { password: password.map(String::from), base: base.clone() };

    if let Some(prev) = std::env::var("VOIDNOTE_LIVE_IN").ok().and_then(|p| std::fs::read_to_string(p).ok()) {
        let prev: Value = serde_json::from_str(&prev).unwrap();
        let from = prev["from"].as_str().unwrap();
        let a = read_with(prev["sha256"].as_str().unwrap(), read_opts(None)).await.unwrap();
        assert_eq!((a.content.as_str(), a.kdf.as_str(), a.destroyed), (prev["content_sha256"].as_str().unwrap(), KDF_SHA256, true));
        pass(&format!("read {from} sha256 note (cross-language), destroyed on last view"));
        let b = read_with(prev["pbkdf2"].as_str().unwrap(), read_opts(prev["password"].as_str())).await.unwrap();
        assert_eq!((b.content.as_str(), b.kdf.as_str(), b.destroyed), (prev["content_pbkdf2"].as_str().unwrap(), KDF_PBKDF2, true));
        pass(&format!("read {from} pbkdf2 note with non-ASCII password (cross-language)"));
    }

    let content_sha256 = format!("live sha256 from {LANG} — ✓ 日本");
    let s = create(&content_sha256, CreateOptions { max_views: Some(2), base: base.clone(), ..Default::default() }).await.unwrap();
    let m = peek(&s.url, base.as_deref()).await.unwrap();
    assert_eq!((m.exists, m.kdf.as_str(), m.views_remaining, s.kdf.as_str()), (true, KDF_SHA256, 2, KDF_SHA256));
    let r = read_with(&s.url, read_opts(None)).await.unwrap();
    assert_eq!((r.content.as_str(), r.max_views - r.view_count), (content_sha256.as_str(), 1));
    pass("anonymous sha256 create → peek → read");

    let content_pbkdf2 = format!("live pbkdf2 from {LANG} — 🔒");
    let p = create(&content_pbkdf2, CreateOptions {
        password: Some(PASSWORD.into()),
        max_views: Some(2),
        base: base.clone(),
        ..Default::default()
    }).await.unwrap();
    assert_eq!(peek(&p.url, base.as_deref()).await.unwrap().kdf, KDF_PBKDF2);
    assert!(matches!(read_with(&p.url, read_opts(None)).await, Err(Error::PasswordRequired)));
    assert_eq!(peek(&p.url, base.as_deref()).await.unwrap().views_remaining, 2);
    pass("pbkdf2 read without password refused before consume (views still 2)");
    let r = read_with(&p.url, read_opts(Some(PASSWORD))).await.unwrap();
    assert_eq!((r.content.as_str(), r.max_views - r.view_count), (content_pbkdf2.as_str(), 1));
    pass("anonymous pbkdf2 create → read with non-ASCII password");

    let err = create("x", CreateOptions { api_key: Some("vn_invalid_live_check".into()), base: base.clone(), ..Default::default() })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Http { status: 401, ref message, .. } if message == "Invalid API key."), "{err}");
    pass("invalid API key surfaces 401 \"Invalid API key.\"");

    if let Ok(dst) = std::env::var("VOIDNOTE_LIVE_OUT") {
        let out = json!({
            "from": LANG, "password": PASSWORD,
            "sha256": s.url, "content_sha256": content_sha256,
            "pbkdf2": p.url, "content_pbkdf2": content_pbkdf2,
        });
        std::fs::write(dst, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
}
