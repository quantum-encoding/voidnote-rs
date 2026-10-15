//! VoidNote Rust SDK — demo
//! cargo run --example demo -- read <url-or-token> [password]
//! cargo run --example demo -- create "your secret" [password]
//! cargo run --example demo -- stream <api-key>
//!
//! VOIDNOTE_API_KEY, when set, is used by `create` (otherwise the note is anonymous).

use voidnote::{create, create_stream, read_with, CreateOptions, ReadOptions, StreamOptions};

#[tokio::main]
async fn main() -> voidnote::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("read") => {
            let token = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo read <url-or-token> [password]");
                std::process::exit(1);
            });
            let result = read_with(token, ReadOptions {
                password: args.get(3).cloned(),
                ..Default::default()
            })
            .await?;
            println!("content:    {}", result.content);
            if let Some(t) = result.title {
                println!("title:      {t}");
            }
            println!("views:      {}/{}", result.view_count, result.max_views);
            println!("kdf:        {}", result.kdf);
            println!("destroyed:  {}", result.destroyed);
        }

        Some("create") => {
            let content = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo create <message> [password]");
                std::process::exit(1);
            });
            let result = create(
                content,
                CreateOptions {
                    api_key: std::env::var("VOIDNOTE_API_KEY").ok(),
                    password: args.get(3).cloned(),
                    max_views: Some(1),
                    ..Default::default()
                },
            )
            .await?;
            println!("url:        {}", result.url);
            println!("expires_at: {}", result.expires_at);
            println!("kdf:        {}", result.kdf);
        }

        Some("stream") => {
            let api_key = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo stream <api-key>");
                std::process::exit(1);
            });
            let stream = create_stream(StreamOptions {
                api_key: api_key.into(),
                title: Some("demo stream".into()),
                ..Default::default()
            })
            .await?;

            println!("stream url: {}", stream.url);
            println!("writing messages...");

            stream.write("Hello from Rust! Message 1").await?;
            stream.write("Message 2 — zero-knowledge encrypted").await?;
            stream.close().await?;
            println!("stream closed.");
        }

        _ => {
            eprintln!(
                "usage:\n\
                 demo read   <url-or-token> [password]\n\
                 demo create <message> [password]\n\
                 demo stream <api-key>"
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
