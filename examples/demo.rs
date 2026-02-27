//! VoidNote Rust SDK — demo
//! cargo run --example demo -- read <url-or-token>
//! cargo run --example demo -- create "your secret" <api-key>
//! cargo run --example demo -- stream <api-key>
//! cargo run --example demo -- watch <url-or-token>

use futures::StreamExt;
use voidnote::{create, create_stream, read, CreateOptions, StreamOptions};

#[tokio::main]
async fn main() -> voidnote::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("read") => {
            let token = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo read <url-or-token>");
                std::process::exit(1);
            });
            let result = read(token).await?;
            println!("content:    {}", result.content);
            if let Some(t) = result.title {
                println!("title:      {t}");
            }
            println!("views:      {}/{}", result.view_count, result.max_views);
            println!("destroyed:  {}", result.destroyed);
        }

        Some("create") => {
            let content = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo create <message> <api-key>");
                std::process::exit(1);
            });
            let api_key = args.get(3).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo create <message> <api-key>");
                std::process::exit(1);
            });
            let result = create(
                content,
                CreateOptions {
                    api_key: api_key.into(),
                    max_views: Some(1),
                    ..Default::default()
                },
            )
            .await?;
            println!("url:        {}", result.url);
            println!("expires_at: {}", result.expires_at);
        }

        Some("stream") => {
            let api_key = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo stream <api-key>");
                std::process::exit(1);
            });
            let mut stream = create_stream(StreamOptions {
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

        Some("watch") => {
            let token = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("usage: demo watch <url-or-token>");
                std::process::exit(1);
            });

            // You need a stream handle to watch — this example shows the API shape.
            // In practice you'd get the handle from create_stream() and share the URL.
            println!("watching stream: {token}");
            println!("(create a stream first and share its URL/token)");
            println!("note: to watch, you need a StreamHandle from create_stream()");
            println!("      the watch() method is available on that handle.");
            let _ = token;
        }

        _ => {
            eprintln!(
                "usage:\n\
                 demo read   <url-or-token>\n\
                 demo create <message> <api-key>\n\
                 demo stream <api-key>\n\
                 demo watch  <url-or-token>"
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
