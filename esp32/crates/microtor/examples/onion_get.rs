//! Dial an onion service and issue one HTTP GET: the client half of the onion stack.
//!
//!   cargo run --example onion_get -- <address>.onion /path
mod common;
use microtor::circuit::turn;
use microtor::crypto::ed_blind_public;
use microtor::hs::connect_onion;
use microtor::hsdesc::parse_onion;
use microtor::netdir::{hs_service_index, MemScratch, RingQuery};
use microtor::rt::{spawn, Executor};
use microtor::tor::Tor;
use std::time::Instant;

fn main() {
    common::init_logging();
    let address = std::env::args().nth(1).expect("onion address");
    let path = std::env::args().nth(2).unwrap_or_else(|| "/".into());
    let identity = parse_onion(&address).expect("valid v3 onion address");
    let tor = Tor::new(Box::<MemScratch>::default(), microtor::crypto::rand_array());
    let t2 = tor.clone();
    spawn(async move {
        let run = async {
            t2.refresh(&mut |meta| {
                let periods = meta.hs_periods();
                let (period, _) = periods.pairs[periods.fetch];
                let blinded = ed_blind_public(&identity, period, periods.length).unwrap();
                (1..=meta.hsdir_n_replicas)
                    .map(|replica| {
                        let index = hs_service_index(&blinded, replica, period, periods.length);
                        RingQuery::new(periods.fetch, index, usize::from(meta.hsdir_spread_fetch))
                    })
                    .collect()
            })
            .await?;
            let started = Instant::now();
            let conn = connect_onion(&t2, &identity, 80).await?;
            log::info!("connected to the onion service in {:?}", started.elapsed());
            let host = address.trim_end_matches(".onion");
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {host}.onion\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
            );
            conn.stream.write_all(request.as_bytes()).await?;
            let mut body = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = conn.stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            log::info!("{} bytes in {:?}", body.len(), started.elapsed());
            let text = String::from_utf8_lossy(&body);
            let limit = if std::env::var("FULL").is_ok() {
                usize::MAX
            } else {
                700
            };
            println!("{}", text.chars().take(limit).collect::<String>());
            Ok::<(), microtor::Error>(())
        };
        if let Err(e) = run.await {
            log::error!("failed: {e}");
        }
    });
    let mut exec = Executor::new();
    while turn(tor.core(), &mut exec) > 0 {}
}
