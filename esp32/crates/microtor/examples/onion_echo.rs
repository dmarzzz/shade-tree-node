//! Host an onion service that answers HTTP on port 80 with a short page.
//!
//!   cargo run --example onion_echo            # fresh identity each run
//!   SEED=<64 hex> cargo run --example onion_echo
mod common;
use microtor::circuit::turn;
use microtor::hs::{OnionService, ServiceConfig};
use microtor::netdir::MemScratch;
use microtor::rt::{spawn, Executor};
use microtor::tor::Tor;
use std::time::{Duration, Instant};

fn main() {
    common::init_logging();
    let seed: [u8; 32] = match std::env::var("SEED") {
        Ok(hex) => microtor::util::hex_fixed(&hex).expect("SEED is 64 hex chars"),
        Err(_) => microtor::crypto::rand_array(),
    };
    let tor = Tor::new(Box::<MemScratch>::default(), microtor::crypto::rand_array());
    let service = OnionService::new(tor.clone(), &seed, ServiceConfig::default());
    println!("onion: {}", service.onion());
    service.start();

    let svc = service.clone();
    spawn(async move {
        loop {
            let incoming = svc.accept().await;
            log::info!("stream for port {}", incoming.port);
            spawn(async move {
                let Ok(stream) = incoming.accept() else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 512];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 4096 {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let first = String::from_utf8_lossy(&request);
                let first = first.lines().next().unwrap_or("");
                let body = format!("hello from microtor\nyou asked: {first}\n");
                let reply = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                stream.end(microtor::cell::end_reason::DONE);
            });
        }
    });

    let mut exec = Executor::new();
    let mut last_report = Instant::now();
    let mut announced = false;
    loop {
        turn(tor.core(), &mut exec);
        if service.is_published() && !announced {
            announced = true;
            println!("PUBLISHED {}", service.onion());
        }
        if last_report.elapsed() > Duration::from_secs(30) {
            last_report = Instant::now();
            log::info!(
                "intros={} circuits={} stats={:?}",
                service.intro_count(),
                tor.core().borrow().circuit_count(),
                service.stats()
            );
        }
    }
}
