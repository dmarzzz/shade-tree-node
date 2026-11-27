//! Bootstrap from a fallback directory: verified consensus, relay sample, one ring query.
mod common;
use microtor::bootstrap_data::FALLBACKS;
use microtor::circuit::{connect_link, turn, Circuit, Core};
use microtor::netdir::{fetch_certs, fetch_netdir, hs_service_index, MemScratch, RingQuery};
use microtor::rt::{spawn, Executor};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

fn main() {
    common::init_logging();
    let core = Core::new();
    let mut link = None;
    for _ in 0..12 {
        let f = &FALLBACKS[microtor::crypto::rand_u32() as usize % FALLBACKS.len()];
        let addr = SocketAddrV4::new(Ipv4Addr::from(f.ip), f.or_port);
        match connect_link(&core, addr, Duration::from_secs(6)) {
            Ok(l) => {
                log::info!("bootstrap link to {addr}");
                link = Some(l);
                break;
            }
            Err(e) => log::info!("fallback {addr}: {e}"),
        }
    }
    let link = link.expect("no fallback reachable");
    let c2 = core.clone();
    spawn(async move {
        let run = async {
            let circ = Circuit::create_fast(&c2, link).await?;
            let certs = fetch_certs(&circ).await?;
            let mut scratch = MemScratch::default();
            let (netdir, queries) =
                fetch_netdir(&circ, &certs, &mut scratch, &[7u8; 32], &mut |meta| {
                    let periods = meta.hs_periods();
                    log::info!(
                        "hs periods: {:?} fetch={}",
                        periods.pairs.map(|p| p.0),
                        periods.fetch
                    );
                    vec![RingQuery::new(
                        0,
                        hs_service_index(&[1u8; 32], 1, periods.pairs[0].0, periods.length),
                        4,
                    )]
                })
                .await?;
            for g in &netdir.guards {
                log::info!("guard candidate {}", g.addr);
            }
            for r in queries[0].relays() {
                log::info!("hsdir {}", r.addr);
            }
            Ok::<(), microtor::Error>(())
        };
        if let Err(e) = run.await {
            log::error!("failed: {e}");
        }
    });
    let mut exec = Executor::new();
    while turn(&core, &mut exec) > 0 {}
    let c = core.borrow();
    println!("cells in={} out={}", c.cells_in, c.cells_out);
}
