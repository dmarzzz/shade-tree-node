//! After a bootstrap, build three-hop circuits to pool relays and to ring directories.
mod common;
use microtor::circuit::turn;
use microtor::netdir::{hs_service_index, MemScratch, RingQuery};
use microtor::rt::{spawn, Executor};
use microtor::tor::Tor;
use std::time::Instant;

fn main() {
    common::init_logging();
    let tor = Tor::new(Box::<MemScratch>::default(), microtor::crypto::rand_array());
    let t2 = tor.clone();
    spawn(async move {
        let target = std::cell::Cell::new([0u8; 32]);
        let r = t2
            .refresh(&mut |meta| {
                let p = meta.hs_periods();
                let idx = hs_service_index(&[1u8; 32], 1, p.pairs[0].0, p.length);
                target.set(idx);
                vec![RingQuery::new(0, idx, 6)]
            })
            .await;
        if let Err(e) = r {
            log::error!("refresh: {e}");
            return;
        }
        let netdir = t2.netdir().unwrap();
        for relay in netdir.pool.iter().take(4) {
            let t = Instant::now();
            match t2.circuit_to(&relay.info).await {
                Ok(_) => log::info!("pool {} ok in {:?}", relay.info.addr, t.elapsed()),
                Err(e) => log::info!("pool {} FAILED {e} in {:?}", relay.info.addr, t.elapsed()),
            }
        }
        for dir in t2.hsdirs_for(&target.get()) {
            let t = Instant::now();
            match t2.circuit_to(&dir).await {
                Ok(_) => log::info!("hsdir {} ok in {:?}", dir.addr, t.elapsed()),
                Err(e) => log::info!("hsdir {} FAILED {e} in {:?}", dir.addr, t.elapsed()),
            }
        }
    });
    let mut exec = Executor::new();
    while turn(tor.core(), &mut exec) > 0 {}
}
