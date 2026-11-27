//! One-hop CREATE_FAST circuit to a relay, then a raw directory GET over BEGIN_DIR.
mod common;
use microtor::circuit::{connect_link, flush, pump, Circuit, Core};
use microtor::rt::{progress, spawn, Executor};
use std::time::Duration;

fn main() {
    common::init_logging();
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "217.196.147.77:443".into());
    let path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tor/keys/all".into());
    let core = Core::new();
    let link = connect_link(&core, addr.parse().unwrap(), Duration::from_secs(10)).expect("link");
    let c2 = core.clone();
    spawn(async move {
        let run = async {
            let circ = Circuit::create_fast(&c2, link).await?;
            log::info!("circuit up");
            let stream = circ.begin_dir().await?;
            log::info!("dir stream up");
            let req = format!("GET {path} HTTP/1.0\r\n\r\n");
            stream.write_all(req.as_bytes()).await?;
            let mut total = 0usize;
            let mut head = Vec::new();
            let mut buf = [0u8; 2048];
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                if head.len() < 600 {
                    head.extend_from_slice(&buf[..n.min(600 - head.len())]);
                }
                total += n;
            }
            log::info!(
                "got {total} bytes; head:\n{}",
                String::from_utf8_lossy(&head)
            );
            Ok::<(), microtor::Error>(())
        };
        if let Err(e) = run.await {
            log::error!("failed: {e}");
        }
    });
    let mut exec = Executor::new();
    loop {
        let before = progress();
        pump(&core);
        let alive = exec.turn();
        flush(&core);
        if alive == 0 {
            break;
        }
        if progress() == before {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let c = core.borrow();
    println!("cells in={} out={}", c.cells_in, c.cells_out);
}
