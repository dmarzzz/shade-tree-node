//! The service: signer, stake verifier, registry (reloaded from the store), the sweep loop,
//! the loopback metrics listener, the discovery listener behind the onion, and a drain on
//! SIGTERM or SIGINT that lets in-flight requests finish for the configured grace.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use shadenet_service::clock;
use shadenet_service::metrics::Registry as Metrics;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::canopy::Canopy;
use crate::config::{Admission, Config};
use crate::error::Error;
use crate::federation::Federation;
use crate::incidents::Incidents;
use crate::probe::Prober;
use crate::registry::{self, Registry};
use crate::relay::Aggregator;
use crate::server::{self, Shared};
use crate::signer::Signer;
use crate::stake::Verifier;
use shadenet_service::torhttp::Socks;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Elder {
    config: Config,
}

enum Signal {
    Terminate(&'static str),
}

struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Shutdown {
    fn install() -> Result<Self, Error> {
        #[cfg(unix)]
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|source| Error::Signal {
            signal: "SIGTERM",
            source,
        })?;
        Ok(Self {
            #[cfg(unix)]
            terminate,
        })
    }

    async fn recv(&mut self) -> Signal {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => Signal::Terminate("SIGINT"),
                _ = self.terminate.recv() => Signal::Terminate("SIGTERM"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            Signal::Terminate("SIGINT")
        }
    }
}

impl Elder {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Serve until SIGTERM or SIGINT, then drain.
    pub async fn run(self) -> Result<(), Error> {
        let config = self.config;
        let metrics = Arc::new(Metrics::new(
            "elder",
            VERSION,
            shadenet_service::version::COMMIT,
            crate::metrics::DEFINITIONS,
        ));
        let signer = Arc::new(Signer::load_or_mint(&config.signer_key)?);
        let stake = Arc::new(
            Verifier::new(&config.stake, Arc::clone(&metrics))
                .map_err(|e| Error::Config(vec![e]))?,
        );
        let now = clock::now_secs();
        let registry = Arc::new(Registry::new(
            Arc::clone(&stake),
            registry::Settings {
                require_stake: config.admission == Admission::Stake,
                ttl_secs: config.ttl_secs,
                max_entries: config.max_entries,
                min_reannounce_secs: config.min_reannounce_secs,
                announce_rate: config.announce_rate,
                announce_burst: config.announce_burst,
                store: config.store.clone(),
            },
            now,
        ));
        if let Some(store) = &config.store {
            let (loaded, dropped) = registry.load_persisted(now).await;
            tracing::info!(loaded, dropped, store = %store.display(), "persistence: reloaded gateways");
        }
        let canopy = Arc::new(Canopy::new(
            Arc::clone(&signer),
            Arc::clone(&registry),
            config.delta_history,
        ));
        let incidents = Arc::new(Incidents::new(
            config.incidents_file.clone(),
            Arc::clone(&signer),
        ));
        let relay = Arc::new(
            Aggregator::new(
                Arc::clone(&signer),
                Arc::clone(&registry),
                Some(config.relay.state.clone()),
                config.relay.minimum_cohort,
                config.relay.delay_hours,
            )
            .map_err(|message| Error::State {
                path: config.relay.state.clone(),
                message,
            })?,
        );
        let shared = Arc::new(Shared {
            registry: Arc::clone(&registry),
            canopy: Arc::clone(&canopy),
            metrics: Arc::clone(&metrics),
            signer_pub: signer.public_hex().to_string(),
            admission: config.admission.label(),
            pay: config.pay.clone(),
            relay,
            incidents: Arc::clone(&incidents),
            incidents_token: config.incidents_token.clone(),
            limits: config.limits.clone(),
            connections: AtomicUsize::new(0),
            listening: AtomicBool::new(false),
        });
        metrics.gauge(
            "shade_tree_bootnode_live_gateways",
            &[],
            registry.size() as f64,
        );

        let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| Error::Bind { addr, source })?;
        // port 0 asks the system for a free one; the ready line names what was bound
        let bound = listener.local_addr().unwrap_or(addr);
        let metrics_listener = match config.metrics_port {
            0 => None,
            port => Some(
                shadenet_service::metrics::bind(port)
                    .await
                    .map_err(|source| Error::Bind {
                        addr: SocketAddr::from(([127, 0, 0, 1], port)),
                        source,
                    })?,
            ),
        };
        let mut shutdown = Shutdown::install()?;
        let mut background = JoinSet::new();

        // the sweep ages out entries between announces so the store never keeps a dead node
        let sweeper = Arc::clone(&registry);
        let sweep_metrics = Arc::clone(&metrics);
        let sweep_every = Duration::from_secs(config.ttl_secs.clamp(1, 60));
        background.spawn(async move {
            loop {
                tokio::time::sleep(sweep_every).await;
                sweeper.sweep(clock::now_secs());
                sweep_metrics.gauge(
                    "shade_tree_bootnode_live_gateways",
                    &[],
                    sweeper.size() as f64,
                );
            }
        });
        if let Some(listener) = metrics_listener {
            let ready = Arc::clone(&shared);
            tracing::info!(event = "metrics.ready", listen = %format!("127.0.0.1:{}", config.metrics_port), "operator metrics ready");
            background.spawn(shadenet_service::metrics::serve(
                listener,
                Arc::clone(&metrics),
                move || ready.ready(),
            ));
        }
        let socks = Socks {
            host: config.tor.host.clone(),
            port: config.tor.port,
        };
        if let Some(probe) = &config.probe {
            let prober = Arc::new(Prober::new(
                socks.clone(),
                probe.timeout,
                probe.interval,
                probe.fail_threshold,
                Arc::clone(&registry),
                Arc::clone(&canopy),
            ));
            tracing::info!(
                interval_sec = prober.interval().as_secs(),
                fail_threshold = prober.fail_threshold(),
                "active health probing on"
            );
            background.spawn(prober.run());
        }
        if let Some(settings) = &config.federation {
            let federation = Arc::new(Federation::new(
                Arc::clone(&registry),
                settings.peers.clone(),
                socks,
                settings.interval,
                settings.max_pull,
            ));
            tracing::info!(
                peers = federation.peers().len(),
                interval_sec = federation.interval().as_secs(),
                "bootnode federation on"
            );
            background.spawn(federation.run());
        }
        tracing::info!(
            file = %incidents.path().display(),
            webhook = if config.incidents_token.is_some() { "POST /incidents/alertmanager (bearer)" } else { "off" },
            "incident feed on"
        );
        if let Some(pay) = &config.pay {
            tracing::info!(advert = %pay, "advertising 402 registrar in /health");
        }

        shared.listening.store(true, Ordering::Relaxed);
        let (rate, burst) = registry.bucket();
        tracing::info!(
            event = "service.ready",
            admission = config.admission.label(),
            stake = %stake.mode(),
            ttl_sec = config.ttl_secs,
            metrics_port = config.metrics_port,
            "bootnode up on {bound}"
        );
        tracing::info!(signer = signer.public_hex(), "Canopy signer ready");
        tracing::debug!(
            announce_rate_per_sec = format!("{rate:.2}"),
            announce_burst = burst,
            headers_timeout_ms = config.limits.headers_timeout.map(|d| d.as_millis()),
            request_timeout_ms = config.limits.request_timeout.map(|d| d.as_millis()),
            keepalive_timeout_ms = config.limits.keepalive_timeout.map(|d| d.as_millis()),
            max_header_bytes = config.limits.max_header_bytes,
            "endpoint hardening"
        );

        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .keep_alive(true)
            .max_header_size(config.limits.max_header_bytes)
            .header_read_timeout(server::header_read_timeout(&config.limits));
        let graceful = GracefulShutdown::new();
        let signal = loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    let shared = Arc::clone(&shared);
                    let open = shared.connections.fetch_add(1, Ordering::Relaxed) + 1;
                    shared.metrics.gauge("shade_tree_bootnode_connections", &[], open as f64);
                    let service = {
                        let shared = Arc::clone(&shared);
                        service_fn(move |req| {
                            let shared = Arc::clone(&shared);
                            async move { Ok::<_, std::convert::Infallible>(server::handle(shared, req).await) }
                        })
                    };
                    let connection = graceful.watch(builder.serve_connection(TokioIo::new(stream), service));
                    tokio::spawn(async move {
                        let _ = connection.await;
                        let open = shared.connections.fetch_sub(1, Ordering::Relaxed) - 1;
                        shared.metrics.gauge("shade_tree_bootnode_connections", &[], open as f64);
                    });
                }
                signal = shutdown.recv() => break signal,
            }
        };
        let Signal::Terminate(name) = signal;
        shared.listening.store(false, Ordering::Relaxed);
        drop(listener);
        let open = shared.connections.load(Ordering::Relaxed);
        tracing::info!(
            event = "service.shutdown",
            "elder: draining ({name}); {open} in-flight, no new connections, {}ms grace",
            config.shutdown_timeout.as_millis()
        );
        background.abort_all();
        match tokio::time::timeout(config.shutdown_timeout, graceful.shutdown()).await {
            Ok(()) => {
                tracing::info!(
                    event = "service.shutdown",
                    "elder: drained cleanly, exiting"
                );
                Ok(())
            }
            Err(_) => Err(Error::DrainTimeout {
                open: shared.connections.load(Ordering::Relaxed),
                grace: config.shutdown_timeout,
            }),
        }
    }
}
