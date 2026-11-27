//! A stderr logger for the examples (the library only depends on the `log` facade).
use std::time::Instant;

struct Stderr(Instant);

impl log::Log for Stderr {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        eprintln!(
            "[{:>8.3}] {:<5} {}",
            self.0.elapsed().as_secs_f64(),
            record.level(),
            record.args()
        );
    }
    fn flush(&self) {}
}

pub fn init_logging() {
    let level = match std::env::var("LOG").as_deref() {
        Ok("trace") => log::LevelFilter::Trace,
        Ok("debug") => log::LevelFilter::Debug,
        Ok("warn") => log::LevelFilter::Warn,
        _ => log::LevelFilter::Info,
    };
    let logger: &'static Stderr = Box::leak(Box::new(Stderr(Instant::now())));
    log::set_logger(logger).ok();
    log::set_max_level(level);
}
