//! A single-threaded cooperative runtime with no wakers.
//!
//! Every task is polled once per loop turn. That is wasteful on a server and exactly right
//! here: there are a dozen tasks at most, each poll is a few comparisons, and the alternative
//! (wakers, timers, an I/O driver) costs more code and more RAM than the polling does. Tasks
//! are heap-allocated state machines, so nothing nests on the small device stack.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::{Duration, Instant};

use crate::Error;

type Task = Pin<Box<dyn Future<Output = ()>>>;

thread_local! {
    static SPAWNED: RefCell<Vec<Task>> = const { RefCell::new(Vec::new()) };
    static PROGRESS: Cell<u64> = const { Cell::new(0) };
}

/// Queue a task; it starts on the next executor turn.
pub fn spawn(fut: impl Future<Output = ()> + 'static) {
    SPAWNED.with(|s| s.borrow_mut().push(Box::pin(fut)));
}

/// Record that something moved (bytes, cells, a state change), so the loop does not sleep.
pub fn note_progress() {
    PROGRESS.with(|p| p.set(p.get().wrapping_add(1)));
}

pub fn progress() -> u64 {
    PROGRESS.with(Cell::get)
}

fn noop_waker() -> Waker {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable functions ignore the data pointer and do nothing.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

#[derive(Default)]
pub struct Executor {
    tasks: Vec<Task>,
}

impl Executor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Poll every task once. Returns how many are still running.
    pub fn turn(&mut self) -> usize {
        SPAWNED.with(|s| self.tasks.append(&mut s.borrow_mut()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let before = self.tasks.len();
        self.tasks
            .retain_mut(|task| task.as_mut().poll(&mut cx).is_pending());
        if self.tasks.len() != before {
            note_progress();
        }
        self.tasks.len() + SPAWNED.with(|s| s.borrow().len())
    }
}

/// Yield once so other tasks and the link get a turn.
pub async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(|_| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            Poll::Pending
        }
    })
    .await;
}

pub async fn sleep(duration: Duration) {
    let until = Instant::now() + duration;
    std::future::poll_fn(|_| {
        if Instant::now() >= until {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

/// Run `fut` until it finishes or `duration` passes.
pub async fn timeout<T>(
    duration: Duration,
    what: &'static str,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let until = Instant::now() + duration;
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(v);
        }
        if Instant::now() >= until {
            return Poll::Ready(Err(Error::Timeout(what)));
        }
        Poll::Pending
    })
    .await
}

/// Memory-related limits, adjustable once at start-up for the platform.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Stop reading the link while one stream holds this much undelivered data.
    pub stream_high_water: usize,
    /// Cells handled per link per loop turn.
    pub cells_per_turn: usize,
    /// Ask directory servers for deflate-compressed documents. Saves two thirds of the
    /// transfer and costs about 43 KB of heap for the inflater while a fetch runs.
    pub dir_compression: bool,
    /// Descriptor uploads in flight at once (each is its own three-hop circuit).
    pub upload_concurrency: usize,
}

impl Limits {
    pub const DESKTOP: Limits = Limits {
        stream_high_water: 64 * 1024,
        cells_per_turn: 64,
        dir_compression: true,
        upload_concurrency: 3,
    };
    /// For a device with about 200 KB of heap.
    pub const SMALL: Limits = Limits {
        stream_high_water: 8 * 1024,
        cells_per_turn: 16,
        dir_compression: true,
        upload_concurrency: 2,
    };
}

thread_local! {
    static LIMITS: Cell<Limits> = const { Cell::new(Limits::DESKTOP) };
    static HEAVY: Cell<bool> = const { Cell::new(false) };
}

pub fn limits() -> Limits {
    LIMITS.with(Cell::get)
}

pub fn set_limits(limits: Limits) {
    LIMITS.with(|l| l.set(limits));
}

/// Held while one memory-hungry job runs (a directory refresh, a descriptor build, a proof
/// verification). On a small device two of them at once do not fit, so they take turns.
pub struct Heavy(());

impl Drop for Heavy {
    fn drop(&mut self) {
        HEAVY.with(|h| h.set(false));
        note_progress();
    }
}

/// Wait for the heavy-job slot.
pub async fn heavy() -> Heavy {
    std::future::poll_fn(|_| {
        HEAVY.with(|h| {
            if h.get() {
                Poll::Pending
            } else {
                h.set(true);
                Poll::Ready(Heavy(()))
            }
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn tasks_interleave_and_finish() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut exec = Executor::new();
        for id in 0..3 {
            let log = log.clone();
            spawn(async move {
                for step in 0..2 {
                    log.borrow_mut().push((id, step));
                    yield_now().await;
                }
            });
        }
        while exec.turn() > 0 {}
        assert_eq!(log.borrow().len(), 6);
        assert_eq!(&log.borrow()[..3], &[(0, 0), (1, 0), (2, 0)]);
    }

    #[test]
    fn timeout_fires() {
        let mut exec = Executor::new();
        let out = Rc::new(RefCell::new(None));
        let o = out.clone();
        spawn(async move {
            let r = timeout(Duration::from_millis(5), "test", async {
                sleep(Duration::from_secs(5)).await;
                Ok(())
            })
            .await;
            *o.borrow_mut() = Some(r);
        });
        while exec.turn() > 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(*out.borrow(), Some(Err(Error::Timeout("test"))));
    }
}
