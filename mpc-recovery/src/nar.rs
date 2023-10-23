// TODO: use NAR in the future.
//! Separated away from client to distinguish functions that are common and
//! need to be moved eventually into their own separate crate. Not necessarily
//! to be used from workspaces directly even though it is imported from there.

use std::time::Duration;

use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

pub(crate) async fn retry_every<R, E, T, F>(interval: Duration, task: F) -> T::Output
where
    F: FnMut() -> T,
    T: core::future::Future<Output = core::result::Result<R, E>>,
{
    let retry_strategy = std::iter::repeat_with(|| interval);
    let task = Retry::spawn(retry_strategy, task);
    task.await
}

pub(crate) async fn retry<R, E, T, F>(task: F) -> T::Output
where
    F: FnMut() -> T,
    T: core::future::Future<Output = core::result::Result<R, E>>,
{
    // Exponential backoff starting w/ 5ms for maximum retry of 4 times with the following delays:
    //   5, 25, 125, 625 ms
    let retry_strategy = ExponentialBackoff::from_millis(5).map(jitter).take(4);
    Retry::spawn(retry_strategy, task).await
}
