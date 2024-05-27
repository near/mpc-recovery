use chrono::{DateTime, LocalResult, TimeZone, Utc};
use std::env;
use std::time::Duration;

pub fn get_triple_timeout() -> Duration {
    env::var("MPC_RECOVERY_TRIPLE_TIMEOUT_SEC")
        .map(|val| val.parse::<u64>().ok().map(Duration::from_secs))
        .unwrap_or_default()
        .unwrap_or(crate::types::PROTOCOL_TRIPLE_TIMEOUT)
}

pub fn is_elapsed_longer_than_timeout(timestamp_sec: u64, timeout: Duration) -> bool {
    if let LocalResult::Single(msg_timestamp) = Utc.timestamp_opt(timestamp_sec as i64, 0) {
        let now_datetime: DateTime<Utc> = Utc::now();
        // Calculate the difference in seconds
        let elapsed_duration = now_datetime.signed_duration_since(msg_timestamp);
        let timeout = chrono::Duration::seconds(timeout.as_secs() as i64)
            + chrono::Duration::nanoseconds(timeout.subsec_nanos() as i64);
        elapsed_duration > timeout
    } else {
        false
    }
}
