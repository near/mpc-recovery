use prometheus::{register_int_counter_vec, HistogramVec, IntCounterVec};

use lazy_static::lazy_static;
use prometheus::{opts, register_histogram_vec};

const EXPONENTIAL_SECONDS: &[f64] = &[
    0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256, 0.512, 1.024, 2.048, 4.096,
    8.192, 16.384, 32.768,
];

lazy_static! {
    pub static ref HTTP_REQUEST_COUNT: IntCounterVec = register_int_counter_vec!(
        opts!(
            "mpc_http_total_count",
            "Total count of HTTP RPC requests received, by method and path"
        ),
        &["method", "path"]
    )
    .expect("can't create a metric");
    pub static ref HTTP_CLIENT_ERROR_COUNT: IntCounterVec = register_int_counter_vec!(
        opts!(
            "mpc_http_client_error_count",
            "Total count of client errors (4xx) by method and path"
        ),
        &["method", "path"]
    )
    .expect("can't create a metric");
    pub static ref HTTP_SERVER_ERROR_COUNT: IntCounterVec = register_int_counter_vec!(
        opts!(
            "mpc_http_server_error_count",
            "Total count of server errors (5xx) by method and path"
        ),
        &["method", "path"]
    )
    .expect("can't create a metric");
    pub static ref HTTP_PROCESSING_TIME: HistogramVec = register_histogram_vec!(
        "mpc_http_processing_time",
        "Time taken to process HTTP requests in seconds",
        &["method", "path"],
        EXPONENTIAL_SECONDS.to_vec(),
    )
    .expect("can't create a metric");
}
