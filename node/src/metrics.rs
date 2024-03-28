use once_cell::sync::Lazy;
pub use prometheus::{
    self, core::MetricVec, core::MetricVecBuilder, exponential_buckets, linear_buckets, Counter,
    Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts, Result, TextEncoder,
};

pub(crate) static NODE_RUNNING: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_node_is_up",
        "whether the multichain signer node is up and running",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_sign_requests_count",
        "number of multichain sign requests, marked by sign requests indexed",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_SUCCESS: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_sign_requests_success",
        "number of successful multichain sign requests, marked by publish()",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGN_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_sign_latency_sec",
        "Latency of multichain signing, start from indexing sign request, end when publish() called.",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static LATEST_BLOCK_HEIGHT: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_latest_block_height",
        "Latest block height seen by the node",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static TRIPLE_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_triple_latency_sec",
        "Latency of multichain triple generation, start from starting generation, end when triple generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_presignature_latency_sec",
        "Latency of multichain presignature generation, start from starting generation, end when presignature generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGN_QUEUE_SIZE: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_sign_queue_size",
        "number of requests in sign queue",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGN_QUEUE_MINE_SIZE: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_sign_queue_mine_size",
        "number of my requests in sign queue",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLE_GENERATORS_INTRODUCED: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triple_generators_introduced",
        "number of triple generators",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLE_GENERATORS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triple_generators_total",
        "number of total ongoing triple generators",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLES_MINE: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triples_mine",
        "number of triples of the node's own",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLES_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triples_total",
        "number of total triples",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_PRESIGNATURES_MINE: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignatures_mine",
        "number of presignatures of the node's own",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_PRESIGNATURES_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignatures_total",
        "number of total presignatures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_PRESIGNATURE_GENERATORS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignature_generators_total",
        "number of total ongoing presignature generators",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static MESSAGE_QUEUE_SIZE: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_message_queue_size",
        "size of message queue of the node",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static MPC_CONTRACT_VERSION: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_contract_version",
        "contract version, the contract is of form v[x].multichain-mpc.testnet",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_total_historical_triple_generators",
        "number of all triple generators historically on the node",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        try_create_int_gauge_vec(
            "multichain_num_total_historical_triple_generators_success",
            "number of all successful triple generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        try_create_int_gauge_vec(
            "multichain_num_total_historical_triple_generations_mine_success",
            "number of successful triple generators that was mine historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        try_create_int_gauge_vec(
            "multichain_num_total_historical_presignature_generators",
            "number of all presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        try_create_int_gauge_vec(
            "multichain_num_total_historical_presignature_generators_success",
            "number of all successful presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        try_create_int_gauge_vec(
            "multichain_num_total_historical_presignature_generators_mine",
            "number of mine presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        try_create_int_gauge_vec(
            "multichain_num_total_historical_presignature_generators_mine_success",
            "number of mine presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_SIGN_SUCCESS_30S: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
            "multichain_sign_requests_success_30s",
            "number of successful multichain sign requests that finished within 30s, marked by publish()",
            &["node_account_id"],
        )
        .unwrap()
});

pub(crate) static SEND_ENCRYPTED_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_send_encrypted_ms",
        "Latency of send encrypted.",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_TOTAL: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_total",
        "Latency of multichain protocol iter, start of protocol till end of iteration",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 3.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_CRYPTO: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_crypto",
        "Latency of multichain protocol iter, start of crypto iter till end",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_CONSENSUS: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_consensus",
        "Latency of multichain protocol iter, start of consensus iter till end",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_MESSAGE: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_message",
        "Latency of multichain protocol iter, start of message iter till end",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static NUM_SEND_ENCRYPTED_FAILURE: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_send_encrypted_failure",
        "number of successful send encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SEND_ENCRYPTED_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    try_create_int_gauge_vec(
        "multichain_send_encrypted_total",
        "number total send encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static FAILED_SEND_ENCRYPTED_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    try_create_histogram_vec(
        "multichain_failed_send_encrypted_ms",
        "Latency of failed send encrypted.",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub fn try_create_int_gauge_vec(name: &str, help: &str, labels: &[&str]) -> Result<IntGaugeVec> {
    check_metric_multichain_prefix(name)?;
    let opts = Opts::new(name, help);
    let gauge = IntGaugeVec::new(opts, labels)?;
    prometheus::register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

/// Attempts to create a `HistogramVector`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Option<Vec<f64>>,
) -> Result<HistogramVec> {
    check_metric_multichain_prefix(name)?;
    let mut opts = HistogramOpts::new(name, help);
    if let Some(buckets) = buckets {
        opts = opts.buckets(buckets);
    }
    let histogram = HistogramVec::new(opts, labels)?;
    prometheus::register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

fn check_metric_multichain_prefix(name: &str) -> Result<()> {
    if name.starts_with("multichain_") {
        Ok(())
    } else {
        Err(prometheus::Error::Msg(format!(
            "Metrics are expected to start with 'multichain_', got {}",
            name
        )))
    }
}
