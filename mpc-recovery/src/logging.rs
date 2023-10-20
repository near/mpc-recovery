use opentelemetry::sdk::trace::{self, RandomIdGenerator, Sampler, Tracer};
use opentelemetry::sdk::Resource;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use std::fmt::Display;
use std::sync::OnceLock;
use tracing::subscriber::DefaultGuard;
use tracing_appender::non_blocking::NonBlocking;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::filter::{Filtered, LevelFilter};
use tracing_subscriber::layer::{Layered, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{fmt, reload, EnvFilter, Layer, Registry};

static LOG_LAYER_RELOAD_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();
static OTLP_LAYER_RELOAD_HANDLE: OnceLock<reload::Handle<LevelFilter, LogLayer<Registry>>> =
    OnceLock::new();

type LogLayer<Inner> = Layered<
    Filtered<
        fmt::Layer<Inner, fmt::format::DefaultFields, fmt::format::Format, NonBlocking>,
        reload::Layer<EnvFilter, Inner>,
        Inner,
    >,
    Inner,
>;

type TracingLayer<Inner> = Layered<
    Filtered<OpenTelemetryLayer<Inner, Tracer>, reload::Layer<LevelFilter, Inner>, Inner>,
    Inner,
>;

// Records the level of opentelemetry tracing verbosity configured via command-line flags at the startup.
static DEFAULT_OTLP_LEVEL: OnceLock<OpenTelemetryLevel> = OnceLock::new();

// Doesn't define WARN and ERROR, because the highest verbosity of spans is INFO.
#[derive(Copy, Clone, Debug, Default, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum OpenTelemetryLevel {
    #[default]
    OFF,
    INFO,
    DEBUG,
    TRACE,
}

impl Display for OpenTelemetryLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            OpenTelemetryLevel::OFF => "off",
            OpenTelemetryLevel::INFO => "info",
            OpenTelemetryLevel::DEBUG => "debug",
            OpenTelemetryLevel::TRACE => "trace",
        };
        write!(f, "{}", str)
    }
}

/// Whether to use colored log format.
/// Option `Auto` enables color output only if the logging is done to a terminal and
/// `NO_COLOR` environment variable is not set.
#[derive(clap::ValueEnum, Debug, Clone, Default)]
pub enum ColorOutput {
    #[default]
    Auto,
    Always,
    Never,
}

impl Display for ColorOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ColorOutput::Auto => "auto",
            ColorOutput::Always => "always",
            ColorOutput::Never => "never",
        };
        write!(f, "{}", str)
    }
}

/// Configures exporter of span and trace data.
#[derive(Debug, Default, clap::Parser)]
pub struct Options {
    /// Enables export of span data using opentelemetry exporters.
    #[clap(long, value_enum, default_value = "off")]
    opentelemetry: OpenTelemetryLevel,

    /// Opentelemetry gRPC collector endpoint.
    #[clap(long, default_value = "http://localhost:4317")]
    otlp_endpoint: String,

    /// Whether the log needs to be colored.
    #[clap(long, value_enum, default_value = "auto")]
    color: ColorOutput,

    /// Enable logging of spans. For instance, this prints timestamps of entering and exiting a span,
    /// together with the span duration and used/idle CPU time.
    #[clap(long)]
    log_span_events: bool,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut buf = vec![
            "--opentelemetry".to_string(),
            self.opentelemetry.to_string(),
            "--otlp-endpoint".to_string(),
            self.otlp_endpoint,
            "--color".to_string(),
            self.color.to_string(),
        ];
        if self.log_span_events {
            buf.push("--log-span-events".to_string());
        }
        buf
    }
}

fn use_color_output(options: &Options) -> bool {
    fn use_color_auto() -> bool {
        std::env::var_os("NO_COLOR").is_none() && is_terminal()
    }

    fn is_terminal() -> bool {
        // Crate `atty` provides a platform-independent way of checking whether the output is a tty.
        atty::is(atty::Stream::Stderr)
    }

    match options.color {
        ColorOutput::Auto => use_color_auto(),
        ColorOutput::Always => true,
        ColorOutput::Never => false,
    }
}

fn get_fmt_span(with_span_events: bool) -> fmt::format::FmtSpan {
    if with_span_events {
        fmt::format::FmtSpan::ENTER | fmt::format::FmtSpan::CLOSE
    } else {
        fmt::format::FmtSpan::NONE
    }
}

fn add_non_blocking_log_layer<S>(
    filter: EnvFilter,
    writer: NonBlocking,
    ansi: bool,
    with_span_events: bool,
    subscriber: S,
) -> (LogLayer<S>, reload::Handle<EnvFilter, S>)
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span> + Send + Sync,
{
    let (filter, handle) = reload::Layer::<EnvFilter, S>::new(filter);

    let layer = fmt::layer()
        .with_ansi(ansi)
        .with_span_events(get_fmt_span(with_span_events))
        .with_writer(writer)
        .with_line_number(true)
        .with_thread_names(true)
        .with_filter(filter);

    (subscriber.with(layer), handle)
}

/// Constructs an OpenTelemetryConfig which sends span data to an external collector.
async fn add_opentelemetry_layer<S>(
    opentelemetry_level: OpenTelemetryLevel,
    otlp_endpoint: &str,
    env: String,
    node_id: String,
    subscriber: S,
) -> (TracingLayer<S>, reload::Handle<LevelFilter, S>)
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span> + Send + Sync,
{
    let filter = match opentelemetry_level {
        OpenTelemetryLevel::OFF => LevelFilter::OFF,
        OpenTelemetryLevel::INFO => LevelFilter::INFO,
        OpenTelemetryLevel::DEBUG => LevelFilter::DEBUG,
        OpenTelemetryLevel::TRACE => LevelFilter::TRACE,
    };
    let (filter, handle) = reload::Layer::<LevelFilter, S>::new(filter);

    let resource = vec![
        KeyValue::new(SERVICE_NAME, format!("mpc:{}", node_id)),
        KeyValue::new("env", env),
        KeyValue::new("node_id", node_id),
    ];

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint),
        )
        .with_trace_config(
            trace::config()
                .with_sampler(Sampler::AlwaysOn)
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(Resource::new(resource)),
        )
        .install_batch(opentelemetry::runtime::Tokio)
        .unwrap();
    let layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(filter);
    (subscriber.with(layer), handle)
}

fn set_default_otlp_level(options: &Options) {
    // Record the initial tracing level specified as a command-line flag. Use this recorded value to
    // reset opentelemetry filter when the LogConfig file gets deleted.
    DEFAULT_OTLP_LEVEL.set(options.opentelemetry).unwrap();
}

/// The resource representing a registered subscriber.
///
/// Once dropped, the subscriber is unregistered, and the output is flushed. Any messages output
/// after this value is dropped will be delivered to a previously active subscriber, if any.
pub struct DefaultSubscriberGuard<S> {
    // NB: the field order matters here. We must first drop the `local_subscriber_guard` so that
    // no new messages are delivered to this subscriber while we take care of flushing the
    // messages already in queue. If dropped the other way around, the events/spans generated
    // while the subscriber drop guard runs would be lost.
    subscriber: Option<S>,
    local_subscriber_guard: Option<DefaultGuard>,
    #[allow(dead_code)] // This field is never read, but has semantic purpose as a drop guard.
    writer_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl<S: tracing::Subscriber + Send + Sync> DefaultSubscriberGuard<S> {
    /// Register this default subscriber globally , for all threads.
    ///
    /// Must not be called more than once. Mutually exclusive with `Self::local`.
    pub fn global(mut self) -> Self {
        if let Some(subscriber) = self.subscriber.take() {
            tracing::subscriber::set_global_default(subscriber)
                .expect("could not set a global subscriber");
        } else {
            panic!("trying to set a default subscriber that has been already taken")
        }
        self
    }

    /// Register this default subscriber for the current thread.
    ///
    /// Must not be called more than once. Mutually exclusive with `Self::global`.
    pub fn local(mut self) -> Self {
        if let Some(subscriber) = self.subscriber.take() {
            self.local_subscriber_guard = Some(tracing::subscriber::set_default(subscriber));
        } else {
            panic!("trying to set a default subscriber that has been already taken")
        }
        self
    }
}

pub async fn default_subscriber_with_opentelemetry(
    env_filter: EnvFilter,
    options: &Options,
    env: String,
    node_id: String,
) -> DefaultSubscriberGuard<impl tracing::Subscriber + Send + Sync> {
    let color_output = use_color_output(options);

    // Do not lock the `stderr` here to allow for things like `dbg!()` work during development.
    let stderr = std::io::stderr();
    let lined_stderr = std::io::LineWriter::new(stderr);
    let (writer, writer_guard) = tracing_appender::non_blocking(lined_stderr);

    let subscriber = tracing_subscriber::registry();

    set_default_otlp_level(options);

    let (subscriber, handle) = add_non_blocking_log_layer(
        env_filter,
        writer,
        color_output,
        options.log_span_events,
        subscriber,
    );
    LOG_LAYER_RELOAD_HANDLE
        .set(handle)
        .unwrap_or_else(|_| panic!("Failed to set Log Layer Filter"));

    let (subscriber, handle) = add_opentelemetry_layer(
        options.opentelemetry,
        &options.otlp_endpoint,
        env,
        node_id,
        subscriber,
    )
    .await;
    OTLP_LAYER_RELOAD_HANDLE
        .set(handle)
        .unwrap_or_else(|_| panic!("Failed to set OTLP Layer Filter"));

    DefaultSubscriberGuard {
        subscriber: Some(subscriber),
        local_subscriber_guard: None,
        writer_guard: Some(writer_guard),
    }
}

pub enum FeatureGuard<S> {
    Noop,
    Default(DefaultSubscriberGuard<S>),
}

pub async fn subscribe_global(
    env_filter: EnvFilter,
    options: &Options,
    env: String,
    node_id: String,
) -> FeatureGuard<impl tracing::Subscriber + Send + Sync> {
    if cfg!(feature = "disable-open-telemetry") {
        FeatureGuard::Noop
    } else {
        let subscriber_guard =
            default_subscriber_with_opentelemetry(env_filter, options, env, node_id)
                .await
                .global();

        FeatureGuard::Default(subscriber_guard)
    }
}
