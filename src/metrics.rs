use color_eyre::eyre::{Context, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Initialize the Prometheus metrics recorder.
///
/// This spawns a background task that serves metrics at the given address.
pub fn init(addr: SocketAddr) -> Result<()> {
    let builder = PrometheusBuilder::new();
    builder
        .with_http_listener(addr)
        .install()
        .wrap_err("failed to install Prometheus recorder")?;

    tracing::info!("Metrics endpoints listening on http://{}/metrics", addr);

    Ok(())
}
