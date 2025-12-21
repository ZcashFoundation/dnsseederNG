use color_eyre::eyre::Result;

pub mod config;
pub mod commands;
pub mod server;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    commands::SeederApp::run().await
}
