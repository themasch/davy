use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod authentication;
mod commands;
mod config;
mod server;

use commands::*;

#[derive(Debug, Parser)]
struct AppCommandLine {
    #[arg(long)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server(ServerConfig),
    #[cfg(feature = "tools")]
    EncryptPassword,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = AppCommandLine::parse();
    let config = config::load_config(cli.config);

    match cli.command {
        Command::Server(server_config) => start_server(config, server_config).await,
        #[cfg(feature = "tools")]
        Command::EncryptPassword => encrypt_password().await,
    };
}
