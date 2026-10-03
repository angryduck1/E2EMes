use std::{fs, path::PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use e2emes_proto::transport::StaticKeypair;
use e2emes_server::{serve, Config};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "E2EMes server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the server's static key pair.
    GenKey {
        /// Where to write the private key (keep it secret).
        #[arg(long, default_value = "server.key")]
        key: PathBuf,
        /// Where to write the public key that clients need.
        #[arg(long, default_value = "server.pub")]
        public: PathBuf,
    },
    /// Run the server.
    Serve {
        #[arg(long, default_value = "0.0.0.0:8088")]
        listen: String,
        /// SQLite database file (created if missing).
        #[arg(long, default_value = "e2emes.db")]
        db: String,
        #[arg(long, default_value = "server.key")]
        key: PathBuf,
    },
}

fn write_secret(path: &PathBuf, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

fn load_key(path: &PathBuf) -> anyhow::Result<[u8; 32]> {
    let text = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("reading {} (run `e2emes-server gen-key` first)", path.display()))?,
    );
    let mut key = [0u8; 32];
    if hex::decode_to_slice(text.trim(), &mut key).is_err() {
        bail!("{} must contain a 32-byte key in hex", path.display());
    }
    Ok(key)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    match Cli::parse().command {
        Command::GenKey { key, public } => {
            if key.exists() {
                bail!("{} already exists; refusing to overwrite the server key", key.display());
            }
            let pair = StaticKeypair::generate()?;
            write_secret(&key, &hex::encode(pair.private))?;
            fs::write(&public, hex::encode(pair.public))?;
            println!("private key: {}", key.display());
            println!("public key:  {} ({})", public.display(), hex::encode(pair.public));
            println!("Give {} to clients.", public.display());
        }
        Command::Serve { listen, db, key } => {
            let private_key = load_key(&key)?;
            let listener = TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            serve(
                listener,
                Config {
                    db_path: db,
                    private_key,
                },
            )
            .await?;
        }
    }
    Ok(())
}
