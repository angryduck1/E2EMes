use std::{
    fs,
    io::IsTerminal,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context};
use clap::Parser;
use e2emes_client::{connect, AccountVault, Decrypted, Messenger, Notice, Store};
use e2emes_proto::{ErrorCode, MIN_PASSWORD_LEN};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "E2EMes console client")]
struct Cli {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:8088")]
    server: String,
    /// The server's public key: a 64-character hex string or a file containing it.
    #[arg(long, default_value = "server.pub")]
    server_key: String,
    /// Directory for the account vault and the local message history.
    #[arg(long, default_value = "e2emes-data")]
    data_dir: PathBuf,
}

const HELP: &str = "\
Commands:
  /chats                 list chats, pending requests and who is online
  /chat <name>           ask <name> to start a chat
  /accept <name>         accept a chat request    /reject <name>   decline it
  /msg <name> <text>     send an end-to-end encrypted message
  /history <name> [n]    show the last n messages (default 20)
  /verify <name>         compare safety numbers with <name> and mark them verified
  /trust <name>          accept a changed identity key of <name>
  /whoami                show your name
  /logout                revoke this device's session and forget the account
  /quit                  exit";

/// Reads all user input from one place, so prompts and commands never race for stdin.
struct Input {
    lines: Lines<BufReader<Stdin>>,
    tty: bool,
}

impl Input {
    fn new() -> Self {
        Self {
            lines: BufReader::new(tokio::io::stdin()).lines(),
            tty: std::io::stdin().is_terminal(),
        }
    }

    async fn line(&mut self) -> anyhow::Result<Option<String>> {
        Ok(self.lines.next_line().await?)
    }

    async fn prompt(&mut self, text: &str) -> anyhow::Result<String> {
        println!("{text}");
        match self.line().await? {
            Some(line) => Ok(line.trim().to_owned()),
            None => bail!("input closed"),
        }
    }

    /// Reads a password without echo when attached to a terminal.
    async fn password(&mut self, text: &str) -> anyhow::Result<Zeroizing<String>> {
        if self.tty {
            let text = text.to_owned();
            let pw = tokio::task::spawn_blocking(move || rpassword::prompt_password(text)).await??;
            Ok(Zeroizing::new(pw))
        } else {
            Ok(Zeroizing::new(self.prompt(text).await?))
        }
    }

    async fn new_password(&mut self, what: &str) -> anyhow::Result<Zeroizing<String>> {
        loop {
            let pw = self
                .password(&format!("{what} (at least {MIN_PASSWORD_LEN} characters):"))
                .await?;
            if pw.chars().count() < MIN_PASSWORD_LEN {
                println!("Too short.");
                continue;
            }
            let again = self.password("Repeat it:").await?;
            if *pw != *again {
                println!("Passwords don't match.");
                continue;
            }
            return Ok(pw);
        }
    }
}

fn server_key(arg: &str) -> anyhow::Result<[u8; 32]> {
    let text = if arg.len() == 64 && arg.bytes().all(|b| b.is_ascii_hexdigit()) {
        arg.to_owned()
    } else {
        fs::read_to_string(arg).with_context(|| format!("reading the server public key from {arg}"))?
    };
    let mut key = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut key).context("the server public key must be 64 hex characters")?;
    Ok(key)
}

/// `YYYY-MM-DD HH:MM` in UTC.
fn format_time(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Civil-from-days, see http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60
    )
}

fn print_message(me: &str, m: &Decrypted) {
    let direction = if m.from.eq_ignore_ascii_case(me) {
        format!("you -> {}", m.to)
    } else {
        m.from.clone()
    };
    match &m.text {
        Ok(text) => println!("[{} UTC] {direction}: {text}", format_time(m.timestamp)),
        Err(reason) => println!("[{} UTC] {direction}: <{reason}>", format_time(m.timestamp)),
    }
}

async fn open_account(
    input: &mut Input,
    cli: &Cli,
    vault_path: &Path,
) -> anyhow::Result<(Messenger, tokio::sync::mpsc::UnboundedReceiver<e2emes_proto::Event>)> {
    let key = server_key(&cli.server_key)?;
    let (conn, events) = connect(&cli.server, &key).await?;
    let store = Store::open(&cli.data_dir.join("messages.db"))?;

    if vault_path.exists() {
        let (vault, local_pw) = loop {
            let pw = input.password("Local password:").await?;
            match AccountVault::load(vault_path, &pw) {
                Ok(vault) => break (vault, pw),
                Err(e) => println!("{e}"),
            }
        };
        match Messenger::resume(conn.clone(), store, &vault.token, &vault.phrase).await {
            Ok((messenger, _)) => return Ok((messenger, events)),
            Err(e) if e.api_code() == Some(ErrorCode::Unauthorized) => {
                println!("Your session has expired. Log in again as {}.", vault.name);
            }
            Err(e) => return Err(e.into()),
        }
        let store = Store::open(&cli.data_dir.join("messages.db"))?;
        let password = input.password("Account password:").await?;
        let (messenger, token) = Messenger::login(conn, store, &vault.name, &password, &vault.phrase).await?;
        AccountVault {
            name: vault.name.clone(),
            token,
            phrase: vault.phrase.clone(),
        }
        .save(vault_path, &local_pw)?;
        return Ok((messenger, events));
    }

    let choice = input
        .prompt("No account on this device. [r]egister a new one or [l]og in to an existing one?")
        .await?;
    let (messenger, token, phrase) = match choice.as_str() {
        "r" | "register" => {
            let name = input
                .prompt("Choose a name (3-32 characters: letters, digits, _ or -):")
                .await?;
            let password = input.new_password("Account password").await?;
            let (messenger, token, phrase) = Messenger::register(conn, store, &name, &password).await?;
            println!();
            println!("Your recovery phrase:");
            println!();
            println!("    {}", phrase.as_str());
            println!();
            println!("Write it down and keep it safe. It is the only way to restore your");
            println!("identity key, and with it your messages, on another device.");
            println!();
            (messenger, token, phrase)
        }
        "l" | "login" => {
            let name = input.prompt("Name:").await?;
            let password = input.password("Account password:").await?;
            let phrase = Zeroizing::new(input.prompt("Recovery phrase (12 words):").await?);
            let (messenger, token) = Messenger::login(conn, store, &name, &password, &phrase).await?;
            (messenger, token, phrase)
        }
        _ => bail!("unknown choice"),
    };

    let local_pw = input
        .new_password("Local password protecting this device's copy of the account")
        .await?;
    AccountVault {
        name: messenger.name().to_owned(),
        token,
        phrase: phrase.to_string(),
    }
    .save(vault_path, &local_pw)?;
    Ok((messenger, events))
}

async fn print_chats(messenger: &Messenger) -> anyhow::Result<()> {
    let list = messenger.chats().await?;
    if list.chats.is_empty() && list.incoming.is_empty() && list.outgoing.is_empty() {
        println!("No chats yet. Start one with /chat <name>.");
    }
    for chat in &list.chats {
        let mark = match messenger.peer(&chat.name)? {
            Some(p) if p.changed_key.is_some() => " [KEY CHANGED]",
            Some(p) if p.verified => " [verified]",
            _ => "",
        };
        let status = if chat.online { "online" } else { "offline" };
        println!("  {} ({status}){mark}", chat.name);
    }
    for user in &list.incoming {
        println!("  {} wants to chat: /accept {0} or /reject {0}", user.name);
    }
    for name in &list.outgoing {
        println!("  waiting for {name} to accept your request");
    }
    Ok(())
}

/// Returns `false` when the client should exit.
async fn command(messenger: &Messenger, input: &mut Input, line: &str, vault_path: &Path) -> anyhow::Result<bool> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(true);
    }
    let (cmd, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let rest = rest.trim();
    let mut args = rest.split_whitespace();

    match cmd {
        "/help" => println!("{HELP}"),
        "/quit" | "/exit" => return Ok(false),
        "/whoami" => println!("You are {}.", messenger.name()),
        "/chats" => print_chats(messenger).await?,
        "/chat" => {
            let Some(name) = args.next() else {
                bail!("usage: /chat <name>");
            };
            let (name, open) = messenger.request_chat(name).await?;
            if open {
                println!("Chat with {name} is open.");
            } else {
                println!("Request sent; {name} needs to accept it.");
            }
        }
        "/accept" | "/reject" => {
            let Some(name) = args.next() else {
                bail!("usage: {cmd} <name>");
            };
            let accept = cmd == "/accept";
            let name = messenger.respond_chat(name, accept).await?;
            if accept {
                println!("Chat with {name} is open. Check safety numbers with /verify {name}.");
            } else {
                println!("Declined the request from {name}.");
            }
        }
        "/msg" => {
            let Some((name, text)) = rest.split_once(char::is_whitespace) else {
                bail!("usage: /msg <name> <text>");
            };
            let sent = messenger.send(name, text.trim()).await?;
            print_message(messenger.name(), &sent);
        }
        "/history" => {
            let Some(name) = args.next() else {
                bail!("usage: /history <name> [n]");
            };
            let limit = args
                .next()
                .map(str::parse)
                .transpose()
                .context("n must be a number")?
                .unwrap_or(20);
            let messages = messenger.history(name, limit)?;
            if messages.is_empty() {
                println!("No messages with {name}.");
            }
            for m in &messages {
                print_message(messenger.name(), m);
            }
        }
        "/verify" => {
            let Some(name) = args.next() else {
                bail!("usage: /verify <name>");
            };
            let Some(number) = messenger.safety_number(name)? else {
                bail!("no key known for {name}; open a chat first");
            };
            println!("Safety number with {name}:\n\n    {number}\n");
            println!("Compare it with {name} in person or over a call. Type 'yes' if it matches.");
            if input.line().await?.as_deref().map(str::trim) == Some("yes") {
                messenger.mark_verified(name)?;
                println!("{name} is verified.");
            } else {
                println!("Not marked as verified.");
            }
        }
        "/trust" => {
            let Some(name) = args.next() else {
                bail!("usage: /trust <name>");
            };
            if messenger.accept_changed_key(name)? {
                println!("Accepted the new key of {name}. Verify it with /verify {name}.");
            } else {
                println!("The key of {name} has not changed.");
            }
        }
        "/logout" => {
            messenger.logout().await?;
            fs::remove_file(vault_path)?;
            println!("Logged out. The local message history is kept in the data directory.");
            return Ok(false);
        }
        _ => println!("Unknown command. Type /help."),
    }
    Ok(true)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(&cli.data_dir).with_context(|| format!("creating {}", cli.data_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cli.data_dir, fs::Permissions::from_mode(0o700))?;
    }
    let vault_path = cli.data_dir.join("account.vault");

    let mut input = Input::new();
    let (messenger, mut events) = open_account(&mut input, &cli, &vault_path).await?;
    println!("Logged in as {}.", messenger.name());

    for m in messenger.sync().await? {
        print_message(messenger.name(), &m);
    }
    print_chats(&messenger).await?;
    println!("Type /help for commands.");

    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.tick().await;
    loop {
        tokio::select! {
            line = input.line() => {
                let Some(line) = line? else { break };
                match command(&messenger, &mut input, &line, &vault_path).await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => println!("Error: {e:#}"),
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    println!("Disconnected from the server.");
                    break;
                };
                match messenger.handle_event(event).await {
                    Ok(Notice::Message(m)) => print_message(messenger.name(), &m),
                    Ok(Notice::ChatRequest { name }) => println!("{name} wants to chat: /accept {name} or /reject {name}"),
                    Ok(Notice::ChatAccepted { name }) => println!("{name} accepted your chat request."),
                    Ok(Notice::Presence { name, online }) => println!("{name} is {}.", if online { "online" } else { "offline" }),
                    Ok(Notice::Nothing) => {}
                    Err(e) => println!("Error: {e:#}"),
                }
            }
            _ = ping.tick() => {
                if let Err(e) = messenger.ping().await {
                    println!("Error: {e:#}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::format_time;

    #[test]
    fn time_formatting() {
        assert_eq!(format_time(0), "1970-01-01 00:00");
        assert_eq!(format_time(1_790_985_600 + 3_660), "2026-10-03 01:01");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00");
    }
}
