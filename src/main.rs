use crate::DmarcPolicy::{NotFound, Quarantine, Reject};
use addr::email::Host;
use addr::parse_email_address;
use clap::Parser;
use colored::Colorize;
use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::ops::AddAssign;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use strum::Display;
use tokio::io::{
    stdout, AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter, Lines,
};
use tokio::sync::mpsc;
use tokio::task::{id, JoinSet};
use tokio::{fs, io, spawn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;
use whirlwind::ShardMap;

type Pool = VecDeque<mpsc::Sender<(usize, Arc<str>)>>;

static MX_CACHE: LazyLock<ShardMap<Arc<str>, DmarcPolicy>> = LazyLock::new(ShardMap::new);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// File input containing email addresses
    #[arg(short, long)]
    input: PathBuf,
    /// Output directory to write results
    #[arg(short, long)]
    directory: PathBuf,
    /// Number of threads to use
    #[arg(short, long)]
    thread: u32,
    #[arg(short, long, default_value = "1024")]
    buffer: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!(
        "{} v{}",
        "Dmarc Scanner".green(),
        env!("CARGO_PKG_VERSION").green()
    );
    _ = &*MX_CACHE; // Initialize the cache

    println!("{}", "Initializing...".green());

    let mut args = Args::parse();
    if args.buffer == 0 {
        args.buffer = 1
    }

    if !args.input.exists() {
        eprintln!("Input file does not exist");
        return Ok(());
    }

    if !args.directory.is_dir() || !args.directory.exists() {
        eprintln!("Output directory does not exist");
        return Ok(());
    }

    println!("Setting up buffered writer");
    let none_buffer = open_w(args.directory.join("none.txt")).await?;
    let bad_buffer = open_w(args.directory.join("bad.txt")).await?;
    let notfound_buffer = open_w(args.directory.join("notfound.txt")).await?;

    let (writer_tx, writer_rx) = mpsc::channel::<(usize, DmarcPolicy, Arc<str>)>(args.buffer);
    let writer_handle = spawn(writer_handle(
        writer_rx,
        BufWriter::new(bad_buffer),
        BufWriter::new(none_buffer),
        BufWriter::new(notfound_buffer),
    ));
    println!("Writer initialized");

    let (mut worker_handles, mut pools) = (JoinSet::new(), VecDeque::new());
    println!("Setting up worker threads");
    for _ in 0..args.thread {
        let (tx, rx) = mpsc::channel::<(usize, Arc<str>)>(1);
        pools.push_back(tx);
        worker_handles.spawn(worker_function(rx, writer_tx.clone()));
    }
    println!("Workers initialized");

    let reader = open_r(args.input).await.map(BufReader::new)?.lines();
    start_dispatch(pools, reader).await;

    println!("Waiting background tasks to finish");

    for h in worker_handles.join_all().await {
        h?;
    }

    writer_handle.await??;

    Ok(())
}

pub async fn count_lines(lines: &mut Lines<BufReader<fs::File>>) -> io::Result<usize> {
    let mut i = 0;
    while lines.next_line().await?.is_some() {
        i += 1;
    }

    lines.get_mut().rewind().await.map(|_| i)
}

pub async fn start_dispatch(mut pools: Pool, mut lines: Lines<BufReader<fs::File>>) {
    let mut stdout = stdout();

    let total_lines = count_lines(&mut lines).await.unwrap();
    let mut index = 0;

    while let Some(line) = lines.next_line().await.unwrap() {
        index.add_assign(1);

        match send_seqcst(pools, (index, line.trim().to_lowercase().into())).await {
            Ok(pool) => pools = pool,
            Err(_) => {
                eprintln!("No available threads to process the line");
                break;
            }
        }

        let pct = (index as f64) * 100.0 / (total_lines as f64);
        let pct_str = if pct < 25.0 {
            format!("{pct:.2}%").red()
        } else if pct < 50.0 {
            format!("{pct:.2}%").yellow()
        } else if pct < 75.0 {
            format!("{pct:.2}%").blue()
        } else {
            format!("{pct:.2}%").green()
        };
        _ = stdout.write_all(format!("{pct_str}\r").as_bytes()).await;
    }

    stdout.flush().await.unwrap()
}

async fn open_r(path: impl AsRef<Path>) -> io::Result<fs::File> {
    fs::File::options().read(true).open(path).await
}

async fn open_w(path: impl AsRef<Path>) -> io::Result<fs::File> {
    fs::File::options()
        .create(true)
        .append(true)
        .open(path)
        .await
}

async fn worker_function(
    mut worker_rx: mpsc::Receiver<(usize, Arc<str>)>,
    writer_tx: mpsc::Sender<(usize, DmarcPolicy, Arc<str>)>,
) -> anyhow::Result<()> {
    while let Some((index, email)) = worker_rx.recv().await {
        let address = match parse_email_address(email.as_ref()) {
            Ok(addr) => addr,
            Err(err) => {
                eprintln!("{email}: {err}");
                continue;
            }
        };

        let Host::Domain(name) = address.host() else {
            continue;
        };

        let domain: Arc<str> = Arc::from(name.as_str());
        let dmarc_cache = if let Some(cache) = MX_CACHE.get(&domain).await {
            cache.clone()
        } else {
            let dmarc = DmarcPolicy::scan(&domain).await;
            MX_CACHE.insert(domain, dmarc.clone()).await;
            dmarc
        };

        if writer_tx.send((index, dmarc_cache, email)).await.is_err() {
            eprintln!("Failed to send data to writer");
            drop(writer_tx);
            break;
        }
    }

    println!("Worker #{:?} finished processing", id());
    Ok(())
}

async fn writer_handle(
    mut writer_rx: mpsc::Receiver<(usize, DmarcPolicy, Arc<str>)>,
    mut bad_buffer: BufWriter<fs::File>,
    mut none_buffer: BufWriter<fs::File>,
    mut notfound_buffer: BufWriter<fs::File>,
) -> io::Result<()> {
    while let Some((idx, dmarc, data)) = writer_rx.recv().await {
        println!("[{idx}] {data} ->  {dmarc:?}");

        match dmarc {
            Reject | Quarantine => {
                bad_buffer.write_all(data.as_bytes()).await?;
                bad_buffer.write_all(b"\n").await?
            }
            NotFound => {
                notfound_buffer.write_all(data.as_bytes()).await?;
                notfound_buffer.write_all(b"\n").await?
            }
            DmarcPolicy::None => {
                none_buffer.write_all(data.as_bytes()).await?;
                none_buffer.write_all(b"\n").await?
            }
        }
    }

    println!("All data processed");
    Ok(())
}

async fn send_seqcst(
    mut pool: Pool,
    mut data: (usize, Arc<str>),
) -> Result<Pool, (usize, Arc<str>)> {
    let time = Duration::from_millis(1);

    while !pool.is_empty() {
        pool.retain(|x| !x.is_closed());
        let Some(tx) = pool.pop_front() else { continue };

        let status = tx.send_timeout(data, time).await;
        pool.push_back(tx);

        match status {
            Ok(_) => return Ok(pool),
            Err(timeout) => data = timeout.into_inner(),
        }
    }

    Err(data)
}

async fn lookup<N: AsRef<str>>(name: N, rtype: RecordType) -> Result<Lookup, ResolveError> {
    let rt = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    rt.lookup(name.as_ref(), rtype).await
}

#[derive(Display, Clone, PartialEq, Eq, Hash)]
enum DmarcPolicy {
    #[strum(to_string = "Reject")]
    Reject,
    #[strum(to_string = "Quarantine")]
    Quarantine,
    #[strum(to_string = "Not Found")]
    NotFound,
    #[strum(to_string = "None")]
    None,
}

impl DmarcPolicy {
    fn first_record(lookup: &Lookup) -> Self {
        let Some(rdata) = lookup.records().first() else {
            return NotFound;
        };

        Self::from_str(&rdata.to_string()).unwrap_or(NotFound)
    }

    async fn scan<S: AsRef<str>>(s: S) -> Self {
        use DmarcPolicy::*;
        if let Ok(lookup) = lookup(format!("_dmarc.{}", s.as_ref()), RecordType::TXT).await {
            if let policy @ (Reject | Quarantine | None) = Self::first_record(&lookup) {
                return policy;
            }
        }

        let Ok(fqdn) = addr::parse_domain_name(s.as_ref()) else {
            return NotFound;
        };
        if fqdn.prefix().is_none() {
            return NotFound;
        }

        let Some(root) = fqdn.root() else {
            return NotFound;
        };

        let root = format!("_dmarc.{root}");
        let Ok(lookup) = lookup(root, RecordType::TXT).await else {
            return NotFound;
        };

        Self::first_record(&lookup)
    }
}

impl Debug for DmarcPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use DmarcPolicy::*;
        match *self {
            ref variants @ (Reject | Quarantine) => {
                f.write_str(&variants.to_string().red().to_string())
            }
            None => f.write_str(&"None".green().to_string()),
            NotFound => f.write_str(&"NotFound".yellow().to_string()),
        }
    }
}

impl FromStr for DmarcPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let full = s.to_lowercase();
        if full.contains("p=reject") {
            Ok(Reject)
        } else if full.contains("p=quarantine") {
            Ok(Quarantine)
        } else if full.contains("p=none") {
            Ok(DmarcPolicy::None)
        } else {
            Err(())
        }
    }
}
