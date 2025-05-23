use crate::DmarcPolicy::{NotFound, Quarantine, Reject};
use addr::email::Host;
use addr::parse_email_address;
use clap::Parser;
use colored::Colorize;
use dashmap::{DashMap, Entry};
use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::ops::AddAssign;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use strum::Display;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::{fs, io};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

type Pool = VecDeque<mpsc::Sender<(usize, Arc<str>)>>;

static MX_CACHE: LazyLock<DashMap<Arc<str>, DmarcPolicy>> = LazyLock::new(Default::default);

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
    _ = &*MX_CACHE; // Initialize the cache

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

    let none_buffer = open_w(args.directory.join("none.txt")).await?;
    let bad_buffer = open_w(args.directory.join("bad.txt")).await?;
    let notfound_buffer = open_w(args.directory.join("notfound.txt")).await?;

    let (writer_tx, writer_rx) = mpsc::channel::<(usize, DmarcPolicy, Arc<str>)>(args.buffer);
    let writer_handle = tokio::spawn(writer_handle(
        writer_rx,
        BufWriter::new(bad_buffer),
        BufWriter::new(none_buffer),
        BufWriter::new(notfound_buffer),
    ));

    let (worker_handles, pools) = (0..args.thread)
        .map(|_| {
            let (tx, rx) = mpsc::channel::<(usize, Arc<str>)>(1);

            let handle: JoinHandle<anyhow::Result<()>> =
                tokio::spawn(worker_function(rx, writer_tx.clone()));
            (handle, tx)
        })
        .collect::<(Vec<_>, VecDeque<_>)>();

    reader_handle(args.input, pools).await?;

    for worker_handle in worker_handles {
        worker_handle.await??;
    }

    writer_handle.await??;

    Ok(())
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

        let dmarc_cache = *match MX_CACHE.entry(Arc::from(name.as_str())) {
            Entry::Occupied(e) => e.into_ref(),
            Entry::Vacant(e) => e.insert(DmarcPolicy::scan(name.as_str()).await),
        }
        .value();

        if writer_tx.send((index, dmarc_cache, email)).await.is_err() {
            eprintln!("Failed to send data to writer");
            break;
        }
    }

    Ok(())
}

async fn reader_handle(input: impl AsRef<Path>, mut pools: Pool) -> io::Result<()> {
    let mut reader = open_r(input).await.map(BufReader::new)?.lines();
    let mut index = 0;

    while let Some(line) = reader.next_line().await? {
        index.add_assign(1);
        match send_seqcst(pools, (index, line.into())).await {
            Ok(pool) => pools = pool,
            Err(_) => return Err(io::Error::other("No available threads to process the line")),
        }
    }

    Ok(())
}

async fn writer_handle(
    mut writer_rx: mpsc::Receiver<(usize, DmarcPolicy, Arc<str>)>,
    mut bad_buffer: BufWriter<fs::File>,
    mut none_buffer: BufWriter<fs::File>,
    mut notfound_buffer: BufWriter<fs::File>,
) -> io::Result<()> {
    while let Some((idx, dmarc, data)) = writer_rx.recv().await {
        println!("[{idx}] {data} ->  {dmarc:?}\n");

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

    Ok(())
}

async fn lookup<N: AsRef<str>>(name: N, rtype: RecordType) -> Result<Lookup, ResolveError> {
    let rt = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    rt.lookup(name.as_ref(), rtype).await
}

async fn send_seqcst(
    mut pool: Pool,
    mut data: (usize, Arc<str>),
) -> Result<Pool, (usize, Arc<str>)> {
    loop {
        pool.retain(|x| !x.is_closed());

        if let Some(tx) = pool.pop_back() {
            match tx.send_timeout(data, Duration::from_millis(25)).await {
                Ok(_) => {
                    pool.push_back(tx);
                    break Ok(pool);
                }
                Err(timeout) => {
                    data = timeout.into_inner();
                    continue;
                }
            }
        }

        break Err(data);
    }
}

#[derive(Display, Clone, Copy, PartialEq, Eq, Hash)]
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
            variants @ (Reject | Quarantine) => {
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
