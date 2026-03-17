#[cfg(not(target_arch = "wasm32"))]
#[path = "../hash_tree.rs"]
mod hash_tree;

#[cfg(not(target_arch = "wasm32"))]
mod cli_impl {
use super::hash_tree::{HashTree, Label, LookupResult};
use anyhow::{Context, Result};
use candid::{CandidType, Deserialize, Principal};
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use ic_agent::{export::Principal as AgentPrincipal, Agent};
use ic_utils::{call::SyncCall, canister::CanisterBuilder, Canister};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;



use ic_certificate_verification::VerifyCertificate;
use ic_certification::Certificate;
use ic_cbor::CertificateToCbor;
use std::time::{SystemTime, UNIX_EPOCH};

// We parse the exact same structure as the replica certificate
#[allow(dead_code)]
#[derive(Deserialize)]
struct ReplicaCertificate<'a> {
    #[serde(borrow)]
    tree: HashTree<'a>,
    signature: serde_bytes::ByteBuf,
}

// ── Candid Block type (must match src/main.rs Block struct) ─────────────────
#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
struct Block {
    certificate: Vec<u8>,
    tree: Vec<u8>,
    data: Vec<Vec<u8>>,
    callers: Vec<Principal>,
    previous_hash: [u8; 32],
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Authorization {
    id: Principal,
    auth: Auth,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq)]
enum Auth {
    User,
    Admin,
}

// ── Snapshot Serialization ───────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SnapBlock {
    index: u64,
    certificate: String,
    tree: String,
    data: Vec<String>,
    callers: Vec<String>,
    previous_hash: String,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    #[serde(rename = "canisterId")]
    canister_id: String,
    #[serde(rename = "rootKey")]
    root_key: String,
    network: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    first: u64,
    next: u64,
    blocks: Vec<SnapBlock>,
}

fn snap_to_block(snap: &SnapBlock) -> Result<Block> {
    let mut data = Vec::new();
    for d in &snap.data {
        data.push(from_hex(d)?);
    }

    let mut callers = Vec::new();
    for c in &snap.callers {
        callers.push(Principal::from_text(c)?);
    }

    let mut ph = [0u8; 32];
    let ph_vec = from_hex(&snap.previous_hash)?;
    if ph_vec.len() != 32 {
        anyhow::bail!("invalid previous_hash length");
    }
    ph.copy_from_slice(&ph_vec);

    Ok(Block {
        certificate: from_hex(&snap.certificate)?,
        tree: from_hex(&snap.tree)?,
        data,
        callers,
        previous_hash: ph,
    })
}

fn block_to_snap(index: u64, block: &Block) -> SnapBlock {
    SnapBlock {
        index,
        certificate: to_hex(&block.certificate),
        tree: to_hex(&block.tree),
        data: block.data.iter().map(|d| to_hex(d)).collect(),
        callers: block.callers.iter().map(|c| c.to_text()).collect(),
        previous_hash: to_hex(&block.previous_hash),
    }
}

fn fmt_data(data: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(data) {
        if s.chars().all(|c| {
            let n = c as u32;
            n == 0x09 || n == 0x0A || n == 0x0D || (0x20..=0x7E).contains(&n)
        }) {
            return format!("\"{}\"", s.replace('\n', "\\n").replace('\r', "\\r"));
        }
    }

    let hex = to_hex(data);
    let mut trunc = hex.chars().take(32).collect::<String>();
    if data.len() > 16 {
        trunc.push('…');
    }
    format!("<{} bytes 0x{}>", data.len(), trunc)
}

// ── CLI Setup ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "icb",
    about = "ic-certified-blockchain CLI (Rust)",
    version = "0.1.0"
)]
struct Cli {
    #[arg(long, env = "IC_NETWORK", default_value = "http://localhost:8080")]
    network: String,

    #[arg(long, env = "IC_IDENTITY_FILE")]
    identity: Option<String>,

    #[arg(long, env = "IC_CANISTER_ID")]
    canister: Option<String>,

    #[arg(long, env = "IC_PRODUCTION", default_value_t = false)]
    production: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show blockchain status
    Status,
    /// Safely append a block; each arg becomes one blob entry
    Append {
        entries: Vec<String>,
        #[arg(short, long)]
        file: Vec<String>,
        #[arg(short = 'x', long)]
        hex: Vec<String>,
    },
    /// Get and display a block
    Get {
        index: u64,
        #[arg(short, long)]
        verbose: bool,
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        raw: bool,
    },
    /// Find block(s) by data hash
    Find {
        query: String,
        #[arg(short, long)]
        file: bool,
        #[arg(short = 'x', long)]
        hex: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Download blocks to individual JSON files
    Download {
        #[arg(short, long)]
        start: Option<u64>,
        #[arg(short, long)]
        end: Option<u64>,
        #[arg(short, long, default_value = "./blocks")]
        output: String,
    },
    /// Download the blockchain to a single JSON snapshot file
    Snapshot {
        #[arg(short, long)]
        start: Option<u64>,
        #[arg(short, long)]
        end: Option<u64>,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Verify blockchain integrity
    Verify {
        path: Option<String>,
        #[arg(short, long)]
        start: Option<u64>,
        #[arg(short, long)]
        end: Option<u64>,
        #[arg(long)]
        no_chain: bool,
        #[arg(long)]
        root_key: Option<String>,
    },
    /// Rotate the log: primary→secondary, clear old secondary
    Rotate,
    /// Manage authorized principals
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// List authorized principals
    List,
    /// Authorize a principal (default role: User)
    Add {
        principal: String,
        #[arg(long)]
        admin: bool,
    },
    /// Deauthorize a principal
    Remove { principal: String },
}

// ── Utilities ────────────────────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn from_hex(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).context("invalid hex")
}

fn sha256bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn resolve_canister_id(override_id: Option<String>) -> Result<Principal> {
    if let Some(id) = override_id {
        return Principal::from_text(&id).context("Invalid canister ID");
    }
    if let Ok(id) = std::env::var("IC_CANISTER_ID") {
        return Principal::from_text(&id).context("Invalid canister ID in env var");
    }

    let mut dir = std::env::current_dir()?;
    for _ in 0..6 {
        let p = dir.join(".dfx/local/canister_ids.json");
        if p.exists() {
            let content = fs::read_to_string(&p)?;
            let json: serde_json::Value = serde_json::from_str(&content)?;
            if let Some(local_id) = json["ic-certified-blockchain"]["local"].as_str() {
                return Principal::from_text(local_id).context("Invalid local canister ID");
            }
        }
        if !dir.pop() {
            break;
        }
    }
    anyhow::bail!("canister ID not found — set IC_CANISTER_ID in .env or run dfx deploy first")
}
use std::sync::Arc;

fn load_identity(file: Option<String>) -> Result<Option<Arc<dyn ic_agent::Identity>>> {
    let f = match file {
        Some(f) => f,
        None => match std::env::var("IC_IDENTITY_FILE") {
            Ok(f) => f,
            Err(_) => return Ok(None),
        },
    };

    // Resolve path
    let resolved = if let Some(stripped) = f.strip_prefix('~') {
        let home = std::env::var("HOME").unwrap_or_default();
        let stripped = f.strip_prefix("~/").unwrap_or(stripped);
        PathBuf::from(home).join(stripped)
    } else {
        PathBuf::from(f)
    };

    if !resolved.exists()  {
        anyhow::bail!("identity file not found: {}", resolved.display());
    }

    if let Ok(identity) = ic_agent::identity::Secp256k1Identity::from_pem_file(&resolved) {
        return Ok(Some(Arc::new(identity)));
    }

    if let Ok(identity) = ic_agent::identity::BasicIdentity::from_pem_file(&resolved) {
        return Ok(Some(Arc::new(identity)));
    }

    anyhow::bail!("unsupported identity format (expected secp256k1 SEC1 or ed25519) from {:?}", resolved);
}

async fn make_agent(cli: &Cli) -> Result<(Agent, Principal)> {
    let canister_id = resolve_canister_id(cli.canister.clone())?;

    let mut builder = Agent::builder().with_url(&cli.network);

    if let Some(id) = load_identity(cli.identity.clone())? {
        builder = builder.with_arc_identity(id);
    }

    let agent = builder.build()?;

    if !cli.production {
        agent.fetch_root_key().await?;
    }

    Ok((agent, canister_id))
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
pub async fn main() -> Result<()> {
    println!("Starting cli_impl::main");
    // Load .env if present
    let _ = dotenv();
    println!("Parsing args");
    let cli = Cli::parse();
    println!("Running CLI logic");
    run_cli(cli).await
}

async fn run_cli(cli: Cli) -> Result<()> {
    println!("Entering run_cli");
    let (agent, canister_id) = make_agent(&cli).await?;
    let canister = CanisterBuilder::new()
        .with_agent(&agent)
        .with_canister_id(AgentPrincipal::from_slice(canister_id.as_slice()))
        .build()?;

    match &cli.command {
        Commands::Status => {
            let (first,): (u64,) = canister.query("first").build().call().await?;
            let (mid,): (u64,) = canister.query("mid").build().call().await?;
            let (next,): (u64,) = canister.query("next").build().call().await?;
            let (last_hash,): (String,) = canister.query("last_hash").build().call().await?;
            let (staged,): (Option<Vec<u8>>,) =
                canister.query("get_certificate").build().call().await?;
            let (auths,): (Vec<Authorization>,) =
                canister.query("get_authorized").build().call().await?;

            println!("network    : {}", cli.network);
            println!("canister   : {}", canister_id);
            println!("first      : {}", first);
            println!("mid        : {}", mid);
            println!("next       : {}", next);
            println!("blocks     : {}", next.saturating_sub(first));
            println!("last_hash  : {}", last_hash);
            println!(
                "staged     : {}",
                if staged.is_some() {
                    "yes (pending commit)"
                } else {
                    "no"
                }
            );
            println!("authorized : {}", auths.len());

            for a in auths {
                let role = if a.auth == Auth::Admin {
                    "Admin"
                } else {
                    "User"
                };
                println!("  {}  [{}]", a.id.to_text(), role);
            }
        }
        Commands::Get {
            index,
            verbose,
            verify,
            raw,
        } => {
            let (block,): (Block,) = canister
                .query("get_block")
                .with_arg(*index)
                .build()
                .call()
                .await
                .context(format!("get_block({}) failed", index))?;

            if *raw {
                let snap = block_to_snap(*index, &block);
                let json = serde_json::to_string_pretty(&snap)?;
                println!("{}", json);
                return Ok(());
            }

            println!(
                "Block #{}  [{} entr{}]",
                index,
                block.data.len(),
                if block.data.len() == 1 { "y" } else { "ies" }
            );
            println!("  previous_hash : {}", to_hex(&block.previous_hash));
            for (i, data) in block.data.iter().enumerate() {
                let caller = block
                    .callers
                    .get(i)
                    .map(|c| c.to_text())
                    .unwrap_or_default();
                println!("  entry[{}]", i);
                println!("    caller : {}", caller);
                println!("    data   : {}", fmt_data(data));
                if *verbose {
                    println!("    sha256 : {}", to_hex(&sha256bytes(data)));
                }
            }

            if *verbose {
                println!(
                    "  certificate  : {}...",
                    &to_hex(&block.certificate)
                        .chars()
                        .take(64)
                        .collect::<String>()
                );
                println!(
                    "  tree         : {}...",
                    &to_hex(&block.tree).chars().take(64).collect::<String>()
                );
            }

            if *verify {
                let rk = agent.read_root_key();
                match verify_block(&block, canister_id, &rk) {
                    Ok(_) => println!("Verification successful: valid BLS signature and internally consistent."),
                    Err(errors) => {
                        println!("Verification failed:");
                        for err in errors {
                            println!("  ! {}", err);
                        }
                    }
                }
            }
        }
        Commands::Append { entries, file, hex } => {
            let mut blob_entries = Vec::new();
            for t in entries {
                blob_entries.push(t.as_bytes().to_vec());
            }
            for h in hex {
                blob_entries.push(from_hex(h)?);
            }
            for f in file {
                let bytes = fs::read(f).context("file not found")?;
                blob_entries.push(bytes);
            }

            if blob_entries.is_empty() {
                anyhow::bail!("no entries — provide text args, --file <path>, or --hex <hex>");
            }

            let index = safe_append(&canister, blob_entries).await?;
            println!("Block appended at index {}", index);
        }
        Commands::Find {
            query,
            file,
            hex,
            verbose,
        } => {
            let hash = if *hex {
                let h = from_hex(query)?;
                if h.len() != 32 {
                    anyhow::bail!("--hex hash must be 32 bytes (64 hex chars)");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                arr
            } else if *file {
                let bytes = fs::read(query).context("file not found")?;
                sha256bytes(&bytes)
            } else {
                sha256bytes(query.as_bytes())
            };

            let std_hash: [u8; 32] = hash; // Ensure we match the Rust type (Hash is [u8; 32])
            let (result,): (Option<u64>,) = canister
                .query("find")
                .with_arg(std_hash.to_vec())
                .build()
                .call()
                .await?;

            if let Some(index) = result {
                println!("Found at block {}", index);
                if *verbose {
                    let (block,): (Block,) = canister
                        .query("get_block")
                        .with_arg(index)
                        .build()
                        .call()
                        .await
                        .context(format!("get_block({}) failed", index))?;

                    println!(
                        "Block #{}  [{} entr{}]",
                        index,
                        block.data.len(),
                        if block.data.len() == 1 { "y" } else { "ies" }
                    );
                    println!("  previous_hash : {}", to_hex(&block.previous_hash));
                    for (i, data) in block.data.iter().enumerate() {
                        let caller = block
                            .callers
                            .get(i)
                            .map(|c| c.to_text())
                            .unwrap_or_default();
                        println!("  entry[{}]", i);
                        println!("    caller : {}", caller);
                        println!("    data   : <{} bytes>", data.len());
                        println!("    sha256 : {}", to_hex(&sha256bytes(data)));
                    }

                    println!(
                        "  certificate  : {}...",
                        &to_hex(&block.certificate)
                            .chars()
                            .take(64)
                            .collect::<String>()
                    );
                    println!(
                        "  tree         : {}...",
                        &to_hex(&block.tree).chars().take(64).collect::<String>()
                    );
                }
            } else {
                println!("Not found");
            }
        }
        Commands::Download { start, end, output } => {
            let (first,): (u64,) = canister.query("first").build().call().await?;
            let (next,): (u64,) = canister.query("next").build().call().await?;
            if next == first {
                println!("Blockchain is empty.");
                return Ok(());
            }
            let s = start.unwrap_or(first);
            let e = end.unwrap_or(next.saturating_sub(1));

            if s > e {
                anyhow::bail!("start ({}) > end ({})", s, e);
            }
            if s < first {
                anyhow::bail!("start ({}) < first() ({})", s, first);
            }
            if e >= next {
                anyhow::bail!("end ({}) >= next() ({})", e, next);
            }

            fs::create_dir_all(output)?;
            println!("Downloading blocks {}..{} → {}/", s, e, output);

            for i in s..=e {
                let (block,): (Block,) = canister
                    .query("get_block")
                    .with_arg(i)
                    .build()
                    .call()
                    .await
                    .context(format!("get_block({}) failed", i))?;

                // create snapshot representation if we want, currently just dump serialize json
                let snap = SnapBlock {
                    index: i,
                    certificate: to_hex(&block.certificate),
                    tree: to_hex(&block.tree),
                    data: block.data.iter().map(|d| to_hex(d)).collect(),
                    callers: block.callers.iter().map(|c| c.to_text()).collect(),
                    previous_hash: to_hex(&block.previous_hash),
                };

                let file_path = PathBuf::from(output).join(format!("block-{}.json", i));
                fs::write(file_path, serde_json::to_string_pretty(&snap)?)?;
            }
            println!("Downloaded {} block(s) to {}/", e - s + 1, output);
        }
        Commands::Rotate => {
            let (first,): (u64,) = canister.query("first").build().call().await?;
            let (mid,): (u64,) = canister.query("mid").build().call().await?;
            let (next,): (u64,) = canister.query("next").build().call().await?;
            println!("Before: first={} mid={} next={}", first, mid, next);

            let (result,): (Option<u64>,) =
                canister.update("rotate").build().call_and_wait().await?;

            let (first2,): (u64,) = canister.query("first").build().call().await?;
            let (mid2,): (u64,) = canister.query("mid").build().call().await?;
            let (next2,): (u64,) = canister.query("next").build().call().await?;
            println!("After : first={} mid={} next={}", first2, mid2, next2);

            if let Some(index) = result {
                println!("Rotated. New first (deleted up to): {}", index);
            } else {
                println!("Rotated. Secondary was empty; nothing deleted.");
            }
        }
        Commands::Auth { command } => match command {
            AuthCommands::List => {
                let (auths,): (Vec<Authorization>,) =
                    canister.query("get_authorized").build().call().await?;
                if auths.is_empty() {
                    println!("No authorized principals.");
                    return Ok(());
                }
                for a in auths {
                    let role = if a.auth == Auth::Admin {
                        "Admin"
                    } else {
                        "User"
                    };
                    println!("  {}  [{}]", a.id.to_text(), role);
                }
            }
            AuthCommands::Add { principal, admin } => {
                let p = Principal::from_text(principal)?;
                let role = if *admin { Auth::Admin } else { Auth::User };
                let _: ((),) = canister
                    .update("authorize")
                    .with_args((p, role))
                    .build()
                    .call_and_wait()
                    .await?;
                println!(
                    "Authorized {} as {}",
                    principal,
                    if *admin { "Admin" } else { "User" }
                );
            }
            AuthCommands::Remove { principal } => {
                let p = Principal::from_text(principal)?;
                let _: ((),) = canister
                    .update("deauthorize")
                    .with_arg(p)
                    .build()
                    .call_and_wait()
                    .await?;
                println!("Deauthorized {}", principal);
            }
        },
        Commands::Snapshot { start, end, output } => {
            let (first,): (u64,) = canister.query("first").build().call().await?;
            let (next,): (u64,) = canister.query("next").build().call().await?;
            if next == first {
                println!("Blockchain is empty.");
                return Ok(());
            }
            let s = start.unwrap_or(first);
            let e = end.unwrap_or(next.saturating_sub(1));

            let ts = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ");
            let out_file = output
                .clone()
                .unwrap_or_else(|| format!("blockchain-{}.json", ts));

            println!("Snapshotting blocks {}..{} → {}", s, e, out_file);

            let root_key = agent.read_root_key();
            let mut snap = Snapshot {
                version: 1,
                canister_id: canister_id.to_text(),
                root_key: to_hex(&root_key),
                network: cli.network.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                first,
                next,
                blocks: Vec::new(),
            };

            for i in s..=e {
                let (block,): (Block,) = canister
                    .query("get_block")
                    .with_arg(i)
                    .build()
                    .call()
                    .await
                    .context(format!("get_block({}) failed", i))?;

                snap.blocks.push(SnapBlock {
                    index: i,
                    certificate: to_hex(&block.certificate),
                    tree: to_hex(&block.tree),
                    data: block.data.iter().map(|d| to_hex(d)).collect(),
                    callers: block.callers.iter().map(|c| c.to_text()).collect(),
                    previous_hash: to_hex(&block.previous_hash),
                });
            }

            fs::write(&out_file, serde_json::to_string_pretty(&snap)?)?;
            println!("{} block(s) saved to {}", snap.blocks.len(), out_file);
        }
        Commands::Verify {
            path,
            start,
            end,
            no_chain,
            root_key: _,
        } => {
            // ── Live chain vs Local file ─────────────────────────────────────────────
            let mut records: Vec<(u64, Block)> = Vec::new();
            // Optional metadata loaded from files
            let mut _file_canister_id: Option<String> = None;
            let mut _file_root_key: Option<Vec<u8>> = None;

            if path.is_none() {
                let (first,): (u64,) = canister.query("first").build().call().await?;
                let (next,): (u64,) = canister.query("next").build().call().await?;
                let s = start.unwrap_or(first);
                let e = end.unwrap_or(next.saturating_sub(1));

                println!("Verifying live chain: blocks {}..{}", s, e);
                for i in s..=e {
                    let (block,): (Block,) = canister
                        .query("get_block")
                        .with_arg(i)
                        .build()
                        .call()
                        .await
                        .context(format!("get_block({}) failed", i))?;
                    records.push((i, block));
                }
            } else {
                let input_path = path.as_ref().unwrap();
                let p = PathBuf::from(input_path);
                if !p.exists() {
                    anyhow::bail!("not found: {}", input_path);
                }

                if p.is_dir() {
                    let mut files = Vec::new();
                    for entry in fs::read_dir(&p)? {
                        let entry = entry?;
                        let file_name = entry.file_name().into_string().unwrap_or_default();
                        if file_name.starts_with("block-") && file_name.ends_with(".json") {
                            files.push(entry.path());
                        }
                    }
                    if files.is_empty() {
                        anyhow::bail!("no block-*.json files found in {}", input_path);
                    }

                    files.sort_by_cached_key(|f| {
                        let name = f.file_stem().unwrap().to_str().unwrap();
                        let num_str = name.strip_prefix("block-").unwrap_or("0");
                        num_str.parse::<u64>().unwrap_or(0)
                    });

                    for f in files {
                        let content = fs::read_to_string(&f)?;
                        let obj: SnapBlock = serde_json::from_str(&content)?;
                        if let Ok(b) = snap_to_block(&obj) {
                            records.push((obj.index, b));
                        }
                    }

                    let s = start.unwrap_or(records.first().map(|r| r.0).unwrap_or(0));
                    let e = end.unwrap_or(records.last().map(|r| r.0).unwrap_or(0));
                    records.retain(|&(idx, _)| idx >= s && idx <= e);
                    println!("Verifying directory {} ({} block(s), indices {}..{})", input_path, records.len(), s, e);
                } else {
                    let content = fs::read_to_string(&p)?;
                    // Try parsing as Snapshot first
                    if let Ok(snap) = serde_json::from_str::<Snapshot>(&content) {
                        if snap.canister_id.is_empty() {
                            anyhow::bail!("snapshot missing canisterId");
                        }
                        if snap.root_key.is_empty() {
                            anyhow::bail!("snapshot missing rootKey");
                        }
                        _file_canister_id = Some(snap.canister_id.clone());
                        _file_root_key = Some(from_hex(&snap.root_key)?);

                        let s = start.unwrap_or(snap.first);
                        let e = end.unwrap_or(snap.next.saturating_sub(1));

                        for b in snap.blocks {
                            if b.index >= s && b.index <= e {
                                if let Ok(block) = snap_to_block(&b) {
                                    records.push((b.index, block));
                                }
                            }
                        }
                        println!("Verifying snapshot {} (blocks {}..{})", input_path, s, e);
                    } else if let Ok(obj) = serde_json::from_str::<SnapBlock>(&content) {
                        // Single block fallback
                        if let Ok(block) = snap_to_block(&obj) {
                            records.push((obj.index, block));
                        }
                        println!("Verifying block file {}", input_path);
                    } else {
                        anyhow::bail!("unrecognised file format: {}", input_path);
                    }
                }
            }

            if records.is_empty() {
                println!("No blocks in range.");
                return Ok(());
            }

            let mut pass = 0;
            let mut fail = 0;

            let rk_file = _file_root_key.unwrap_or_else(|| agent.read_root_key());
            let cid_file = _file_canister_id.and_then(|c| Principal::from_text(&c).ok()).unwrap_or(canister_id);

            for (index, block) in &records {
                print!("  Block {}: ", index);
                match verify_block(block, cid_file, &rk_file) {
                    Ok(_) => {
                        println!("OK");
                        pass += 1;
                    }
                    Err(errors) => {
                        println!("FAIL");
                        for err in errors {
                            println!("    ! {}", err);
                        }
                        fail += 1;
                    }
                }
            }

            if !*no_chain {
                println!("Checking hash chain…");
                let chain_issues = verify_chain_hashes(&records)?;
                if chain_issues.is_empty() {
                    println!("  Hash chain: OK");
                } else {
                    for issue in chain_issues {
                        println!("  ! {}", issue);
                        fail += 1;
                    }
                }
            }

            println!(
                "\nResult: {} OK, {} FAIL  ({} block(s))",
                pass,
                fail,
                records.len()
            );

            if fail > 0 {
                std::process::exit(1);
            }
            println!("Verification complete.");
        }
    }

    Ok(())
}

async fn safe_append(canister: &Canister<'_>, entries: Vec<Vec<u8>>) -> Result<u64> {
    // Commit any previously staged data before staging ours
    let (pending,): (Option<Vec<u8>>,) = canister.query("get_certificate").build().call().await?;
    if let Some(cert) = pending {
        if !cert.is_empty() {
            println!("Note: committing previously staged data first…");
            let (committed,): (Option<u64>,) = canister
                .update("commit")
                .with_arg(cert)
                .build()
                .call_and_wait()
                .await?;
            if let Some(index) = committed {
                println!("  Committed pending block at index {}", index);
            } else {
                println!(
                    "  Warning: commit returned None (stale certificate, staged data discarded)"
                );
            }
        }
    }

    println!(
        "Staging {} entr{}…",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    let mut _certified: Option<Vec<u8>> = None;

    // Call prepare
    match canister
        .update("prepare")
        .with_arg(&entries)
        .build()
        .call_and_wait()
        .await
    {
        Ok((cert,)) => {
            _certified = Some(cert);
        }
        Err(e) => {
            // Concurrent prepare raced us — commit the other writer's data then retry
            let (cert2,): (Option<Vec<u8>>,) =
                canister.query("get_certificate").build().call().await?;
            if let Some(c2) = cert2 {
                if !c2.is_empty() {
                    println!("  Race detected; committing concurrent staged data and retrying…");
                    let _: ((),) = canister
                        .update("commit")
                        .with_arg(c2)
                        .build()
                        .call_and_wait()
                        .await?;
                    let (cert3,): (Vec<u8>,) = canister
                        .update("prepare")
                        .with_arg(&entries)
                        .build()
                        .call_and_wait()
                        .await
                        .context("Retry prepare failed")?;
                    _certified = Some(cert3);
                } else {
                    return Err(e.into());
                }
            } else {
                return Err(e.into());
            }
        }
    }

    let cert_hex = to_hex(_certified.as_ref().unwrap());
    println!(
        "  certified_data: {}...",
        &cert_hex.chars().take(32).collect::<String>()
    );

    let (cert,): (Option<Vec<u8>>,) = canister.query("get_certificate").build().call().await?;
    let cert = cert.context("get_certificate() returned None after prepare()")?;

    let (result,): (Option<u64>,) = canister
        .update("commit")
        .with_arg(cert)
        .build()
        .call_and_wait()
        .await?;
    let index = result.context("commit() returned None after certificate obtained")?;

    Ok(index)
}

// Add to the main match statement logic via sed in next step

// Continued below via multi_replace

// ── Block verification ───────────────────────────────────────────────────────

fn block_hash(block: &Block) -> Result<[u8; 32]> {
    let enc = candid::encode_args((block,))?;
    Ok(sha256bytes(&enc))
}

fn verify_chain_hashes(records: &[(u64, Block)]) -> Result<Vec<String>> {
    let mut issues = Vec::new();
    if records.is_empty() {
        return Ok(issues);
    }

    let first_ph = &records[0].1.previous_hash;
    if !first_ph.iter().all(|&b| b == 0) {
        println!("  Note: block {} has non-zero previous_hash (chain continuation from prior segment)", records[0].0);
    }

    for i in 1..records.len() {
        if records[i].0 != records[i - 1].0 + 1 {
            continue; // non-contiguous range, skip
        }

        let actual_ph = &records[i].1.previous_hash;

        let expected_ph = block_hash(&records[i - 1].1)?;
        if actual_ph != &expected_ph {
            issues.push(format!(
                "Block {}: previous_hash mismatch (expected {}… got {}…)",
                records[i].0,
                to_hex(&expected_ph).chars().take(16).collect::<String>(),
                to_hex(actual_ph).chars().take(16).collect::<String>()
            ));
        }
    }

    Ok(issues)
}

fn verify_block(
    block: &Block,
    canister_id: Principal,
    root_key: &[u8],
) -> Result<(), Vec<String>> {
    let mut errors: Vec<String> = Vec::new();

    // Decode the tree inside the block
    let block_tree: HashTree = match serde_cbor::from_slice(&block.tree) {
        Ok(t) => t,
        Err(e) => {
            errors.push(format!(
                "Failed to parse block.tree as CBOR HashTree: {}",
                e
            ));
            return Err(errors);
        }
    };

    // 1. Entry hashes in Merkle tree
    for (i, data) in block.data.iter().enumerate() {
        // Construct the 4-byte big-endian key for the index
        let key = (i as u32).to_be_bytes();

        let path_iter = [Label::from("certified_blocks"), Label::from(key.to_vec())];

        let found = block_tree.lookup_path(path_iter.iter());
        match found {
            LookupResult::Found(tree_hash) => {
                let caller = block.callers.get(i).map(|c| c.as_slice()).unwrap_or(&[]);
                let caller_hash = sha256bytes(caller);
                let data_hash = sha256bytes(data);
                let mut hasher = Sha256::new();
                hasher.update(caller_hash);
                hasher.update(data_hash);
                let expected = hasher.finalize();

                if tree_hash != expected.as_slice() {
                    errors.push(format!("entry[{}] hash mismatch in tree", i));
                }
            }
            _ => {
                errors.push(format!("entry[{}] not found in tree", i));
            }
        }
    }

    // 2. previous_hash field matches certified value in tree
    let ph_path = [Label::from("certified_blocks"),
        Label::from("previous_hash")];
    let found_ph = block_tree.lookup_path(ph_path.iter());
    match found_ph {
        LookupResult::Found(tree_ph) => {
            if tree_ph != block.previous_hash {
                errors.push("previous_hash in tree != block.previous_hash".to_string());
            }
        }
        _ => {
            errors.push("previous_hash not found in tree".to_string());
        }
    }

    // 3. Cryptographic Signature Verification
    // Use ic-certificate-verification to validate the subnet BLS signature against our root_key
    match Certificate::from_cbor(&block.certificate) {
        Ok(cert) => {
            let current_time_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let max_cert_time_offset_ns = u128::MAX; // Unlimited time for offline snapshots

            if let Err(e) = VerifyCertificate::<()>::verify(
                &cert,
                canister_id.as_slice(),
                root_key,
                &current_time_ns,
                &max_cert_time_offset_ns,
            ) {
                errors.push(format!("BLS signature validation failed: {:?}", e));
            }
        }
        Err(e) => {
            errors.push(format!("Failed to parse block.certificate as CBOR: {}", e));
        }
    };

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli_impl::main().await
}

#[cfg(target_arch = "wasm32")]
fn main() {}
