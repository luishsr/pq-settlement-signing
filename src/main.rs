//! `pq-settle`: generate keys, sign and verify settlement instructions, and benchmark.
//! Exit codes: 0 ok or accepted, 1 signature rejected, 2 usage or I/O error.

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use aws_lc_rs::encoding::AsRawBytes;
use aws_lc_rs::signature::{
    ED25519, Ed25519KeyPair, KeyPair, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING,
    ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm,
    UnparsedPublicKey,
};
use pq_settlement_signing::{
    Mode, PartyKeys, Phase, PrivateKeyFile, PublicKeys, SettlementInstruction, SignedInstruction,
    message_to_sign, verify, verify_in_phase,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

const USAGE: &str = "\
usage:
  pq-settle keygen --id <party> --out-dir <dir>
  pq-settle sign   --key <party.key.json> --in <instruction.json> --out <signed.json>
                   (--mode classical|hybrid|post-quantum | --phase <phase>)
  pq-settle verify --pub <party.pub.json> --in <signed.json> --phase <phase>
  pq-settle bench  [--iterations <n>]

phases: accept-classical | prefer-hybrid | hybrid-required | post-quantum-ready";

const EXAMPLE_INSTRUCTION: &str = include_str!("../examples/instruction.json");

enum Fail {
    /// Bad command line: exit 2 with usage.
    Usage(String),
    /// I/O or key problem on our side: exit 2.
    Error(String),
    /// The counterparty's signed instruction is not acceptable: exit 1.
    Rejected(String),
}

fn usage(msg: impl Into<String>) -> Fail {
    Fail::Usage(msg.into())
}

fn error(msg: impl ToString) -> Fail {
    Fail::Error(msg.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((cmd, rest)) => Opts::parse(rest).and_then(|o| match cmd.as_str() {
            "keygen" => keygen(o),
            "sign" => sign(o),
            "verify" => verify_cmd(o),
            "bench" => bench(o),
            _ => Err(usage(format!("unknown command {cmd:?}"))),
        }),
        None => Err(usage("no command")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Rejected(msg)) => {
            println!("REJECTED  {}", printable(&msg));
            ExitCode::from(1)
        }
        Err(Fail::Usage(msg)) => {
            eprintln!("error: {}\n\n{USAGE}", printable(&msg));
            ExitCode::from(2)
        }
        Err(Fail::Error(msg)) => {
            eprintln!("error: {}", printable(&msg));
            ExitCode::from(2)
        }
    }
}

/// Messages can quote attacker-controlled text (a JSON field name, say), which could carry terminal
/// escape sequences or invisible characters. Show anything outside printable ASCII as `\u{..}`.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' '..='~' => c.to_string(),
            _ => c.escape_unicode().to_string(),
        })
        .collect()
}

/// `--name value` pairs. Each command takes what it needs, then `done()` refuses leftovers, so a
/// misspelt option is an error before anything runs, not a silently ignored setting.
struct Opts(BTreeMap<String, String>);

impl Opts {
    fn parse(args: &[String]) -> Result<Self, Fail> {
        let mut map = BTreeMap::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let name = arg
                .strip_prefix("--")
                .ok_or_else(|| usage(format!("unexpected argument {arg:?}")))?;
            let value = it
                .next()
                .ok_or_else(|| usage(format!("--{name} needs a value")))?;
            if map.insert(name.to_string(), value.clone()).is_some() {
                return Err(usage(format!("--{name} given twice")));
            }
        }
        Ok(Opts(map))
    }

    fn take(&mut self, name: &str) -> Option<String> {
        self.0.remove(name)
    }

    fn required(&mut self, name: &str) -> Result<String, Fail> {
        self.take(name)
            .ok_or_else(|| usage(format!("missing --{name}")))
    }

    fn done(self) -> Result<(), Fail> {
        match self.0.keys().next() {
            Some(name) => Err(usage(format!("unknown option --{name}"))),
            None => Ok(()),
        }
    }
}

fn parse_mode(s: &str) -> Result<Mode, Fail> {
    match s {
        "classical" => Ok(Mode::Classical),
        "hybrid" => Ok(Mode::Hybrid),
        "post-quantum" => Ok(Mode::PostQuantum),
        _ => Err(usage(format!("unknown mode {s:?}"))),
    }
}

fn parse_phase(s: &str) -> Result<Phase, Fail> {
    Phase::parse(s).ok_or_else(|| usage(format!("unknown phase {s:?}")))
}

fn read_json<T: DeserializeOwned>(path: &str) -> Result<T, Fail> {
    let text = fs::read_to_string(path).map_err(|e| error(format!("{path}: {e}")))?;
    serde_json::from_str(&text).map_err(|e| error(format!("{path}: {e}")))
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("our types always serialize") + "\n"
}

/// Writes a file that must not already exist. Private keys are readable by their owner only.
fn create_new(path: &Path, contents: &str, private: bool) -> Result<(), Fail> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(|e| error(format!("{}: {e}", path.display())))
}

fn keygen(mut o: Opts) -> Result<(), Fail> {
    let id = o.required("id")?;
    let dir = PathBuf::from(o.required("out-dir")?);
    o.done()?;
    // The id becomes a file name: keep it to characters that can't escape the directory.
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(usage(format!(
            "--id {id:?} must be letters, digits, '-' or '_'"
        )));
    }
    let key_path = dir.join(format!("{id}.key.json"));
    let pub_path = dir.join(format!("{id}.pub.json"));
    // Check both before writing either, so a clash never leaves half a key pair behind.
    for path in [&key_path, &pub_path] {
        if path.exists() {
            return Err(error(format!("{} already exists", path.display())));
        }
    }
    let keys = PartyKeys::generate(&id).map_err(error)?;
    fs::create_dir_all(&dir).map_err(|e| error(format!("{}: {e}", dir.display())))?;
    create_new(&key_path, &to_json(&keys.to_file().map_err(error)?), true)?;
    create_new(&pub_path, &to_json(&keys.public_keys()), false)?;
    let pk = keys.public_keys();
    println!(
        "{id}: private keys -> {} (owner-only, unencrypted: demo only)",
        key_path.display()
    );
    println!(
        "{id}: public keys  -> {} (Ed25519 {} B, ML-DSA-65 {} B)",
        pub_path.display(),
        pk.ed25519.len(),
        pk.ml_dsa_65.len()
    );
    Ok(())
}

fn sign(mut o: Opts) -> Result<(), Fail> {
    let key_path = o.required("key")?;
    let in_path = o.required("in")?;
    let out_path = o.required("out")?;
    let mode = match (o.take("mode"), o.take("phase")) {
        (Some(m), None) => parse_mode(&m)?,
        (None, Some(p)) => parse_phase(&p)?.signing_mode(),
        _ => return Err(usage("give exactly one of --mode or --phase")),
    };
    o.done()?;
    let keys = PartyKeys::from_file(&read_json::<PrivateKeyFile>(&key_path)?).map_err(error)?;
    let instruction: SettlementInstruction = read_json(&in_path)?;
    let signed = keys.sign(mode, &instruction).map_err(error)?;
    // Never overwrite (or follow a symlink to) an existing file, such as a key file.
    create_new(Path::new(&out_path), &to_json(&signed), false)?;
    let sizes: Vec<String> = [
        ("Ed25519", &signed.signature.ed25519),
        ("ML-DSA-65", &signed.signature.ml_dsa_65),
    ]
    .iter()
    .filter_map(|(alg, sig)| sig.as_ref().map(|s| format!("{alg} {} B", s.len())))
    .collect();
    println!(
        "{} signed {} as {} ({}) -> {out_path}",
        keys.id(),
        instruction.instruction_id,
        mode.label(),
        sizes.join(" + ")
    );
    Ok(())
}

fn verify_cmd(mut o: Opts) -> Result<(), Fail> {
    let pub_path = o.required("pub")?;
    let in_path = o.required("in")?;
    let phase = parse_phase(&o.required("phase")?)?;
    o.done()?;
    // The public keys are our own configuration: a bad key is our error (exit 2), not a rejection.
    let signer: PublicKeys = read_json(&pub_path)?;
    signer
        .validate()
        .map_err(|e| error(format!("{pub_path}: {e}")))?;
    // The signed instruction comes from a counterparty: anything wrong with its contents, including
    // invalid UTF-8, is a rejection (exit 1). Only failing to read the file is our error.
    let bytes = fs::read(&in_path).map_err(|e| error(format!("{in_path}: {e}")))?;
    let signed: SignedInstruction = serde_json::from_slice(&bytes)
        .map_err(|e| Fail::Rejected(format!("malformed signed instruction: {e}")))?;
    let mode =
        verify_in_phase(&signed, &signer, phase).map_err(|e| Fail::Rejected(e.to_string()))?;
    println!(
        "ACCEPTED  {} signature by {} in phase {}",
        mode.label(),
        signer.id,
        phase.name()
    );
    println!("          {}", printable(&describe(&signed.instruction)));
    Ok(())
}

fn describe(i: &SettlementInstruction) -> String {
    format!(
        "{}: {} delivers {} {} to {} against {} {}.{:02}, settling {}",
        i.instruction_id,
        i.deliverer,
        grouped(i.nominal),
        i.isin,
        i.receiver,
        i.currency,
        grouped(i.cash_amount_minor / 100),
        i.cash_amount_minor % 100,
        i.settlement_date
    )
}

/// 1234567 -> "1,234,567"
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// bench

/// Median, mean and 99th percentile of timed runs.
#[derive(Clone, Copy)]
struct Stats {
    p50: Duration,
    mean: Duration,
    p99: Duration,
}

/// Times `n` runs of `f`, after a short warm-up.
fn measure<T>(n: usize, mut f: impl FnMut() -> T) -> Stats {
    for _ in 0..n.div_ceil(10) {
        black_box(f());
    }
    let mut samples: Vec<Duration> = (0..n)
        .map(|_| {
            let start = Instant::now();
            black_box(f());
            start.elapsed()
        })
        .collect();
    samples.sort_unstable();
    Stats {
        p50: samples[n / 2],
        mean: samples.iter().sum::<Duration>() / n as u32,
        p99: samples[(n * 99 / 100).min(n - 1)],
    }
}

struct Row {
    name: &'static str,
    public_key: usize,
    signature: usize,
    /// The secret every other part of the private key is derived from.
    seed: usize,
    /// The private key in the form the signing algorithm uses.
    expanded: usize,
    /// The private key file as this crate stores it (PKCS#8 DER).
    pkcs8: usize,
    keygen: Stats,
    sign: Stats,
    verify: Stats,
}

/// Ed25519: the private key is a 32-byte seed, hashed with SHA-512 into a 64-byte expanded form
/// (a scalar and a nonce prefix; RFC 8032, section 5.1.5). aws-lc-rs doesn't expose the latter.
const ED25519_SEED_LEN: usize = 32;
const ED25519_EXPANDED_LEN: usize = 64;
/// ML-DSA keys are generated from a 32-byte seed (FIPS 204, Algorithm 1).
const ML_DSA_SEED_LEN: usize = 32;

fn bench_ed25519(n: usize, m: &[u8]) -> Row {
    let kp = Ed25519KeyPair::generate().expect("keygen");
    let sig = kp.sign(m);
    let pk = UnparsedPublicKey::new(&ED25519, kp.public_key().as_ref().to_vec());
    assert!(pk.verify(m, sig.as_ref()).is_ok());
    Row {
        name: "Ed25519",
        public_key: kp.public_key().as_ref().len(),
        signature: sig.as_ref().len(),
        seed: ED25519_SEED_LEN,
        expanded: ED25519_EXPANDED_LEN,
        pkcs8: kp.to_pkcs8().expect("export").as_ref().len(),
        keygen: measure(n, Ed25519KeyPair::generate),
        sign: measure(n, || kp.sign(m)),
        verify: measure(n, || pk.verify(m, sig.as_ref()).is_ok()),
    }
}

fn bench_ml_dsa(
    name: &'static str,
    signing: &'static PqdsaSigningAlgorithm,
    verifying: &'static PqdsaVerificationAlgorithm,
    n: usize,
    m: &[u8],
) -> Row {
    let kp = PqdsaKeyPair::generate(signing).expect("keygen");
    let mut buf = vec![0u8; 8192];
    let len = kp.sign(m, &mut buf).expect("sign");
    let sig = buf[..len].to_vec();
    let pk = UnparsedPublicKey::new(verifying, kp.public_key().as_ref().to_vec());
    assert!(pk.verify(m, &sig).is_ok());
    Row {
        name,
        public_key: kp.public_key().as_ref().len(),
        signature: sig.len(),
        seed: ML_DSA_SEED_LEN,
        expanded: kp
            .private_key()
            .as_raw_bytes()
            .expect("export")
            .as_ref()
            .len(),
        pkcs8: kp.to_pkcs8v1().expect("export").as_ref().len(),
        keygen: measure(n, || PqdsaKeyPair::generate(signing)),
        sign: measure(n, || kp.sign(m, &mut buf)),
        verify: measure(n, || pk.verify(m, &sig).is_ok()),
    }
}

/// The whole envelope: validation, canonical encoding, SHA-512 and both signatures.
fn bench_hybrid(n: usize, keys: &PartyKeys, instruction: &SettlementInstruction) -> Row {
    let pk = keys.public_keys();
    let signed = keys.sign(Mode::Hybrid, instruction).expect("sign");
    assert_eq!(verify(&signed, &pk), Ok(Mode::Hybrid));
    let sig = &signed.signature;
    let file = keys.to_file().expect("export");
    Row {
        name: "Hybrid envelope (Ed25519 + ML-DSA-65)",
        public_key: pk.ed25519.len() + pk.ml_dsa_65.len(),
        signature: sig.ed25519.as_ref().map_or(0, Vec::len)
            + sig.ml_dsa_65.as_ref().map_or(0, Vec::len),
        seed: 0,     // filled in by the caller from the component rows
        expanded: 0, // likewise
        pkcs8: file.ed25519_pkcs8.len() + file.ml_dsa_65_pkcs8.len(),
        keygen: measure(n, || PartyKeys::generate("bank-a")),
        sign: measure(n, || keys.sign(Mode::Hybrid, instruction)),
        verify: measure(n, || verify(&signed, &pk).is_ok()),
    }
}

/// Aggregate operations per second: `threads` threads each run `op` until the same deadline.
/// Time-boxing (rather than a fixed count per thread) keeps fast cores busy while slower ones
/// finish, which matters on CPUs with mixed core types.
fn throughput(threads: usize, window: Duration, op: &(impl Fn() + Sync)) -> f64 {
    let start = Instant::now();
    let deadline = start + window;
    let total: u64 = std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut ops = 0u64;
                    while Instant::now() < deadline {
                        op();
                        ops += 1;
                    }
                    ops
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).sum()
    });
    total as f64 / start.elapsed().as_secs_f64()
}

fn cpu_model() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".into())
}

fn bench(mut o: Opts) -> Result<(), Fail> {
    let n: usize = match o.take("iterations") {
        Some(s) => s
            .parse()
            .ok()
            .filter(|&n| n > 0)
            .ok_or_else(|| usage(format!("--iterations {s:?} is not a positive number")))?,
        None => 2000,
    };
    o.done()?;
    if cfg!(debug_assertions) {
        eprintln!("warning: debug build; use `cargo run --release -- bench` for real numbers");
    }
    let instruction: SettlementInstruction =
        serde_json::from_str(EXAMPLE_INSTRUCTION).expect("example instruction parses");
    let m = message_to_sign(Mode::PostQuantum, &instruction);
    let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
    println!("CPU: {} ({cores} hardware threads available)", cpu_model());
    println!(
        "{n} runs per operation, one thread; message: M' ({} bytes)",
        m.len()
    );
    println!("(for stable latencies, pin to one fast core, e.g. `taskset -c 2 pq-settle bench`)\n");

    let keys = PartyKeys::generate("bank-a").expect("keygen");
    let mut rows = [
        bench_ed25519(n, &m),
        bench_ml_dsa("ML-DSA-44", &ML_DSA_44_SIGNING, &ML_DSA_44, n, &m),
        bench_ml_dsa("ML-DSA-65", &ML_DSA_65_SIGNING, &ML_DSA_65, n, &m),
        bench_ml_dsa("ML-DSA-87", &ML_DSA_87_SIGNING, &ML_DSA_87, n, &m),
        bench_hybrid(n, &keys, &instruction),
    ];
    rows[4].seed = rows[0].seed + rows[2].seed;
    rows[4].expanded = rows[0].expanded + rows[2].expanded;

    let us = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1e6);
    println!("Latency, µs");
    println!(
        "| {:<38} | {:>10} | {:>8} | {:>9} | {:>8} | {:>10} | {:>10} |",
        "Algorithm", "Keygen p50", "Sign p50", "Sign mean", "Sign p99", "Verify p50", "Verify p99"
    );
    println!(
        "|{:-<40}|{:->12}|{:->10}|{:->11}|{:->10}|{:->12}|{:->12}|",
        "", ":", ":", ":", ":", ":", ":"
    );
    for r in &rows {
        println!(
            "| {:<38} | {:>10} | {:>8} | {:>9} | {:>8} | {:>10} | {:>10} |",
            r.name,
            us(r.keygen.p50),
            us(r.sign.p50),
            us(r.sign.mean),
            us(r.sign.p99),
            us(r.verify.p50),
            us(r.verify.p99)
        );
    }

    println!("\nSizes, bytes");
    println!(
        "| {:<38} | {:>10} | {:>9} | {:>4} | {:>8} | {:>12} |",
        "Algorithm", "Public key", "Signature", "Seed", "Expanded", "Key file DER"
    );
    println!(
        "|{:-<40}|{:->12}|{:->11}|{:->6}|{:->10}|{:->14}|",
        "", ":", ":", ":", ":", ":"
    );
    for r in &rows {
        println!(
            "| {:<38} | {:>10} | {:>9} | {:>4} | {:>8} | {:>12} |",
            r.name, r.public_key, r.signature, r.seed, r.expanded, r.pkcs8
        );
    }

    let pk = keys.public_keys();
    let signed = keys.sign(Mode::Hybrid, &instruction).expect("sign");
    let window = Duration::from_secs(1);
    let mut counts = vec![1, 2, 4, 8, 16, cores];
    counts.retain(|&t| t <= cores);
    counts.dedup();
    println!("\nHybrid envelope throughput, every thread busy for the same 1 s window");
    println!(
        "| {:>7} | {:>12} | {:>15} |",
        "Threads", "Signatures/s", "Verifications/s"
    );
    println!("|{:->9}|{:->14}|{:->17}|", ":", ":", ":");
    for t in counts {
        let sign = throughput(t, window, &|| {
            black_box(keys.sign(Mode::Hybrid, &instruction).is_ok());
        });
        let verify = throughput(t, window, &|| {
            black_box(verify(&signed, &pk).is_ok());
        });
        println!("| {t:>7} | {sign:>12.0} | {verify:>15.0} |");
    }
    Ok(())
}
