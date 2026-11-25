//! The CLI's exit codes are part of its contract: scripts branch on them.
//! 0 = accepted (or the command succeeded), 1 = the counterparty's signed instruction is rejected,
//! 2 = usage or I/O error on our side.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_pq-settle");
const EXAMPLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/instruction.json");

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// A scratch directory with Bank A's keys and a hybrid-signed copy of the example instruction.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pq-settle-cli-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = Fixture { dir };
        let (d, key, signed) = (f.path(""), f.path("bank-a.key.json"), f.path("signed.json"));
        assert_eq!(
            code(&run(&["keygen", "--id", "bank-a", "--out-dir", &d])),
            0
        );
        let args = [
            "sign", "--key", &key, "--in", EXAMPLE, "--mode", "hybrid", "--out", &signed,
        ];
        assert_eq!(code(&run(&args)), 0);
        f
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_str().unwrap().to_string()
    }

    fn verify(&self, pubkey: &str, envelope: &str, phase: &str) -> Output {
        run(&[
            "verify", "--pub", pubkey, "--in", envelope, "--phase", phase,
        ])
    }

    /// Writes an edited copy of the signed instruction and returns its path.
    fn edited(&self, name: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let text = fs::read_to_string(self.path("signed.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        edit(&mut v);
        fs::write(self.path(name), v.to_string()).unwrap();
        self.path(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn accepted_exits_0_and_rejected_exits_1() {
    let f = Fixture::new("verdicts");
    let (pubkey, signed) = (f.path("bank-a.pub.json"), f.path("signed.json"));

    let ok = f.verify(&pubkey, &signed, "hybrid-required");
    assert_eq!(code(&ok), 0);
    assert!(String::from_utf8_lossy(&ok.stdout).starts_with("ACCEPTED"));

    let policy = f.verify(&pubkey, &signed, "accept-classical");
    assert_eq!(code(&policy), 1);

    let attacks = [
        f.edited("tampered.json", |v| {
            v["instruction"]["nominal"] = 9_000_000.into()
        }),
        f.edited("half.json", |v| {
            v["signature"].as_object_mut().unwrap().remove("ml_dsa_65");
        }),
        f.edited("smuggled.json", |v| v["instruction"]["memo"] = "x".into()),
    ];
    for envelope in attacks {
        let o = f.verify(&pubkey, &envelope, "hybrid-required");
        assert_eq!(code(&o), 1, "{envelope}");
        assert!(String::from_utf8_lossy(&o.stdout).starts_with("REJECTED"));
    }
}

#[test]
fn whatever_the_counterparty_sends_is_a_rejection_shown_safely() {
    let f = Fixture::new("hostile");
    let pubkey = f.path("bank-a.pub.json");
    // Invalid UTF-8 in the envelope.
    let mut bytes = fs::read(f.path("signed.json")).unwrap();
    bytes.insert(1, 0xff);
    fs::write(f.path("binary.json"), bytes).unwrap();
    assert_eq!(
        code(&f.verify(&pubkey, &f.path("binary.json"), "hybrid-required")),
        1
    );
    // A field name carrying a terminal escape sequence must not reach the terminal raw.
    let evil = f.edited("evil.json", |v| {
        v["instruction"]["\u{1b}[2KACCEPTED"] = 1.into()
    });
    let o = f.verify(&pubkey, &evil, "hybrid-required");
    assert_eq!(code(&o), 1);
    assert!(
        !o.stdout.contains(&0x1b),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
}

#[test]
fn our_own_problems_exit_2() {
    let f = Fixture::new("errors");
    let (pubkey, signed, missing) = (
        f.path("bank-a.pub.json"),
        f.path("signed.json"),
        f.path("nope.json"),
    );
    assert_eq!(code(&f.verify(&pubkey, &missing, "hybrid-required")), 2);
    assert_eq!(code(&f.verify(&missing, &signed, "hybrid-required")), 2);

    // A misspelt option fails before anything runs.
    let (key, out) = (f.path("bank-a.key.json"), f.path("never.json"));
    let args = [
        "sign", "--key", &key, "--in", EXAMPLE, "--out", &out, "--mode", "hybrid", "--phse", "x",
    ];
    assert_eq!(code(&run(&args)), 2);
    assert!(!PathBuf::from(&out).exists());

    // A bad trusted key is our configuration error, not the counterparty's fault.
    let mut keys: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&pubkey).unwrap()).unwrap();
    let truncated = keys["ed25519"].as_str().unwrap()[..62].to_string();
    keys["ed25519"] = truncated.into();
    fs::write(f.path("truncated.pub.json"), keys.to_string()).unwrap();
    assert_eq!(
        code(&f.verify(&f.path("truncated.pub.json"), &signed, "hybrid-required")),
        2
    );
    keys["ed25519"] = format!("01{}", "00".repeat(31)).into(); // the identity point: small order
    fs::write(f.path("weak.pub.json"), keys.to_string()).unwrap();
    assert_eq!(
        code(&f.verify(&f.path("weak.pub.json"), &signed, "hybrid-required")),
        2
    );

    // sign never overwrites, so it can't clobber a key file by mistake.
    let before = fs::read(&key).unwrap();
    let args = [
        "sign", "--key", &key, "--in", EXAMPLE, "--out", &key, "--mode", "hybrid",
    ];
    assert_eq!(code(&run(&args)), 2);
    assert_eq!(fs::read(&key).unwrap(), before);

    // keygen never overwrites keys, and never leaves half a pair behind.
    fs::write(f.path("bank-c.pub.json"), "{}").unwrap();
    assert_eq!(
        code(&run(&[
            "keygen",
            "--id",
            "bank-c",
            "--out-dir",
            &f.path("")
        ])),
        2
    );
    assert!(!PathBuf::from(f.path("bank-c.key.json")).exists());
    assert_eq!(
        code(&run(&[
            "keygen",
            "--id",
            "bank-a",
            "--out-dir",
            &f.path("")
        ])),
        2
    );
    assert_eq!(code(&run(&["verify"])), 2);
}
