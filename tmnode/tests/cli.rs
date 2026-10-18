//! Командная строка `tmnode`: коды выхода, разбор флагов, JSON на выходе.

mod common;

use std::path::{Path, PathBuf};

use common::{healthy, node_public};
use tmnode::cli::{EXIT_USAGE, run};

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

async fn tmnode(args: &[&str], default_config: &Path) -> Out {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        &args,
        &healthy(),
        default_config,
        7,
        &mut stdout,
        &mut stderr,
    )
    .await;
    Out {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

fn nowhere() -> PathBuf {
    PathBuf::from("/nonexistent/tmnode/node.toml")
}

fn temp_file(label: &str, text: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("tmnode_cli_{label}_{nanos}.toml"));
    std::fs::write(&path, text).unwrap();
    path
}

#[tokio::test]
async fn doctor_prints_text_and_json() {
    let out = tmnode(&["doctor"], &nowhere()).await;
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.starts_with("tmnode doctor — 127.0.0.1:18081"));
    assert!(out.stdout.contains("✓ endpoint.config"));

    let out = tmnode(&["doctor", "--json", "--strict"], &nowhere()).await;
    let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["format"], "tmnode.report/1");
    assert_eq!(json["generated_at"], 7);
    assert_eq!(json["status"], "skip");
    assert_eq!(out.code, 0);
}

#[tokio::test]
async fn usage_errors_exit_with_two() {
    for args in [
        &["doctor", "--bogus"][..],
        &["doctor", "--addr"],
        &["doctor", "--addr", "nohost"],
        &["doctor", "--node-key", "abc"],
        &["doctor", "--timeout", "0"],
        &["doctor", "--timeout", "x"],
        &["doctor", "--remote"],
        &["doctor", "--config", "/nonexistent/tmnode/other.toml"],
        &["frobnicate"],
    ] {
        let out = tmnode(args, &nowhere()).await;
        assert_eq!(out.code, EXIT_USAGE, "{args:?}");
        assert!(out.stderr.contains("Использование"), "{args:?}");
        assert!(out.stdout.is_empty());
    }
}

#[tokio::test]
async fn flags_reach_the_doctor() {
    let key = hex::encode(node_public());
    let out = tmnode(
        &[
            "doctor",
            "--remote",
            "--addr",
            "203.0.113.10:18081",
            "--node-key",
            &key,
            "--container",
            "tm",
            "--timeout",
            "2",
            "--json",
        ],
        &nowhere(),
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["target"]["addr"], "203.0.113.10:18081");
    assert_eq!(json["target"]["node_key"], key);
    assert!(json["target"].get("container").is_none());
    assert_eq!(json["checks"][1]["status"], "skip");
}

#[tokio::test]
async fn default_and_explicit_config_files() {
    let good = temp_file("good", "schema = 1\n[node]\nname = \"дом\"\n");
    let out = tmnode(&["doctor", "--json"], &good).await;
    let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["checks"][0]["status"], "ok");
    assert_eq!(json["target"]["config"], good.display().to_string());

    let bad = temp_file("bad", "schema = 1\nnope = true\n");
    let out = tmnode(&["doctor", "--config", bad.to_str().unwrap()], &nowhere()).await;
    assert_eq!(out.code, 1);
    assert!(out.stdout.contains("✗ config.file"));

    assert_eq!(tmnode(&["config", "check"], &good).await.code, 0);
    let out = tmnode(&["config", "check", bad.to_str().unwrap()], &nowhere()).await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("неверная структура"));
    let out = tmnode(&["config", "check", good.to_str().unwrap()], &nowhere()).await;
    assert!(out.stdout.contains("в порядке"));

    let _ = std::fs::remove_file(good);
    let _ = std::fs::remove_file(bad);
}

#[tokio::test]
async fn help_and_version() {
    for args in [&[][..], &["help"], &["--help"], &["-h"]] {
        let out = tmnode(args, &nowhere()).await;
        assert_eq!(out.code, 0);
        assert!(out.stdout.contains("tmnode doctor"));
    }
    for args in [&["version"][..], &["--version"], &["-V"]] {
        let out = tmnode(args, &nowhere()).await;
        assert_eq!(
            out.stdout.trim(),
            format!("tmnode {}", env!("CARGO_PKG_VERSION"))
        );
    }
}
